use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use alighieri::acl::{RuleSet, Scope, Verdict};
use alighieri::config::{AuthKind, Config, LogOutput};
use alighieri::net::Cidr;
use alighieri::util::constant_time_eq;
use password_hash::rand_core::{OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_WIZARD_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const DEFAULT_OUTPUT_PATH: &str = "alighieri.conf";
const MAX_HTTP_BYTES: usize = 64 * 1024;
const MAX_FORM_BYTES: usize = 32 * 1024;
const HTTP_REQUEST_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWizardArgs {
    listen: SocketAddr,
    output_path: PathBuf,
    /// Existing configuration to load into the form, if any.
    import_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WizardTemplate {
    LocalNoAuth,
    LanUsername,
}

impl WizardTemplate {
    fn from_form(value: &str) -> Result<Self, String> {
        match value {
            "local-no-auth" => Ok(WizardTemplate::LocalNoAuth),
            "lan-username" => Ok(WizardTemplate::LanUsername),
            _ => Err("unknown config wizard template".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WizardForm {
    template: WizardTemplate,
    output_path: PathBuf,
    listen_host: String,
    listen_port: u16,
    trusted_client: String,
    userlist_path: Option<PathBuf>,
    log_file: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
struct WriteReport {
    output_path: PathBuf,
    backup_path: Option<PathBuf>,
}

struct WizardState {
    token: String,
    default_output_path: PathBuf,
    /// Pre-filled form data when the wizard was started with `--import`.
    prefill: Option<ImportPrefill>,
}

/// Form pre-fill derived from an existing configuration loaded with `--import`.
#[derive(Debug)]
struct ImportPrefill {
    /// The wizard fields extracted from the imported configuration.
    form: WizardForm,
    /// Setting areas present in the original that the wizard cannot reproduce
    /// and would drop on save. Empty when the import round-trips cleanly.
    warnings: Vec<String>,
    /// The file the settings were imported from (shown in the form banner).
    source: PathBuf,
}

struct HttpRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

pub fn parse_config_wizard_args(args: &[String]) -> Result<ConfigWizardArgs, String> {
    let mut listen = DEFAULT_WIZARD_LISTEN;
    let mut output_path: Option<PathBuf> = None;
    let mut import_path: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--listen" => {
                let Some(value) = iter.next() else {
                    return Err("config wizard --listen requires an address".into());
                };
                listen = parse_wizard_listen(value)?;
            }
            "--output" => {
                let Some(value) = iter.next() else {
                    return Err("config wizard --output requires a path".into());
                };
                validate_single_line("config wizard --output path", value)?;
                validate_output_path(value)?;
                output_path = Some(PathBuf::from(value));
            }
            "--import" => {
                let Some(value) = iter.next() else {
                    return Err("config wizard --import requires a path".into());
                };
                validate_single_line("config wizard --import path", value)?;
                import_path = Some(PathBuf::from(value));
            }
            _ => return Err(config_wizard_usage()),
        }
    }

    // Importing without an explicit --output edits the imported file in place;
    // otherwise fall back to the standard default output name.
    let output_path = output_path
        .or_else(|| import_path.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_PATH));

    Ok(ConfigWizardArgs {
        listen,
        output_path,
        import_path,
    })
}

fn parse_wizard_listen(value: &str) -> Result<SocketAddr, String> {
    let addr = value
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid config wizard listen address '{value}': {e}"))?;
    if !addr.ip().is_loopback() {
        return Err("config wizard must listen on a loopback address".into());
    }
    Ok(addr)
}

fn config_wizard_usage() -> String {
    "usage: alighieri config wizard [--listen 127.0.0.1:PORT] [--output PATH] [--import PATH]"
        .into()
}

pub async fn run_config_wizard(args: ConfigWizardArgs) -> Result<(), String> {
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|e| format!("failed to bind config wizard to {}: {e}", args.listen))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("failed to read config wizard address: {e}"))?;
    let prefill = match &args.import_path {
        Some(path) => Some(load_import_prefill(path, &args.output_path)?),
        None => None,
    };
    let state = WizardState {
        token: random_token(),
        default_output_path: args.output_path,
        prefill,
    };
    let url = format!("http://{local_addr}/?token={}", state.token);

    println!("alighieri: config wizard listening on {url}");
    if let Some(prefill) = &state.prefill {
        println!(
            "alighieri: imported settings from {} — review them in the wizard before saving",
            prefill.source.display()
        );
        if !prefill.warnings.is_empty() {
            println!(
                "alighieri: note: saving will not preserve {} setting area(s) from that file (a .bak backup is kept):",
                prefill.warnings.len()
            );
            for warning in &prefill.warnings {
                println!("alighieri:   - {warning}");
            }
        }
    }
    println!("alighieri: this local wizard exits after saving one configuration");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                eprintln!("alighieri: warning: failed to accept config wizard request: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        if handle_wizard_connection(stream, &state).await {
            return Ok(());
        }
    }
}

async fn handle_wizard_connection(mut stream: TcpStream, state: &WizardState) -> bool {
    let request = match read_http_request(&mut stream).await {
        Ok(Some(request)) => request,
        Ok(None) => return false,
        Err(e) => {
            let response = HttpResponse::html(400, "Bad Request", render_error(&e));
            write_wizard_response(&mut stream, &response).await;
            return false;
        }
    };

    match route_request(&request, state) {
        Ok(response) => {
            write_wizard_response(&mut stream, &response).await;
            response.done
        }
        Err(response) => {
            write_wizard_response(&mut stream, &response).await;
            false
        }
    }
}

async fn write_wizard_response(stream: &mut TcpStream, response: &HttpResponse) {
    match tokio::time::timeout(
        Duration::from_secs(HTTP_REQUEST_TIMEOUT_SECS),
        stream.write_all(&response.as_bytes()),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("alighieri: warning: failed to write config wizard response: {e}");
        }
        Err(_) => {
            eprintln!("alighieri: warning: timed out writing config wizard response");
        }
    }
}

fn route_request(request: &HttpRequest, state: &WizardState) -> Result<HttpResponse, HttpResponse> {
    if request.path == "/favicon.ico" {
        return Err(HttpResponse::text(404, "Not Found", "not found"));
    }
    if !token_matches(request.query.get("token"), &state.token) {
        return Err(HttpResponse::html(
            403,
            "Forbidden",
            html_page("Forbidden", "<main><h1>Forbidden</h1></main>"),
        ));
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => Ok(HttpResponse::html(
            200,
            "OK",
            render_wizard_form(
                &state.token,
                &state.default_output_path,
                state.prefill.as_ref(),
            ),
        )),
        ("POST", "/generate") => {
            let form = parse_urlencoded_body(request)?;
            let wizard_form = wizard_form_from_fields(&form, &state.default_output_path)
                .map_err(|e| HttpResponse::html(400, "Bad Request", render_error(&e)))?;
            let config_text = render_config(&wizard_form);
            Config::parse(&config_text).map_err(|e| {
                HttpResponse::html(
                    400,
                    "Bad Request",
                    render_error(&format!("generated configuration failed validation: {e}")),
                )
            })?;
            let report = write_config_atomically(&wizard_form.output_path, config_text.as_bytes())
                .map_err(|e| {
                    HttpResponse::html(
                        500,
                        "Internal Server Error",
                        render_error(&format!("failed to write configuration: {e}")),
                    )
                })?;
            print_save_report(&report);
            Ok(HttpResponse::html(200, "OK", render_success(&report, &wizard_form)).done())
        }
        _ => Err(HttpResponse::text(404, "Not Found", "not found")),
    }
}

/// Whether the request's `token` query parameter matches the per-run token. A
/// missing token or a length mismatch short-circuits, but the token length is
/// fixed and printed in the URL, so it is not secret; the per-byte comparison of
/// an equal-length token is position-independent (it does not reveal how many
/// leading bytes matched). The token is 192 bits of `OsRng`, so a timing oracle
/// is not a realistic threat regardless — this is defense-in-depth.
fn token_matches(provided: Option<&String>, expected: &str) -> bool {
    provided.is_some_and(|p| constant_time_eq(p.as_bytes(), expected.as_bytes()))
}

async fn read_http_request(stream: &mut TcpStream) -> Result<Option<HttpRequest>, String> {
    // `_untimed` carries the size bounds (MAX_HTTP_BYTES / MAX_FORM_BYTES); this
    // wrapper adds the wall-clock timeout.
    match tokio::time::timeout(
        Duration::from_secs(HTTP_REQUEST_TIMEOUT_SECS),
        read_http_request_untimed(stream),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err("timed out reading config wizard request".into()),
    }
}

async fn read_http_request_untimed(stream: &mut TcpStream) -> Result<Option<HttpRequest>, String> {
    let mut data = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        let n = read_http_chunk(stream, &mut chunk, "request").await?;
        if n == 0 {
            return Ok(None);
        }
        data.extend_from_slice(&chunk[..n]);
        if data.len() > MAX_HTTP_BYTES {
            return Err("config wizard request is too large".into());
        }
        if let Some(pos) = find_header_end(&data) {
            break pos;
        }
    };

    let headers = String::from_utf8_lossy(&data[..header_end]);
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing HTTP method".to_string())?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| "missing HTTP target".to_string())?;
    let (path, query) = parse_target(target);
    let mut header_map = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            header_map.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = header_map
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| "invalid Content-Length".to_string())?
        .unwrap_or(0);
    if content_length > MAX_FORM_BYTES {
        return Err("config wizard form is too large".into());
    }

    let body_start = header_end + 4;
    while data.len() < body_start + content_length {
        let mut chunk = [0u8; 4096];
        let n = read_http_chunk(stream, &mut chunk, "body").await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..n]);
        if data.len() > MAX_HTTP_BYTES {
            return Err("config wizard request is too large".into());
        }
    }
    if data.len() < body_start + content_length {
        return Err("incomplete config wizard request body".into());
    }
    let body = data[body_start..body_start + content_length].to_vec();

    Ok(Some(HttpRequest {
        method,
        path,
        query,
        headers: header_map,
        body,
    }))
}

async fn read_http_chunk(
    stream: &mut TcpStream,
    chunk: &mut [u8],
    context: &str,
) -> Result<usize, String> {
    stream
        .read(chunk)
        .await
        .map_err(|e| format!("failed to read config wizard {context}: {e}"))
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_target(target: &str) -> (String, HashMap<String, String>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    (path.to_string(), parse_urlencoded(query.as_bytes()))
}

fn parse_urlencoded_body(request: &HttpRequest) -> Result<HashMap<String, String>, HttpResponse> {
    if !request
        .headers
        .get("content-type")
        .is_some_and(|value| is_urlencoded_content_type(value))
    {
        return Err(HttpResponse::html(
            415,
            "Unsupported Media Type",
            render_error("config wizard accepts form submissions only"),
        ));
    }
    Ok(parse_urlencoded(&request.body))
}

fn is_urlencoded_content_type(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded")
}

fn parse_urlencoded(input: &[u8]) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    for pair in input.split(|b| *b == b'&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) =
            SplitOnceByte::split_once(pair, |b| *b == b'=').unwrap_or((pair, &[][..]));
        fields.insert(percent_decode(key), percent_decode(value));
    }
    fields
}

trait SplitOnceByte {
    fn split_once<P>(&self, pred: P) -> Option<(&[u8], &[u8])>
    where
        P: FnMut(&u8) -> bool;
}

impl SplitOnceByte for [u8] {
    fn split_once<P>(&self, mut pred: P) -> Option<(&[u8], &[u8])>
    where
        P: FnMut(&u8) -> bool,
    {
        let index = self.iter().position(&mut pred)?;
        Some((&self[..index], &self[index + 1..]))
    }
}

fn percent_decode(input: &[u8]) -> String {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < input.len() => {
                let hi = hex_value(input[index + 1]);
                let lo = hex_value(input[index + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    output.push((hi << 4) | lo);
                    index += 3;
                } else {
                    output.push(input[index]);
                    index += 1;
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn wizard_form_from_fields(
    fields: &HashMap<String, String>,
    default_output_path: &Path,
) -> Result<WizardForm, String> {
    let template = WizardTemplate::from_form(field(fields, "template", "local-no-auth"))?;
    validate_single_line_path("default output path", default_output_path)?;
    let output_path_text = field_path(fields, "output", default_output_path);
    validate_single_line("output path", &output_path_text)?;
    validate_output_path(&output_path_text)?;
    let output_path = PathBuf::from(output_path_text);
    let listen_host = field(fields, "listen_host", default_listen_host(template)).to_string();
    let listen_port = parse_port(field(fields, "listen_port", "1080"))?;
    let trusted_client =
        field(fields, "trusted_client", default_trusted_client(template)).to_string();
    let initial_userlist = default_userlist_path(default_output_path);
    let default_userlist = default_userlist_path(&output_path);
    let initial_log = default_log_path(default_output_path);
    let default_log = default_log_path(&output_path);
    let userlist_path =
        path_field_with_changed_output(fields, "userlist", &initial_userlist, &default_userlist);
    let log_file = log_field_with_changed_output(fields, &initial_log, &default_log);

    let listen_ip = listen_host
        .parse::<IpAddr>()
        .map_err(|_| "listen address must be an IP address".to_string())?;
    if template == WizardTemplate::LocalNoAuth && !listen_ip.is_loopback() {
        return Err("local no-auth template must listen on a loopback address".into());
    }
    validate_config_value("trusted client range", &trusted_client)?;
    validate_optional_config_path("userlist path", &userlist_path)?;
    validate_optional_config_path("log file", &log_file)?;
    if trusted_client.trim().is_empty() {
        return Err("trusted client range is required".into());
    }
    if template == WizardTemplate::LanUsername && userlist_path.is_none() {
        return Err("LAN username template requires a userlist path".into());
    }

    Ok(WizardForm {
        template,
        output_path,
        listen_host,
        listen_port,
        trusted_client,
        userlist_path: if template == WizardTemplate::LanUsername {
            userlist_path
        } else {
            None
        },
        log_file,
    })
}

fn field<'a>(fields: &'a HashMap<String, String>, key: &str, default: &'a str) -> &'a str {
    fields
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(default)
}

fn field_path<'a>(fields: &'a HashMap<String, String>, key: &str, default: &'a Path) -> String {
    fields
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| default.display().to_string())
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| "listen port must be between 1 and 65535".to_string())?;
    if port == 0 {
        return Err("listen port must be between 1 and 65535".into());
    }
    Ok(port)
}

fn optional_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn validate_single_line(label: &str, value: &str) -> Result<(), String> {
    if value.contains('\r') || value.contains('\n') {
        Err(format!("{label} must be a single line"))
    } else {
        Ok(())
    }
}

fn validate_single_line_path(label: &str, path: &Path) -> Result<(), String> {
    validate_single_line(label, &path.display().to_string())
}

fn validate_config_value(label: &str, value: &str) -> Result<(), String> {
    validate_single_line(label, value)?;
    if value.contains('#') {
        return Err(format!(
            "{label} must not contain '#' (it starts a config comment)"
        ));
    }
    Ok(())
}

fn validate_optional_config_path(label: &str, path: &Option<PathBuf>) -> Result<(), String> {
    if let Some(path) = path {
        validate_config_value(label, &path.display().to_string())?;
    }
    Ok(())
}

fn validate_output_path(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    let path = Path::new(trimmed);
    if trimmed.is_empty()
        || trimmed.ends_with('/')
        || trimmed.ends_with('\\')
        || path.file_name().is_none()
        || path.is_dir()
    {
        Err("output path must include a file name".into())
    } else {
        Ok(())
    }
}

fn path_field_with_changed_output(
    fields: &HashMap<String, String>,
    key: &str,
    initial_default: &str,
    output_default: &str,
) -> Option<PathBuf> {
    match fields.get(key).map(String::as_str) {
        None => Some(PathBuf::from(output_default)),
        Some(value) if value.trim().is_empty() => None,
        Some(value) if path_value_matches(value, initial_default) => {
            Some(PathBuf::from(output_default))
        }
        Some(value) => optional_path(value),
    }
}

fn log_field_with_changed_output(
    fields: &HashMap<String, String>,
    initial_default: &str,
    output_default: &str,
) -> Option<PathBuf> {
    // Default to stdout (journald under systemd, console on Windows) for every
    // template: a relative or non-service-writable log file is a common footgun
    // under the hardened unit. File logging is opt-in — the operator supplies an
    // absolute, service-writable path.
    match fields.get("logfile").map(String::as_str).map(str::trim) {
        Some("") | None => None,
        Some(value) if path_value_matches(value, initial_default) => {
            Some(PathBuf::from(output_default))
        }
        Some(value) => Some(PathBuf::from(value)),
    }
}

fn path_value_matches(left: &str, right: &str) -> bool {
    Path::new(left)
        .components()
        .eq(Path::new(right).components())
}

fn default_listen_host(template: WizardTemplate) -> &'static str {
    match template {
        WizardTemplate::LocalNoAuth => "127.0.0.1",
        WizardTemplate::LanUsername => "0.0.0.0",
    }
}

fn default_trusted_client(template: WizardTemplate) -> &'static str {
    match template {
        WizardTemplate::LocalNoAuth => "127.0.0.1",
        WizardTemplate::LanUsername => "192.168.0.0/16",
    }
}

fn default_userlist_path(output_path: &Path) -> String {
    output_sibling(output_path, Path::new("users"))
}

fn default_log_path(output_path: &Path) -> String {
    output_sibling(output_path, &PathBuf::from("logs").join("alighieri.log"))
}

fn output_sibling(output_path: &Path, default_relative: &Path) -> String {
    output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| parent.join(default_relative))
        .unwrap_or_else(|| default_relative.to_path_buf())
        .display()
        .to_string()
}

fn render_config(form: &WizardForm) -> String {
    let mut text = String::new();
    writeln!(text, "# Generated by alighieri config wizard").unwrap();
    writeln!(
        text,
        "internal: {} port = {}",
        form.listen_host, form.listen_port
    )
    .unwrap();
    writeln!(text, "external: 0.0.0.0").unwrap();
    writeln!(text).unwrap();
    // `template` is the single source of truth for the generated structure (it
    // also drives the `socks` rules below); `if let Some` avoids the `unwrap`
    // panic if the template/userlist invariant ever shifts.
    match form.template {
        WizardTemplate::LocalNoAuth => {
            writeln!(text, "socksmethod: none").unwrap();
        }
        WizardTemplate::LanUsername => {
            writeln!(text, "socksmethod: username").unwrap();
            if let Some(userlist) = &form.userlist_path {
                writeln!(text, "userlist: {}", userlist.display()).unwrap();
            }
        }
    }
    writeln!(text).unwrap();
    writeln!(text, "connecttimeout: 30").unwrap();
    writeln!(text, "handshaketimeout: 10").unwrap();
    writeln!(text, "iotimeout: 0").unwrap();
    writeln!(text, "udptimeout: 60").unwrap();
    writeln!(text, "maxconnections: 1024").unwrap();
    writeln!(text).unwrap();
    if let Some(log_file) = &form.log_file {
        writeln!(text, "logoutput: file").unwrap();
        if log_file.is_relative() {
            writeln!(
                text,
                "# WARNING: this logfile path is relative; it resolves against the service"
            )
            .unwrap();
            writeln!(
                text,
                "# working directory. If that location is not writable, logging fails to"
            )
            .unwrap();
            writeln!(
                text,
                "# initialise and the proxy exits at startup. Use an absolute path instead."
            )
            .unwrap();
            #[cfg(target_os = "linux")]
            writeln!(
                text,
                "# (a hardened systemd unit runs with WorkingDirectory=/, so a relative path"
            )
            .unwrap();
            #[cfg(target_os = "linux")]
            writeln!(text, "#  resolves under / and is not writable.)").unwrap();
        }
        writeln!(
            text,
            "# logfile should be an absolute path writable by the running service."
        )
        .unwrap();
        #[cfg(target_os = "linux")]
        writeln!(
            text,
            "# (under the hardened systemd unit, only the service log dir is writable.)"
        )
        .unwrap();
        writeln!(text, "logfile: {}", log_file.display()).unwrap();
        writeln!(text, "logrotate.size: 10MiB").unwrap();
        writeln!(text, "logrotate.keep: 5").unwrap();
    } else {
        writeln!(text, "logoutput: stdout").unwrap();
    }
    writeln!(text, "logformat: text").unwrap();
    writeln!(text).unwrap();
    writeln!(text, "dns.prefer: system").unwrap();
    writeln!(text, "dns.tryall: false").unwrap();
    writeln!(text, "dns.deny: private linklocal loopback reserved").unwrap();
    writeln!(text, "dns.cachettl: 60").unwrap();
    writeln!(text).unwrap();
    writeln!(text, "client pass \"trusted-clients\" {{").unwrap();
    writeln!(text, "    from: {} to: 0.0.0.0/0", form.trusted_client).unwrap();
    writeln!(text, "}}").unwrap();
    writeln!(text).unwrap();
    writeln!(text, "socks block \"deny-loopback\" {{").unwrap();
    writeln!(text, "    from: 0.0.0.0/0 to: 127.0.0.0/8").unwrap();
    writeln!(text, "}}").unwrap();
    writeln!(text).unwrap();
    match form.template {
        WizardTemplate::LocalNoAuth => {
            writeln!(text, "socks pass \"allow-default\" {{").unwrap();
            writeln!(text, "    from: 0.0.0.0/0 to: 0.0.0.0/0").unwrap();
            writeln!(text, "    protocol: tcp udp").unwrap();
            writeln!(text, "    command: connect udpassociate").unwrap();
            writeln!(text, "}}").unwrap();
        }
        WizardTemplate::LanUsername => {
            writeln!(text, "socks pass \"allow-web\" {{").unwrap();
            writeln!(text, "    from: 0.0.0.0/0 to: 0.0.0.0/0 port = 80-443").unwrap();
            writeln!(text, "    protocol: tcp").unwrap();
            writeln!(text, "    command: connect").unwrap();
            writeln!(text, "}}").unwrap();
        }
    }
    text
}

// ---------------------------------------------------------------------------
// Importing an existing configuration
// ---------------------------------------------------------------------------

/// Reads and parses an existing config so the wizard can pre-fill its form, and
/// records which setting areas the wizard cannot represent (and would therefore
/// drop on save). Refuses files that do not parse: there is nothing safe to
/// pre-fill from an invalid configuration.
fn load_import_prefill(path: &Path, output_path: &Path) -> Result<ImportPrefill, String> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "failed to read configuration to import {}: {e}",
            path.display()
        )
    })?;
    let original = Config::parse(&contents).map_err(|e| {
        format!(
            "cannot import {}: it is not a valid configuration: {e}",
            path.display()
        )
    })?;
    let form = wizard_form_from_config(&original, output_path);
    let warnings = import_loss_warnings(&original, &form)?;
    Ok(ImportPrefill {
        form,
        warnings,
        source: path.to_path_buf(),
    })
}

/// Best-effort extraction of the wizard's modelled fields from a parsed config.
/// Anything the wizard does not model is recovered separately as a loss warning.
fn wizard_form_from_config(config: &Config, output_path: &Path) -> WizardForm {
    let template = if config.socks_methods.contains(&AuthKind::Username) {
        WizardTemplate::LanUsername
    } else {
        WizardTemplate::LocalNoAuth
    };
    let userlist_path = if template == WizardTemplate::LanUsername {
        config.userlist.clone()
    } else {
        None
    };
    let log_file = if config.log_outputs.contains(&LogOutput::File) {
        config.log_file.clone()
    } else {
        None
    };
    WizardForm {
        template,
        output_path: output_path.to_path_buf(),
        listen_host: config.internal.ip().to_string(),
        listen_port: config.internal.port(),
        trusted_client: extract_trusted_client(config)
            .unwrap_or_else(|| default_trusted_client(template).to_string()),
        userlist_path,
        log_file,
    }
}

/// Reads the single trusted-client CIDR from the first `client pass` rule that
/// matches the exact shape the wizard emits: one source CIDR with no port
/// constraint, an unrestricted IPv4 destination (`to: 0.0.0.0/0`), and no
/// command/protocol/method selectors. Any other rule is left for the rule loss
/// warning rather than pre-filled — and potentially misrepresented — here.
fn extract_trusted_client(config: &Config) -> Option<String> {
    let wizard_to = ["0.0.0.0/0".parse::<Cidr>().ok()?];
    config
        .rules
        .rules
        .iter()
        .filter(|rule| {
            rule.scope == Scope::Client
                && rule.verdict == Verdict::Pass
                && rule.from.ports.is_none()
                && rule.to.ports.is_none()
                && rule.to.cidrs == wizard_to
                && rule.commands.is_empty()
                && rule.protocols.is_empty()
                && rule.methods.is_empty()
        })
        .find_map(|rule| match rule.from.cidrs.as_slice() {
            [cidr] => Some(cidr.to_string()),
            _ => None,
        })
}

/// Renders the extracted form, re-parses it, and reports which setting areas of
/// the original would not survive that round trip — i.e. what saving drops.
fn import_loss_warnings(original: &Config, form: &WizardForm) -> Result<Vec<String>, String> {
    let regenerated = Config::parse(&render_config(form))
        .map_err(|e| format!("failed to evaluate which imported settings are preserved: {e}"))?;
    Ok(config_loss_warnings(original, &regenerated))
}

/// Compares an imported config against the config the wizard would actually
/// write, returning a human-readable list of the setting areas that differ.
fn config_loss_warnings(original: &Config, regenerated: &Config) -> Vec<String> {
    let mut lost = Vec::new();
    if original.tls != regenerated.tls {
        lost.push("TLS listener (tls.certfile / tls.keyfile)".to_string());
    }
    if original.metrics_listen != regenerated.metrics_listen {
        lost.push("metrics endpoint (metrics.listen)".to_string());
    }
    if original.rate_limits != regenerated.rate_limits {
        lost.push("rate limits (ratelimit.*)".to_string());
    }
    if original.socks_methods != regenerated.socks_methods {
        lost.push("authentication methods (socksmethod)".to_string());
    }
    if original.userlist != regenerated.userlist {
        lost.push("userlist path (userlist)".to_string());
    }
    if original.auth_cache_ttl != regenerated.auth_cache_ttl {
        lost.push("auth cache TTL (auth.cachettl)".to_string());
    }
    if original.dns != regenerated.dns {
        lost.push("DNS policy (dns.prefer / dns.tryall / dns.deny / dns.cachettl)".to_string());
    }
    if original.external != regenerated.external {
        lost.push("outbound source address (external)".to_string());
    }
    if original.connect_timeout != regenerated.connect_timeout
        || original.handshake_timeout != regenerated.handshake_timeout
        || original.io_timeout != regenerated.io_timeout
        || original.udp_timeout != regenerated.udp_timeout
    {
        lost.push(
            "timeouts (connecttimeout / handshaketimeout / iotimeout / udptimeout)".to_string(),
        );
    }
    if original.max_connections != regenerated.max_connections {
        lost.push("maximum connections (maxconnections)".to_string());
    }
    if original.log_format != regenerated.log_format
        || original.log_outputs != regenerated.log_outputs
        || original.log_rotate_size != regenerated.log_rotate_size
        || original.log_rotate_keep != regenerated.log_rotate_keep
    {
        lost.push("logging (logformat / logoutput / logrotate.*)".to_string());
    }
    if !rulesets_equivalent(&original.rules, &regenerated.rules) {
        lost.push("access-control rules (extra or customised client/socks rules)".to_string());
    }
    lost
}

/// Structural rule-set comparison that ignores `source_line`, which always
/// differs after regeneration because the generated text has a new layout.
fn rulesets_equivalent(a: &RuleSet, b: &RuleSet) -> bool {
    a.rules.len() == b.rules.len()
        && a.rules.iter().zip(&b.rules).all(|(x, y)| {
            x.name == y.name
                && x.verdict == y.verdict
                && x.scope == y.scope
                && x.from == y.from
                && x.to == y.to
                && x.commands == y.commands
                && x.protocols == y.protocols
                && x.methods == y.methods
        })
}

fn write_config_atomically(path: &Path, contents: &[u8]) -> std::io::Result<WriteReport> {
    let existed = path.exists();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let (temp_path, mut file) = create_config_temp(path, existed)?;
    {
        file.write_all(contents)?;
        file.sync_all()?;
    }
    drop(file);
    let backup_path = if existed {
        match create_config_backup(path) {
            Ok(backup) => Some(backup),
            // The config can vanish between the exists() snapshot and the
            // backup copy; continue as a new-file write.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                let _ = std::fs::remove_file(&temp_path);
                return Err(e);
            }
        }
    } else {
        None
    };
    if let Err(e) = replace_config(&temp_path, path, existed) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    if let Err(e) = sync_parent(path) {
        eprintln!(
            "alighieri: warning: failed to sync config directory after writing {}: {e}",
            path.display()
        );
    }
    Ok(WriteReport {
        output_path: path.to_path_buf(),
        backup_path,
    })
}

fn create_config_backup(path: &Path) -> std::io::Result<PathBuf> {
    let backup = backup_path(path);
    remove_stale_backup(&backup)?;
    std::fs::copy(path, &backup)?;
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&backup)
    {
        Ok(file) => file.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let file = std::fs::OpenOptions::new().read(true).open(&backup)?;
            let _ = file.sync_all();
        }
        Err(e) => return Err(e),
    }
    Ok(backup)
}

fn remove_stale_backup(backup: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(backup) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => retry_remove_read_only(backup, e),
    }
}

// Windows refuses to delete read-only files (a read-only config propagates the
// attribute to its backup via fs::copy); the lint's Unix world-writable concern
// does not apply because the file is removed immediately afterwards.
#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn retry_remove_read_only(backup: &Path, remove_error: std::io::Error) -> std::io::Result<()> {
    let Ok(metadata) = std::fs::metadata(backup) else {
        return Err(remove_error);
    };
    let mut permissions = metadata.permissions();
    if !permissions.readonly() {
        return Err(remove_error);
    }
    permissions.set_readonly(false);
    if std::fs::set_permissions(backup, permissions).is_err() {
        return Err(remove_error);
    }
    std::fs::remove_file(backup)
}

// Unix unlink ignores file permissions (the directory governs), so a failed
// removal is not a read-only problem worth retrying.
#[cfg(not(windows))]
fn retry_remove_read_only(_backup: &Path, remove_error: std::io::Error) -> std::io::Result<()> {
    Err(remove_error)
}

fn create_config_temp(path: &Path, _existed: bool) -> std::io::Result<(PathBuf, std::fs::File)> {
    #[cfg(unix)]
    let metadata = config_unix_metadata(path, _existed)?;

    for _ in 0..100 {
        let temp_path = next_temp_path(path);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options.mode(metadata.mode);
        }
        match options.open(&temp_path) {
            Ok(file) => {
                #[cfg(unix)]
                {
                    apply_config_unix_metadata(&file, metadata)?;
                }
                return Ok((temp_path, file));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to create unique temporary config path",
    ))
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct ConfigUnixMetadata {
    mode: u32,
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
fn config_unix_metadata(path: &Path, existed: bool) -> std::io::Result<ConfigUnixMetadata> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if existed {
        match std::fs::metadata(path) {
            Ok(metadata) => {
                return Ok(ConfigUnixMetadata {
                    mode: metadata.permissions().mode() & 0o777,
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                });
            }
            // The config can vanish between the exists() snapshot and this
            // read; fall back to new-file metadata.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(ConfigUnixMetadata {
        mode: 0o600,
        uid: u32::MAX,
        gid: u32::MAX,
    })
}

#[cfg(unix)]
fn apply_config_unix_metadata(
    file: &std::fs::File,
    metadata: ConfigUnixMetadata,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;

    file.set_permissions(std::fs::Permissions::from_mode(metadata.mode))?;
    if metadata.uid != u32::MAX || metadata.gid != u32::MAX {
        let rc = unsafe { libc::fchown(file.as_raw_fd(), metadata.uid, metadata.gid) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::PermissionDenied {
                return Err(err);
            }
        }
    }
    Ok(())
}

fn next_temp_path(path: &Path) -> PathBuf {
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("alighieri.conf");
    let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()))
}

fn backup_path(path: &Path) -> PathBuf {
    let mut backup = path.to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("alighieri.conf");
    backup.set_file_name(format!("{file_name}.bak"));
    backup
}

#[cfg(not(windows))]
fn replace_config(temp_path: &Path, path: &Path, _existed: bool) -> std::io::Result<()> {
    std::fs::rename(temp_path, path)
}

#[cfg(windows)]
fn replace_config(temp_path: &Path, path: &Path, existed: bool) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_WRITE_THROUGH,
    };

    let from: Vec<u16> = temp_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if existed {
        let ok = unsafe {
            ReplaceFileW(
                to.as_ptr(),
                from.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        // ReplaceFileW requires an existing destination; if the config
        // vanished after the exists() snapshot, fall through to a plain move.
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(err);
        }
    }
    let ok = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn random_token() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(token, "{byte:02x}").unwrap();
    }
    token
}

fn print_save_report(report: &WriteReport) {
    println!(
        "alighieri: wrote configuration to {}",
        report.output_path.display()
    );
    if let Some(backup) = &report.backup_path {
        println!(
            "alighieri: previous configuration backed up to {}",
            backup.display()
        );
    }
    println!(
        "alighieri: run with: alighieri --config {}",
        shell_quote_path(&report.output_path)
    );
}

// Windows file names cannot contain '"', so double quotes are always safe
// there; POSIX shells need single quotes to keep '"', '$', and backticks
// literal, with embedded single quotes rewritten as '\''.
fn shell_quote_path(path: &Path) -> String {
    let text = path.display().to_string();
    if cfg!(windows) {
        // Double any trailing backslashes so they escape themselves rather than
        // the closing quote (Windows command-line argument parsing rule).
        let trailing = text.len() - text.trim_end_matches('\\').len();
        format!("\"{text}{}\"", "\\".repeat(trailing))
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

#[derive(Clone)]
struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: String,
    done: bool,
}

impl HttpResponse {
    fn html(status: u16, reason: &'static str, body: String) -> Self {
        Self {
            status,
            reason,
            content_type: "text/html; charset=utf-8",
            body,
            done: false,
        }
    }

    fn text(status: u16, reason: &'static str, body: &str) -> Self {
        Self {
            status,
            reason,
            content_type: "text/plain; charset=utf-8",
            body: body.to_string(),
            done: false,
        }
    }

    fn done(mut self) -> Self {
        self.done = true;
        self
    }

    fn as_bytes(&self) -> Vec<u8> {
        let body = self.body.as_bytes();
        let headers = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\n\r\n",
            self.status,
            self.reason,
            self.content_type,
            body.len()
        );
        let mut response = headers.into_bytes();
        response.extend_from_slice(body);
        response
    }
}

fn render_wizard_form(
    token: &str,
    default_output_path: &Path,
    prefill: Option<&ImportPrefill>,
) -> String {
    let action = format!("/generate?token={}", html_escape(token));

    // Initial field values come from the imported config when present, else the
    // standard fresh-form defaults.
    let template = prefill.map_or(WizardTemplate::LocalNoAuth, |p| p.form.template);
    let listen_host = prefill.map_or_else(
        || default_listen_host(template).to_string(),
        |p| p.form.listen_host.clone(),
    );
    let listen_port = prefill.map_or(1080, |p| p.form.listen_port);
    let trusted_client = prefill.map_or_else(
        || default_trusted_client(template).to_string(),
        |p| p.form.trusted_client.clone(),
    );
    let output_path = prefill.map_or_else(
        || default_output_path.to_path_buf(),
        |p| p.form.output_path.clone(),
    );
    let userlist_value = match prefill.and_then(|p| p.form.userlist_path.as_ref()) {
        Some(path) => path.display().to_string(),
        None => default_userlist_path(&output_path),
    };
    let logfile_value = prefill
        .and_then(|p| p.form.log_file.as_ref())
        .map(|path| path.display().to_string())
        .unwrap_or_default();

    let output = html_escape(&output_path.display().to_string());
    let userlist = html_escape(&userlist_value);
    let logfile = html_escape(&logfile_value);
    let listen_host_attr = html_escape(&listen_host);
    let trusted_attr = html_escape(&trusted_client);
    let (local_checked, lan_checked) = match template {
        WizardTemplate::LocalNoAuth => (" checked", ""),
        WizardTemplate::LanUsername => ("", " checked"),
    };
    let banner = render_import_banner(prefill);

    html_page(
        "Alighieri Config Wizard",
        &format!(
            r#"<main>
<h1>Alighieri Config Wizard</h1>{banner}
<form method="post" action="{action}">
<section>
<h2>Template</h2>
<label><input type="radio" name="template" value="local-no-auth"{local_checked}> Local apps only, no authentication</label>
<label><input type="radio" name="template" value="lan-username"{lan_checked}> LAN clients with username/password</label>
</section>
<section>
<h2>Listener</h2>
<label>Listen address <input name="listen_host" value="{listen_host_attr}" required placeholder="127.0.0.1 or 0.0.0.0" autocomplete="off"></label>
<label>Port <input name="listen_port" type="number" min="1" max="65535" value="{listen_port}" required></label>
<label>Trusted client range <input name="trusted_client" value="{trusted_attr}" required placeholder="127.0.0.1 or 192.168.0.0/16" autocomplete="off"></label>
</section>
<section>
<h2>Files</h2>
<label>Config output <input name="output" value="{output}" required placeholder="alighieri.conf" autocomplete="off"></label>
<label>Userlist path <input name="userlist" value="{userlist}" placeholder="users (required for the username template)" autocomplete="off"></label>
<label>Log file (optional) <input name="logfile" value="{logfile}" placeholder="absolute path recommended; empty = stdout / journald" autocomplete="off"></label>
</section>
<button type="submit">Generate config</button>
</form>
<script>
const presets = {{
  "local-no-auth": {{ listen: "127.0.0.1", trusted: "127.0.0.1", logfile: "" }},
  "lan-username": {{ listen: "0.0.0.0", trusted: "192.168.0.0/16", logfile: "" }}
}};
const listen = document.querySelector("[name=listen_host]");
const trusted = document.querySelector("[name=trusted_client]");
const logfile = document.querySelector("[name=logfile]");
document.querySelectorAll("[name=template]").forEach((radio) => {{
  radio.addEventListener("change", () => {{
    const previous = radio.value === "lan-username" ? presets["local-no-auth"] : presets["lan-username"];
    const next = presets[radio.value];
    if (listen.value === previous.listen) listen.value = next.listen;
    if (trusted.value === previous.trusted) trusted.value = next.trusted;
    if (logfile.value === previous.logfile) logfile.value = next.logfile;
  }});
}});
</script>
</main>"#
        ),
    )
}

/// Renders the "imported configuration" banner shown above the form, including
/// the list of settings that saving will not preserve. Empty when not importing.
fn render_import_banner(prefill: Option<&ImportPrefill>) -> String {
    let Some(prefill) = prefill else {
        return String::new();
    };
    let source = html_escape(&prefill.source.display().to_string());
    let mut banner = format!(
        "\n<section class=\"import-notice\">\n<h2>Imported configuration</h2>\n\
<p>Loaded settings from <code>{source}</code>. Review them below before saving.</p>\n"
    );
    if prefill.warnings.is_empty() {
        banner.push_str(
            "<p>Every setting in that file is represented by the wizard, so saving preserves it.</p>\n",
        );
    } else {
        banner.push_str(
            "<p><strong>Saving will not preserve these settings from the original file:</strong></p>\n<ul>\n",
        );
        for warning in &prefill.warnings {
            let _ = writeln!(banner, "<li>{}</li>", html_escape(warning));
        }
        banner.push_str(
            "</ul>\n<p>The original file is kept as a <code>.bak</code> backup when you save, so those settings can be restored.</p>\n",
        );
    }
    banner.push_str("</section>");
    banner
}

fn render_success(report: &WriteReport, form: &WizardForm) -> String {
    let output = html_escape(&report.output_path.display().to_string());
    let backup = report.backup_path.as_ref().map(|backup| {
        format!(
            "<p>Previous configuration backed up to <code>{}</code>.</p>",
            html_escape(&backup.display().to_string())
        )
    });
    let run = html_escape(&format!(
        "alighieri --config {}",
        shell_quote_path(&report.output_path)
    ));
    let commands = if cfg!(windows) {
        let install = html_escape(&format!(
            "alighieri service install --config {}",
            shell_quote_path(&report.output_path)
        ));
        format!("{run}\n{install}\nalighieri service start\nalighieri service reload")
    } else {
        run
    };
    // The username/password template authenticates against a userlist, which
    // the wizard does not create — point the operator at the tooling.
    let userlist_section = match (form.template, &form.userlist_path) {
        (WizardTemplate::LanUsername, Some(path)) => {
            let userlist = html_escape(&path.display().to_string());
            let add = html_escape(&format!(
                "alighieri user add USERNAME --userlist {}",
                shell_quote_path(path)
            ));
            format!(
                "<h2>Create the userlist</h2><p>This config authenticates against \
                 <code>{userlist}</code>, which must contain at least one user before \
                 clients can connect. Add users with:</p><pre>{add}</pre>"
            )
        }
        _ => String::new(),
    };
    html_page(
        "Configuration Saved",
        &format!(
            "<main><h1>Configuration Saved</h1><p>Wrote <code>{output}</code>.</p>{}<h2>Commands</h2><pre>{commands}</pre>{userlist_section}</main>",
            backup.unwrap_or_default()
        ),
    )
}

fn render_error(message: &str) -> String {
    html_page(
        "Configuration Error",
        &format!(
            "<main><h1>Configuration Error</h1><p>{}</p></main>",
            html_escape(message)
        ),
    )
}

fn html_page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{}</title>
<style>
:root {{ color-scheme: light; font-family: Inter, Segoe UI, Arial, sans-serif; }}
body {{ margin: 0; background: #f6f7f9; color: #20242a; }}
main {{ max-width: 760px; margin: 32px auto; padding: 0 20px 40px; }}
h1 {{ font-size: 28px; margin: 0 0 20px; }}
h2 {{ font-size: 16px; margin: 0 0 12px; }}
section {{ border: 1px solid #d9dee7; border-radius: 8px; padding: 16px; margin: 12px 0; background: #fff; }}
.import-notice {{ border-color: #e0b341; background: #fdf6e3; }}
.import-notice ul {{ margin: 8px 0 0; padding-left: 20px; }}
.import-notice li {{ font-size: 14px; margin: 4px 0; }}
label {{ display: block; margin: 10px 0; font-size: 14px; }}
input[type="text"], input[type="number"], input:not([type]) {{ box-sizing: border-box; display: block; width: 100%; margin-top: 6px; padding: 9px 10px; border: 1px solid #b8c0cc; border-radius: 6px; font: inherit; }}
button {{ margin-top: 12px; padding: 10px 14px; border: 0; border-radius: 6px; background: #1f6feb; color: #fff; font: inherit; cursor: pointer; }}
code, pre {{ background: #eef1f5; border-radius: 6px; }}
code {{ padding: 2px 4px; }}
pre {{ overflow-x: auto; padding: 14px; }}
</style>
</head>
<body>
{}
</body>
</html>"#,
        html_escape(title),
        body
    )
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            ch => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wizard_listen_must_be_loopback() {
        let err =
            parse_config_wizard_args(&["--listen".into(), "0.0.0.0:8080".into()]).unwrap_err();
        assert_eq!(err, "config wizard must listen on a loopback address");
    }

    #[test]
    fn wizard_args_parse_output_path() {
        let args = parse_config_wizard_args(&[
            "--listen".into(),
            "127.0.0.1:18080".into(),
            "--output".into(),
            "generated.conf".into(),
        ])
        .unwrap();
        assert_eq!(args.listen, "127.0.0.1:18080".parse().unwrap());
        assert_eq!(args.output_path, PathBuf::from("generated.conf"));
    }

    #[test]
    fn wizard_args_reject_directory_output_path() {
        let err = parse_config_wizard_args(&["--output".into(), "conf/".into()]).unwrap_err();
        assert_eq!(err, "output path must include a file name");
    }

    #[test]
    fn wizard_args_reject_multiline_output_path() {
        let err = parse_config_wizard_args(&["--output".into(), "conf\nalighieri.conf".into()])
            .unwrap_err();
        assert_eq!(err, "config wizard --output path must be a single line");
    }

    #[test]
    fn local_template_generates_valid_config() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "local-no-auth".into());
        let form = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap();
        let config = render_config(&form);
        Config::parse(&config).unwrap();
        assert!(config.contains("socksmethod: none"));
    }

    #[test]
    fn local_template_rejects_non_loopback_listener() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "local-no-auth".into());
        fields.insert("listen_host".into(), "0.0.0.0".into());

        let err = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap_err();

        assert_eq!(
            err,
            "local no-auth template must listen on a loopback address"
        );
    }

    #[test]
    fn lan_template_generates_valid_config() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "lan-username".into());
        fields.insert("listen_host".into(), "0.0.0.0".into());
        fields.insert("trusted_client".into(), "192.168.1.0/24".into());
        fields.insert("userlist".into(), "users".into());
        let form = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap();
        let config = render_config(&form);
        Config::parse(&config).unwrap();
        assert!(config.contains("socksmethod: username"));
        assert!(config.contains("userlist: users"));
    }

    #[test]
    fn lan_template_rejects_cleared_userlist_path() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "lan-username".into());
        fields.insert("userlist".into(), "  ".into());

        let err = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap_err();

        assert_eq!(err, "LAN username template requires a userlist path");
    }

    #[test]
    fn wizard_form_rejects_unknown_template() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "surprise-me".into());

        let err = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap_err();

        assert_eq!(err, "unknown config wizard template");
    }

    #[test]
    fn wizard_form_rejects_multiline_config_values() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "lan-username".into());
        fields.insert(
            "trusted_client".into(),
            "192.168.1.0/24\nlogoutput: stdout".into(),
        );
        fields.insert("userlist".into(), "users".into());

        let err = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap_err();

        assert_eq!(err, "trusted client range must be a single line");
    }

    #[test]
    fn wizard_form_rejects_hash_in_config_values() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "lan-username".into());
        fields.insert("userlist".into(), "users#prod".into());

        let err = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap_err();

        assert_eq!(
            err,
            "userlist path must not contain '#' (it starts a config comment)"
        );
    }

    #[test]
    fn wizard_form_rejects_multiline_output_defaults() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "lan-username".into());
        fields.insert("output".into(), "conf\ninjected/alighieri.conf".into());

        let err = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap_err();

        assert_eq!(err, "output path must be a single line");
    }

    #[test]
    fn wizard_form_rejects_directory_output_path() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "lan-username".into());
        fields.insert("output".into(), "conf/".into());

        let err = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap_err();

        assert_eq!(err, "output path must include a file name");
    }

    #[test]
    fn wizard_form_rejects_existing_directory_output_path() {
        let dir = tempfile::tempdir().unwrap();
        let output_dir = dir.path().join("conf");
        std::fs::create_dir(&output_dir).unwrap();
        let mut fields = HashMap::new();
        fields.insert("template".into(), "lan-username".into());
        fields.insert("output".into(), output_dir.display().to_string());

        let err = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap_err();

        assert_eq!(err, "output path must include a file name");
    }

    #[test]
    fn urlencoded_parser_decodes_form_values() {
        let fields = parse_urlencoded(b"name=Alighieri+Proxy&path=C%3A%5Cconf");
        assert_eq!(fields.get("name").unwrap(), "Alighieri Proxy");
        assert_eq!(fields.get("path").unwrap(), "C:\\conf");
    }

    #[test]
    fn content_type_check_accepts_case_and_parameters() {
        assert!(is_urlencoded_content_type(
            "Application/X-WWW-Form-Urlencoded; charset=UTF-8"
        ));
        assert!(!is_urlencoded_content_type("text/plain"));
    }

    #[test]
    fn wizard_responses_are_not_cacheable() {
        let response = HttpResponse::html(200, "OK", html_page("title", "<main></main>"));
        let bytes = response.as_bytes();
        let response = String::from_utf8_lossy(&bytes);

        assert!(response.contains("\r\nCache-Control: no-store\r\n"));
        assert!(response.contains("\r\nReferrer-Policy: no-referrer\r\n"));
        assert!(response.contains("\r\nX-Frame-Options: DENY\r\n"));
        assert!(response.contains("\r\nContent-Security-Policy: frame-ancestors 'none'\r\n"));
    }

    #[test]
    fn local_template_honors_explicit_logfile() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "local-no-auth".into());
        fields.insert("logfile".into(), "logs/alighieri.log".into());
        let form = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap();
        let config = render_config(&form);
        Config::parse(&config).unwrap();
        assert!(config.contains("logoutput: file"));
        assert!(config.contains("logfile: "));
        assert!(config.contains("alighieri.log"));
    }

    #[test]
    fn relative_logfile_warns_in_config_but_absolute_does_not() {
        // A relative path gets an explicit warning about the hardened-unit footgun.
        let mut rel = HashMap::new();
        rel.insert("template".into(), "local-no-auth".into());
        rel.insert("logfile".into(), "logs/alighieri.log".into());
        let rel_form = wizard_form_from_fields(&rel, Path::new("alighieri.conf")).unwrap();
        let rel_config = render_config(&rel_form);
        assert!(rel_config.contains("# WARNING: this logfile path is relative"));
        // The footgun is a hard startup failure (logging init aborts), not silent loss.
        assert!(rel_config.contains("exits at startup"));
        assert!(rel_config.contains("# logfile should be an absolute path"));
        Config::parse(&rel_config).unwrap();
        // The systemd specifics are scoped to Linux; other platforms must not see them.
        #[cfg(target_os = "linux")]
        assert!(rel_config.contains("systemd"));
        #[cfg(not(target_os = "linux"))]
        assert!(!rel_config.contains("systemd"));

        // An absolute path gets the guidance comment but not the relative-path warning.
        let mut abs = HashMap::new();
        abs.insert("template".into(), "local-no-auth".into());
        #[cfg(windows)]
        abs.insert(
            "logfile".into(),
            r"C:\ProgramData\alighieri\alighieri.log".into(),
        );
        #[cfg(not(windows))]
        abs.insert("logfile".into(), "/var/log/alighieri/alighieri.log".into());
        let abs_form = wizard_form_from_fields(&abs, Path::new("alighieri.conf")).unwrap();
        let abs_config = render_config(&abs_form);
        assert!(!abs_config.contains("WARNING"));
        assert!(abs_config.contains("# logfile should be an absolute path"));
        Config::parse(&abs_config).unwrap();
        #[cfg(target_os = "linux")]
        assert!(abs_config.contains("systemd"));
        #[cfg(not(target_os = "linux"))]
        assert!(!abs_config.contains("systemd"));
    }

    #[test]
    fn rendered_form_uses_output_relative_userlist_default() {
        let output = Path::new("conf/alighieri.conf");
        let html = render_wizard_form("token", output, None);
        assert!(html.contains(&format!(
            r#"value="{}""#,
            html_escape(&default_userlist_path(output))
        )));
        // The log file no longer carries a pre-filled default (it defaults to stdout).
        assert!(!html.contains("data-default"));
    }

    #[test]
    fn rendered_form_defaults_logfile_to_stdout() {
        let output = Path::new(r"C:\ProgramData\alighieri\alighieri.conf");
        let html = render_wizard_form("token", output, None);
        // Both templates default the log file to empty -> stdout, with no
        // pre-filled path and no JS auto-fill from a data attribute.
        assert!(html.contains(
            r#""lan-username": { listen: "0.0.0.0", trusted: "192.168.0.0/16", logfile: "" }"#
        ));
        assert!(!html.contains("dataset.default"));
        assert!(!html.contains("data-default"));
    }

    #[test]
    fn lan_template_defaults_to_stdout_logging() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "lan-username".into());
        fields.insert("userlist".into(), "/etc/alighieri/users".into());
        // No logfile field: must default to stdout, not a (possibly non-writable) file.
        let form =
            wizard_form_from_fields(&fields, Path::new("/etc/alighieri/alighieri.conf")).unwrap();
        assert!(form.log_file.is_none());
        let config = render_config(&form);
        assert!(config.contains("logoutput: stdout"));
        assert!(!config.contains("logoutput: file"));
        Config::parse(&config).unwrap();
    }

    #[test]
    fn wizard_args_import_defaults_output_to_import_path() {
        let args = parse_config_wizard_args(&["--import".into(), "existing.conf".into()]).unwrap();
        assert_eq!(args.import_path, Some(PathBuf::from("existing.conf")));
        assert_eq!(args.output_path, PathBuf::from("existing.conf"));
    }

    #[test]
    fn wizard_args_import_keeps_explicit_output() {
        let args = parse_config_wizard_args(&[
            "--import".into(),
            "existing.conf".into(),
            "--output".into(),
            "new.conf".into(),
        ])
        .unwrap();
        assert_eq!(args.import_path, Some(PathBuf::from("existing.conf")));
        assert_eq!(args.output_path, PathBuf::from("new.conf"));
    }

    #[test]
    fn imported_form_extracts_modelled_fields() {
        let config = Config::parse(
            "internal: 0.0.0.0 port = 1080\n\
             external: 0.0.0.0\n\
             socksmethod: username\n\
             userlist: creds/users\n\
             logoutput: file\n\
             logfile: logs/app.log\n\
             client pass { from: 192.168.0.0/16 to: 0.0.0.0/0 }\n\
             socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }\n",
        )
        .unwrap();
        let form = wizard_form_from_config(&config, Path::new("out.conf"));
        assert_eq!(form.template, WizardTemplate::LanUsername);
        assert_eq!(form.listen_host, "0.0.0.0");
        assert_eq!(form.listen_port, 1080);
        assert_eq!(form.trusted_client, "192.168.0.0/16");
        assert_eq!(form.userlist_path, Some(PathBuf::from("creds/users")));
        assert_eq!(form.log_file, Some(PathBuf::from("logs/app.log")));
    }

    #[test]
    fn wizard_generated_config_imports_without_warnings() {
        // A config the wizard itself produced must round-trip with nothing lost.
        let original_form = WizardForm {
            template: WizardTemplate::LocalNoAuth,
            output_path: PathBuf::from("out.conf"),
            listen_host: "127.0.0.1".into(),
            listen_port: 1080,
            trusted_client: "127.0.0.1".into(),
            userlist_path: None,
            log_file: None,
        };
        let original = Config::parse(&render_config(&original_form)).unwrap();
        let extracted = wizard_form_from_config(&original, Path::new("out.conf"));
        let warnings = import_loss_warnings(&original, &extracted).unwrap();
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn import_flags_settings_the_wizard_cannot_represent() {
        let config = Config::parse(
            "internal: 127.0.0.1 port = 1080\n\
             external: 0.0.0.0\n\
             socksmethod: none\n\
             metrics.listen: 127.0.0.1:9090\n\
             tls.certfile: server.crt\n\
             tls.keyfile: server.key\n\
             ratelimit.connectionrate: 60/60\n\
             client pass { from: 127.0.0.1 to: 0.0.0.0/0 }\n\
             socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }\n",
        )
        .unwrap();
        let form = wizard_form_from_config(&config, Path::new("out.conf"));
        let warnings = import_loss_warnings(&config, &form).unwrap();
        assert!(warnings.iter().any(|w| w.contains("TLS")), "{warnings:?}");
        assert!(
            warnings.iter().any(|w| w.contains("metrics")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("rate limits")),
            "{warnings:?}"
        );
    }

    #[test]
    fn imported_form_renders_prefilled_values_and_warnings() {
        let prefill = ImportPrefill {
            form: WizardForm {
                template: WizardTemplate::LanUsername,
                output_path: PathBuf::from("out.conf"),
                listen_host: "10.0.0.1".into(),
                listen_port: 2080,
                trusted_client: "10.0.0.0/8".into(),
                userlist_path: Some(PathBuf::from("creds/users")),
                log_file: Some(PathBuf::from("logs/app.log")),
            },
            warnings: vec!["TLS listener (tls.certfile / tls.keyfile)".into()],
            source: PathBuf::from("existing.conf"),
        };
        let html = render_wizard_form("token", Path::new("out.conf"), Some(&prefill));
        assert!(html.contains(r#"value="lan-username" checked"#));
        assert!(html.contains(r#"value="10.0.0.1""#));
        assert!(html.contains(r#"value="2080""#));
        assert!(html.contains(r#"value="10.0.0.0/8""#));
        assert!(html.contains("creds"));
        assert!(html.contains("import-notice"));
        assert!(html.contains("existing.conf"));
        assert!(html.contains("tls.certfile"));
    }

    #[test]
    fn load_import_prefill_rejects_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.conf");
        std::fs::write(&path, "internal: not-an-address\n").unwrap();
        let err = load_import_prefill(&path, Path::new("out.conf")).unwrap_err();
        assert!(err.contains("not a valid configuration"), "{err}");
    }

    #[test]
    fn import_flags_collapsed_auth_methods() {
        // The wizard emits a single method; a multi-method offer cannot survive.
        let config = Config::parse(
            "internal: 127.0.0.1 port = 1080\n\
             external: 0.0.0.0\n\
             socksmethod: username none\n\
             userlist: creds/users\n\
             client pass { from: 192.168.0.0/16 to: 0.0.0.0/0 }\n\
             socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }\n",
        )
        .unwrap();
        let form = wizard_form_from_config(&config, Path::new("out.conf"));
        let warnings = import_loss_warnings(&config, &form).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("authentication methods")),
            "{warnings:?}"
        );
    }

    #[test]
    fn import_flags_dropped_userlist_without_username() {
        // A userlist present under `socksmethod: none` is dropped on regenerate.
        let config = Config::parse(
            "internal: 127.0.0.1 port = 1080\n\
             external: 0.0.0.0\n\
             socksmethod: none\n\
             userlist: creds/users\n\
             client pass { from: 127.0.0.1 to: 0.0.0.0/0 }\n\
             socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }\n",
        )
        .unwrap();
        let form = wizard_form_from_config(&config, Path::new("out.conf"));
        let warnings = import_loss_warnings(&config, &form).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("userlist")),
            "{warnings:?}"
        );
    }

    #[test]
    fn extract_trusted_client_matches_only_wizard_rule_shape() {
        // Wizard shape: one source CIDR, `to: 0.0.0.0/0`, no other selectors.
        let wizard_shaped = Config::parse(
            "internal: 127.0.0.1 port = 1080\n\
             external: 0.0.0.0\n\
             socksmethod: none\n\
             client pass { from: 192.168.0.0/16 to: 0.0.0.0/0 }\n\
             socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }\n",
        )
        .unwrap();
        assert_eq!(
            extract_trusted_client(&wizard_shaped).as_deref(),
            Some("192.168.0.0/16")
        );

        // A restricted destination is not the wizard's shape: do not pre-fill
        // from it (the rule loss warning covers the difference instead).
        let restricted_dest = Config::parse(
            "internal: 127.0.0.1 port = 1080\n\
             external: 0.0.0.0\n\
             socksmethod: none\n\
             client pass { from: 192.168.0.0/16 to: 10.0.0.0/8 }\n\
             socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect }\n",
        )
        .unwrap();
        assert_eq!(extract_trusted_client(&restricted_dest), None);
    }

    fn sample_form(template: WizardTemplate, userlist_path: Option<PathBuf>) -> WizardForm {
        WizardForm {
            template,
            output_path: PathBuf::from("alighieri.conf"),
            listen_host: "127.0.0.1".into(),
            listen_port: 1080,
            trusted_client: "127.0.0.1".into(),
            userlist_path,
            log_file: None,
        }
    }

    #[cfg(windows)]
    #[test]
    fn success_page_includes_service_commands_on_windows() {
        let report = WriteReport {
            output_path: PathBuf::from("alighieri.conf"),
            backup_path: None,
        };

        let html = render_success(&report, &sample_form(WizardTemplate::LocalNoAuth, None));

        assert!(html.contains("alighieri service install"));
        assert!(html.contains("alighieri service start"));
        assert!(html.contains("alighieri service reload"));
    }

    #[cfg(not(windows))]
    #[test]
    fn success_page_omits_service_commands_off_windows() {
        let report = WriteReport {
            output_path: PathBuf::from("alighieri.conf"),
            backup_path: None,
        };

        let html = render_success(&report, &sample_form(WizardTemplate::LocalNoAuth, None));

        assert!(html.contains("alighieri --config"));
        assert!(!html.contains("alighieri service"));
    }

    #[test]
    fn success_page_guides_userlist_creation_for_username_template() {
        let report = WriteReport {
            output_path: PathBuf::from("alighieri.conf"),
            backup_path: None,
        };
        let userlist = PathBuf::from("/etc/alighieri/users");
        let form = sample_form(WizardTemplate::LanUsername, Some(userlist.clone()));

        let html = render_success(&report, &form);

        assert!(html.contains("Create the userlist"));
        assert!(html.contains("alighieri user add USERNAME"));
        // Derive the expected string from the same display() the page uses, so
        // the assertion holds on any platform's path rendering.
        assert!(html.contains(&userlist.display().to_string()));
    }

    #[test]
    fn success_page_omits_userlist_guidance_for_local_template() {
        let report = WriteReport {
            output_path: PathBuf::from("alighieri.conf"),
            backup_path: None,
        };

        let html = render_success(&report, &sample_form(WizardTemplate::LocalNoAuth, None));

        assert!(!html.contains("Create the userlist"));
    }

    #[test]
    fn changed_output_rebases_untouched_file_defaults() {
        let mut fields = HashMap::new();
        fields.insert("template".into(), "lan-username".into());
        fields.insert("output".into(), "new/alighieri.conf".into());
        fields.insert("userlist".into(), "users".into());
        fields.insert("logfile".into(), "logs/alighieri.log".into());

        let form = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap();

        assert_eq!(form.userlist_path, Some(PathBuf::from("new").join("users")));
        assert_eq!(
            form.log_file,
            Some(PathBuf::from("new").join("logs").join("alighieri.log"))
        );
    }

    #[test]
    fn atomic_write_creates_backup_for_existing_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.conf");
        std::fs::write(&path, "old").unwrap();

        let report = write_config_atomically(&path, b"new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        let backup = report.backup_path.unwrap();
        assert_eq!(std::fs::read_to_string(backup).unwrap(), "old");
    }

    #[test]
    fn config_backup_handles_read_only_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.conf");
        std::fs::write(&path, "old").unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();

        let backup = create_config_backup(&path).unwrap();

        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "old");

        // Only Windows needs the read-only bit cleared before the temp dir can
        // be removed; on Unix the directory permission governs removal, so
        // clearing it there would only widen the file mode for nothing. Scoping
        // the cleanup (and the allow) to Windows keeps the lint live on Unix.
        #[cfg(windows)]
        #[allow(clippy::permissions_set_readonly_false)]
        {
            for file in [path.as_path(), backup.as_path()] {
                let mut permissions = std::fs::metadata(file).unwrap().permissions();
                permissions.set_readonly(false);
                std::fs::set_permissions(file, permissions).unwrap();
            }
        }
    }

    #[test]
    fn config_backup_replaces_read_only_stale_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.conf");
        std::fs::write(&path, "current").unwrap();
        let stale = backup_path(&path);
        std::fs::write(&stale, "stale").unwrap();
        let mut permissions = std::fs::metadata(&stale).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&stale, permissions).unwrap();

        let backup = create_config_backup(&path).unwrap();

        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "current");
    }

    #[cfg(unix)]
    #[test]
    fn new_config_file_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.conf");

        write_config_atomically(&path, b"new").unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn existing_config_file_mode_is_preserved_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.conf");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        write_config_atomically(&path, b"new").unwrap();

        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[test]
    fn atomic_write_removes_temp_file_when_backup_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.conf");
        std::fs::write(&path, "old").unwrap();
        std::fs::create_dir(backup_path(&path)).unwrap();

        let err = write_config_atomically(&path, b"new").unwrap_err();

        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::IsADirectory
            ),
            "unexpected error kind: {:?}",
            err.kind()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");
        let temp_files = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".alighieri.conf.tmp-")
            })
            .count();
        assert_eq!(temp_files, 0);
    }

    #[tokio::test]
    async fn malformed_request_returns_error_without_finishing_wizard() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = WizardState {
            token: "token".into(),
            default_output_path: PathBuf::from("alighieri.conf"),
            prefill: None,
        };

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_wizard_connection(stream, &state).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "POST /generate?token=token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
            MAX_FORM_BYTES + 1
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert!(!server.await.unwrap());
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains("config wizard form is too large"));
    }

    #[tokio::test(start_paused = true)]
    async fn incomplete_headers_time_out_without_finishing_wizard() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = WizardState {
            token: "token".into(),
            default_output_path: PathBuf::from("alighieri.conf"),
            prefill: None,
        };

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_wizard_connection(stream, &state).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(HTTP_REQUEST_TIMEOUT_SECS + 1)).await;
        tokio::task::yield_now().await;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert!(!server.await.unwrap());
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains("timed out reading config wizard request"));
    }

    #[tokio::test(start_paused = true)]
    async fn incomplete_body_times_out_without_finishing_wizard() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = WizardState {
            token: "token".into(),
            default_output_path: PathBuf::from("alighieri.conf"),
            prefill: None,
        };

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_wizard_connection(stream, &state).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"POST /generate?token=token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\n\r\n",
            )
            .await
            .unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(HTTP_REQUEST_TIMEOUT_SECS + 1)).await;
        tokio::task::yield_now().await;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert!(!server.await.unwrap());
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains("timed out reading config wizard request"));
    }

    #[tokio::test]
    async fn aborted_client_does_not_finish_wizard() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = WizardState {
            token: "token".into(),
            default_output_path: PathBuf::from("alighieri.conf"),
            prefill: None,
        };

        let client = TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        // Linger of zero aborts the connection with RST on drop; the
        // deprecation concern (blocking on drop) applies to non-zero linger.
        #[allow(deprecated)]
        client.set_linger(Some(Duration::from_secs(0))).unwrap();
        client
            .try_write(b"GET /?token=bad HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        drop(client);

        assert!(!handle_wizard_connection(stream, &state).await);
    }

    #[test]
    fn config_backup_missing_source_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.conf");

        let err = create_config_backup(&path).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn unix_metadata_falls_back_when_config_vanishes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.conf");

        let metadata = config_unix_metadata(&path, true).unwrap();

        assert_eq!(metadata.mode, 0o600);
    }

    #[cfg(windows)]
    #[test]
    fn replace_config_falls_back_when_target_vanishes() {
        let dir = tempfile::tempdir().unwrap();
        let temp = dir.path().join(".alighieri.conf.tmp-test");
        std::fs::write(&temp, "new").unwrap();
        let target = dir.path().join("alighieri.conf");

        replace_config(&temp, &target, true).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
    }

    #[cfg(windows)]
    #[test]
    fn shell_quote_path_uses_double_quotes_on_windows() {
        assert_eq!(
            shell_quote_path(Path::new(r"C:\conf dir\alighieri.conf")),
            r#""C:\conf dir\alighieri.conf""#
        );
    }

    #[cfg(windows)]
    #[test]
    fn shell_quote_path_doubles_trailing_backslashes_on_windows() {
        // A trailing backslash must be doubled so it escapes itself, not the
        // closing quote.
        assert_eq!(
            shell_quote_path(Path::new(r"C:\alighieri\")),
            r#""C:\alighieri\\""#
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn shell_quote_path_keeps_quote_characters_literal() {
        assert_eq!(
            shell_quote_path(Path::new(r#"it's "here"/$conf/alighieri.conf"#)),
            r#"'it'\''s "here"/$conf/alighieri.conf'"#
        );
    }

    #[test]
    fn html_escaping_covers_markup_characters() {
        assert_eq!(
            html_escape("<tag attr=\"one\">&'</tag>"),
            "&lt;tag attr=&quot;one&quot;&gt;&amp;&#39;&lt;/tag&gt;"
        );
    }

    #[test]
    fn token_matches_only_the_exact_token() {
        let token = "0a1b2c3d".to_string();
        assert!(token_matches(Some(&token), &token));
        assert!(!token_matches(Some(&"0a1b2c3e".to_string()), &token)); // one byte off
        assert!(!token_matches(Some(&"0a1b".to_string()), &token)); // shorter
        assert!(!token_matches(Some(&String::new()), &token));
        assert!(!token_matches(None, &token));
    }
}
