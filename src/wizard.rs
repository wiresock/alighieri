use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use alighieri::auth::UserDb;
use alighieri::config::{
    AuthKind, Cidr, Config, LogOutput, PortRange, RuleSet, Scope, TlsConfig, UdpAdvertise, Verdict,
};
use alighieri::util::constant_time_eq;
use password_hash::rand_core::{OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_WIZARD_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const DEFAULT_OUTPUT_PATH: &str = "alighieri.conf";
const MAX_HTTP_BYTES: usize = 64 * 1024;
const MAX_FORM_BYTES: usize = 32 * 1024;
const HTTP_REQUEST_TIMEOUT_SECS: u64 = 10;
#[cfg(test)]
const PUBLIC_DOMAIN_EXAMPLE: &str = "proxy.example.com";
const PUBLIC_UDP_RANGE: &str = "40000-40099";

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
    PublicTls,
}

impl WizardTemplate {
    fn from_form(value: &str) -> Result<Self, String> {
        match value {
            "local-no-auth" => Ok(WizardTemplate::LocalNoAuth),
            "lan-username" => Ok(WizardTemplate::LanUsername),
            "public-tls" => Ok(WizardTemplate::PublicTls),
            _ => Err("unknown config wizard template".into()),
        }
    }

    fn as_form_value(self) -> &'static str {
        match self {
            WizardTemplate::LocalNoAuth => "local-no-auth",
            WizardTemplate::LanUsername => "lan-username",
            WizardTemplate::PublicTls => "public-tls",
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
    public_domain: Option<String>,
    acme_email: Option<String>,
    initial_username: Option<String>,
    acme_cache_path: Option<PathBuf>,
    acme_staging: bool,
    udp_enabled: bool,
    udp_port_range: Option<String>,
    udp_advertise: Option<String>,
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
    let listen_port = parse_port(field(fields, "listen_port", default_listen_port(template)))?;
    let trusted_client =
        field(fields, "trusted_client", default_trusted_client(template)).to_string();
    let initial_userlist = default_userlist_path(default_output_path);
    let default_userlist = default_userlist_path(&output_path);
    let initial_log = default_log_path(default_output_path);
    let default_log = default_log_path(&output_path);
    let userlist_path = if template == WizardTemplate::PublicTls {
        required_path_field(
            fields,
            "userlist",
            "public profile userlist path",
            default_public_userlist_path(),
        )
        .map(Some)?
    } else {
        path_field_with_changed_output(fields, "userlist", &initial_userlist, &default_userlist)
    };
    let log_file = log_field_with_changed_output(fields, &initial_log, &default_log);

    let listen_ip = listen_host
        .parse::<IpAddr>()
        .map_err(|_| "listen address must be an IP address".to_string())?;
    if template == WizardTemplate::LocalNoAuth && !listen_ip.is_loopback() {
        return Err("local no-auth template must listen on a loopback address".into());
    }
    if template == WizardTemplate::PublicTls
        && (listen_ip != IpAddr::V4(Ipv4Addr::UNSPECIFIED) || listen_port != 443)
    {
        return Err(
            "public TLS profile must listen on 0.0.0.0 port 443 for ACME TLS-ALPN-01".into(),
        );
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
    if template == WizardTemplate::PublicTls
        && !userlist_path
            .as_ref()
            .is_some_and(|path| path.is_absolute())
    {
        return Err(
            "public profile userlist path must be absolute so the service and user command use the same file"
                .into(),
        );
    }
    if template == WizardTemplate::PublicTls {
        validate_public_userlist_path(
            userlist_path
                .as_deref()
                .expect("public userlist presence was checked above"),
        )?;
    }
    if template == WizardTemplate::PublicTls && trusted_client != "0.0.0.0/0" {
        return Err("public TLS profile client range must be 0.0.0.0/0".into());
    }

    let (
        public_domain,
        acme_email,
        initial_username,
        acme_cache_path,
        acme_staging,
        udp_enabled,
        udp_port_range,
        udp_advertise,
    ) = if template == WizardTemplate::PublicTls {
        let raw_domain = fields.get("public_domain").map_or("", String::as_str);
        if raw_domain != raw_domain.trim() {
            return Err("public domain must not have surrounding whitespace".into());
        }
        let domain = required_text_field(fields, "public_domain", "public domain")?;
        let domain = validate_public_domain(&domain)?;

        let email = match fields.get("acme_email") {
            Some(raw) => {
                validate_config_value("ACME account email", raw)?;
                let email = raw.trim();
                if email.is_empty() {
                    None
                } else {
                    Some(email.to_string())
                }
            }
            None => None,
        };
        if let Some(email) = &email {
            if email.chars().any(char::is_whitespace) {
                return Err("ACME account email must not contain whitespace".into());
            }
        }

        let username = fields
            .get("initial_username")
            .filter(|value| !value.is_empty())
            .cloned();
        if let Some(username) = &username {
            UserDb::validate_username(username)
                .map_err(|e| format!("initial username is invalid: {e}"))?;
        }

        let cache_path = required_path_field(
            fields,
            "acme_cache",
            "ACME cache path",
            default_public_acme_cache_path(),
        )?;
        validate_config_value("ACME cache path", &cache_path.display().to_string())?;
        if !cache_path.is_absolute() {
            return Err(
                "ACME cache path must be absolute so the service can write it reliably".into(),
            );
        }
        validate_public_acme_cache_path(&cache_path)?;

        let staging = parse_checkbox(fields, "acme_staging", false)?;
        let udp_enabled = parse_checkbox(fields, "udp_enabled", true)?;
        let (udp_port_range, udp_advertise) = if udp_enabled {
            let range = fields
                .get("udp_port_range")
                .map(String::as_str)
                .unwrap_or(PUBLIC_UDP_RANGE);
            if range.trim().is_empty() {
                return Err("UDP relay port range is required when UDP is enabled".into());
            }
            let range = parse_udp_port_range(range)?;
            let advertise = fields
                .get("udp_advertise")
                .map(String::as_str)
                .unwrap_or(&domain);
            validate_config_value("UDP advertised host", advertise)?;
            let advertise = advertise.trim();
            if advertise.is_empty() {
                return Err("UDP advertised host is required when UDP is enabled".into());
            }
            let advertise = validate_udp_advertise(advertise)?;
            (Some(range), Some(advertise))
        } else {
            (None, None)
        };

        (
            Some(domain),
            email,
            username,
            Some(cache_path),
            staging,
            udp_enabled,
            udp_port_range,
            udp_advertise,
        )
    } else {
        (None, None, None, None, false, false, None, None)
    };

    Ok(WizardForm {
        template,
        output_path,
        listen_host,
        listen_port,
        trusted_client,
        userlist_path: if matches!(
            template,
            WizardTemplate::LanUsername | WizardTemplate::PublicTls
        ) {
            userlist_path
        } else {
            None
        },
        log_file,
        public_domain,
        acme_email,
        initial_username,
        acme_cache_path,
        acme_staging,
        udp_enabled,
        udp_port_range,
        udp_advertise,
    })
}

fn required_text_field(
    fields: &HashMap<String, String>,
    key: &str,
    label: &str,
) -> Result<String, String> {
    let raw = fields.get(key).map_or("", String::as_str);
    validate_config_value(label, raw)?;
    let value = raw.trim();
    if value.is_empty() {
        return Err(format!("{label} is required"));
    }
    validate_config_value(label, value)?;
    Ok(value.to_string())
}

fn required_path_field(
    fields: &HashMap<String, String>,
    key: &str,
    label: &str,
    default: PathBuf,
) -> Result<PathBuf, String> {
    let value = match fields.get(key) {
        Some(raw) => {
            validate_config_value(label, raw)?;
            raw.trim().to_string()
        }
        None => default.display().to_string(),
    };
    if value.is_empty() {
        return Err(format!("{label} is required"));
    }
    validate_config_value(label, &value)?;
    Ok(PathBuf::from(value))
}

fn parse_checkbox(
    fields: &HashMap<String, String>,
    key: &str,
    default: bool,
) -> Result<bool, String> {
    match fields.get(key).map(String::as_str) {
        None => Ok(default),
        Some("on" | "true" | "1") => Ok(true),
        Some("off" | "false" | "0") => Ok(false),
        Some(_) => Err(format!("invalid value for {key}")),
    }
}

fn validate_public_domain(value: &str) -> Result<String, String> {
    if value.chars().any(char::is_whitespace) {
        return Err("public domain must be exactly one DNS hostname without whitespace".into());
    }
    let probe =
        format!("internal: 0.0.0.0 port = 443\ntls.acme.domains: {value}\ntls.acme.cache: cache\n");
    let parsed = Config::parse(&probe).map_err(|e| format!("public domain is invalid: {e}"))?;
    match parsed.tls {
        Some(TlsConfig::Acme(acme)) => match acme.domains.as_slice() {
            [domain] => Ok(domain.clone()),
            _ => Err("public domain must contain exactly one DNS hostname".into()),
        },
        _ => Err("public domain is not a valid ACME hostname".into()),
    }
}

fn validate_public_userlist_path(path: &Path) -> Result<(), String> {
    let text = path.display().to_string();
    let probe = format!("internal: 0.0.0.0 port = 443\nsocksmethod: username\nuserlist: {text}\n");
    let parsed = Config::parse(&probe)
        .map_err(|e| format!("public profile userlist path is invalid: {e}"))?;
    if parsed.userlist.as_deref() != Some(path) {
        return Err(
            "public profile userlist path changes when parsed as configuration; replace tabs or repeated whitespace with a single space"
                .into(),
        );
    }
    Ok(())
}

fn validate_public_acme_cache_path(path: &Path) -> Result<(), String> {
    let text = path.display().to_string();
    let probe = format!(
        "internal: 0.0.0.0 port = 443\ntls.acme.domains: proxy.example.com\ntls.acme.cache: {text}\n"
    );
    let parsed = Config::parse(&probe).map_err(|e| format!("ACME cache path is invalid: {e}"))?;
    let parsed_path = match &parsed.tls {
        Some(TlsConfig::Acme(acme)) => acme.cache_dir.as_path(),
        _ => return Err("ACME cache path did not produce an ACME configuration".into()),
    };
    if parsed_path != path {
        return Err(
            "ACME cache path changes when parsed as configuration; replace tabs or repeated whitespace with a single space"
                .into(),
        );
    }
    Ok(())
}

fn parse_udp_port_range(value: &str) -> Result<String, String> {
    validate_config_value("UDP relay port range", value)?;
    let Some((_, end)) = value.trim().split_once('-') else {
        return Err("UDP relay port range must use START-END".into());
    };
    if end.contains('-') {
        return Err("UDP relay port range must use START-END".into());
    }
    let range = value
        .parse::<PortRange>()
        .map_err(|e| format!("invalid UDP relay port range: {e}"))?;
    if range.min == 0 || range.max == 0 {
        return Err("UDP relay ports must be between 1 and 65535".into());
    }
    Ok(format!("{}-{}", range.min, range.max))
}

fn validate_udp_advertise(value: &str) -> Result<String, String> {
    validate_config_value("UDP advertised host", value)?;
    if value.chars().any(char::is_whitespace) {
        return Err("UDP advertised host must not contain whitespace".into());
    }
    let probe = format!("internal: 0.0.0.0 port = 443\nudp.advertise: {value}\n");
    let parsed =
        Config::parse(&probe).map_err(|e| format!("UDP advertised host is invalid: {e}"))?;
    match parsed.udp_advertise {
        Some(UdpAdvertise::Ip(ip)) => Ok(ip.to_string()),
        Some(UdpAdvertise::Host(host)) => Ok(host),
        Some(_) => Err("UDP advertised host uses an unsupported address form".into()),
        None => Err("UDP advertised host is required".into()),
    }
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
    } else if value.contains('\0') {
        Err(format!("{label} must not contain NUL"))
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

fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left.components().eq(right.components()),
    }
}

fn default_listen_host(template: WizardTemplate) -> &'static str {
    match template {
        WizardTemplate::LocalNoAuth => "127.0.0.1",
        WizardTemplate::LanUsername | WizardTemplate::PublicTls => "0.0.0.0",
    }
}

fn default_listen_port(template: WizardTemplate) -> &'static str {
    match template {
        WizardTemplate::LocalNoAuth | WizardTemplate::LanUsername => "1080",
        WizardTemplate::PublicTls => "443",
    }
}

fn default_trusted_client(template: WizardTemplate) -> &'static str {
    match template {
        WizardTemplate::LocalNoAuth => "127.0.0.1",
        WizardTemplate::LanUsername => "192.168.0.0/16",
        WizardTemplate::PublicTls => "0.0.0.0/0",
    }
}

#[cfg(windows)]
fn default_public_userlist_path() -> PathBuf {
    alighieri::platform::windows::service_manager::default_base_dir().join("users")
}

#[cfg(not(windows))]
fn default_public_userlist_path() -> PathBuf {
    PathBuf::from("/etc/alighieri/users")
}

#[cfg(windows)]
fn default_public_acme_cache_path() -> PathBuf {
    alighieri::platform::windows::service_manager::default_base_dir().join("acme")
}

#[cfg(not(windows))]
fn default_public_acme_cache_path() -> PathBuf {
    PathBuf::from("/var/lib/alighieri/acme")
}

#[cfg(windows)]
fn default_public_service_config_path() -> PathBuf {
    alighieri::platform::windows::service_manager::default_config_path()
}

#[cfg(not(windows))]
fn default_public_service_config_path() -> PathBuf {
    PathBuf::from("/etc/alighieri/alighieri.conf")
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
        WizardTemplate::PublicTls => {
            writeln!(text, "socksmethod: username").unwrap();
            if let Some(userlist) = &form.userlist_path {
                writeln!(text, "userlist: {}", userlist.display()).unwrap();
            }
            writeln!(text, "auth.cachettl: 300").unwrap();
            writeln!(text).unwrap();
            if let Some(domain) = &form.public_domain {
                writeln!(text, "tls.acme.domains: {domain}").unwrap();
            }
            if let Some(email) = &form.acme_email {
                writeln!(text, "tls.acme.email: {email}").unwrap();
            }
            if let Some(cache) = &form.acme_cache_path {
                writeln!(text, "tls.acme.cache: {}", cache.display()).unwrap();
            }
            if form.acme_staging {
                writeln!(text, "tls.acme.staging: on").unwrap();
            }
            if form.udp_enabled {
                if let Some(range) = &form.udp_port_range {
                    writeln!(text, "udp.portrange: {range}").unwrap();
                }
                if let Some(advertise) = &form.udp_advertise {
                    writeln!(text, "udp.advertise: {advertise}").unwrap();
                }
            }
            writeln!(text).unwrap();
            writeln!(text, "ratelimit.authfailurerate: 5/300").unwrap();
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
    let client_rule_name = if form.template == WizardTemplate::PublicTls {
        "public-authenticated-clients"
    } else {
        "trusted-clients"
    };
    writeln!(text, "client pass \"{client_rule_name}\" {{").unwrap();
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
        WizardTemplate::PublicTls => {
            writeln!(text, "socks pass \"public-internet\" {{").unwrap();
            writeln!(text, "    from: 0.0.0.0/0 to: 0.0.0.0/0").unwrap();
            if form.udp_enabled {
                writeln!(text, "    protocol: tcp udp").unwrap();
                writeln!(text, "    command: connect udpassociate").unwrap();
            } else {
                writeln!(text, "    protocol: tcp").unwrap();
                writeln!(text, "    command: connect").unwrap();
            }
            writeln!(text, "    method: username").unwrap();
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
    let public_acme = public_acme_profile(config);
    let template = if public_acme.is_some() {
        WizardTemplate::PublicTls
    } else if config.socks_methods.contains(&AuthKind::Username) {
        WizardTemplate::LanUsername
    } else {
        WizardTemplate::LocalNoAuth
    };
    let userlist_path = match template {
        WizardTemplate::LocalNoAuth => None,
        WizardTemplate::LanUsername => config
            .userlist
            .clone()
            .or_else(|| Some(PathBuf::from(default_userlist_path(output_path)))),
        WizardTemplate::PublicTls => config.userlist.clone(),
    };
    let log_file = if config.log_outputs.contains(&LogOutput::File) {
        config.log_file.clone()
    } else {
        None
    };
    let udp_enabled = template == WizardTemplate::PublicTls && config_allows_public_udp(config);
    let public_domain = public_acme.and_then(|acme| acme.domains.first().cloned());
    let acme_email = public_acme.and_then(|acme| acme.email.clone());
    let acme_cache_path = public_acme.map(|acme| acme.cache_dir.clone());
    let acme_staging = public_acme.is_some_and(|acme| acme.staging);
    let udp_port_range = if udp_enabled {
        Some(
            config
                .udp_port_range
                .map(|range| format!("{}-{}", range.min, range.max))
                .unwrap_or_else(|| PUBLIC_UDP_RANGE.to_string()),
        )
    } else {
        None
    };
    let udp_advertise = if udp_enabled {
        config
            .udp_advertise
            .as_ref()
            .and_then(udp_advertise_value)
            .or_else(|| public_domain.clone())
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
        public_domain,
        acme_email,
        initial_username: None,
        acme_cache_path,
        acme_staging,
        udp_enabled,
        udp_port_range,
        udp_advertise,
    }
}

/// Returns the modelled ACME settings only when the imported listener and auth
/// shape identify the public profile unambiguously. Richer public configs still
/// get loss warnings after extraction; LAN username configs cannot be
/// accidentally reclassified merely because they use username authentication.
fn public_acme_profile(config: &Config) -> Option<&alighieri::config::AcmeConfig> {
    if config.internal.ip() != IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        || config.internal.port() != 443
        || config.socks_methods.as_slice() != [AuthKind::Username]
        || !config
            .userlist
            .as_ref()
            .is_some_and(|path| path.is_absolute())
        || extract_trusted_client(config).as_deref() != Some("0.0.0.0/0")
    {
        return None;
    }
    match &config.tls {
        Some(TlsConfig::Acme(acme)) if acme.domains.len() == 1 && acme.cache_dir.is_absolute() => {
            Some(acme)
        }
        _ => None,
    }
}

fn config_allows_public_udp(config: &Config) -> bool {
    config.rules.udp_associate_reachable(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        49_152,
        AuthKind::Username,
    )
}

fn udp_advertise_value(value: &UdpAdvertise) -> Option<String> {
    match value {
        UdpAdvertise::Ip(ip) => Some(ip.to_string()),
        UdpAdvertise::Host(host) => Some(host.clone()),
        _ => None,
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
    if original.internal != regenerated.internal {
        lost.push("listener address (internal)".to_string());
    }
    if original.tls != regenerated.tls {
        lost.push("TLS listener (certificate files or unmodelled tls.acme.* settings)".to_string());
    }
    if original.metrics_listen != regenerated.metrics_listen
        || original.metrics_allow_public != regenerated.metrics_allow_public
    {
        lost.push("metrics endpoint (metrics.listen / metrics.allowpublic)".to_string());
    }
    if original.proxy_protocol != regenerated.proxy_protocol {
        lost.push("trusted PROXY-protocol upstreams (proxyprotocol)".to_string());
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
    if original.auth_command != regenerated.auth_command {
        lost.push("external authentication command (auth.command)".to_string());
    }
    if original.udp_port_range != regenerated.udp_port_range
        || original.udp_strict_reply != regenerated.udp_strict_reply
        || original.udp_advertise != regenerated.udp_advertise
    {
        lost.push(
            "UDP relay settings (udp.portrange / udp.strictreply / udp.advertise)".to_string(),
        );
    }
    if original.dns != regenerated.dns {
        lost.push(
            "DNS policy (dns.prefer / dns.tryall / dns.deny / dns.cachettl / dns.timeout)"
                .to_string(),
        );
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
    if original.shutdown_drain_timeout != regenerated.shutdown_drain_timeout {
        lost.push("shutdown drain timeout (shutdown.draintimeout)".to_string());
    }
    if original.log_format != regenerated.log_format
        || original.log_outputs != regenerated.log_outputs
        || original.log_file != regenerated.log_file
        || original.log_rotate_size != regenerated.log_rotate_size
        || original.log_rotate_keep != regenerated.log_rotate_keep
    {
        lost.push("logging (logformat / logoutput / logfile / logrotate.*)".to_string());
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
                // Per-rule `bandwidth:` is policy too. The wizard does not model
                // it, so it is dropped on regeneration; comparing it here lets the
                // import-loss check warn instead of silently discarding throttles.
                && x.bandwidth == y.bandwidth
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
    // Open the backup *source* first and no-follow (shared `open_no_follow`): a
    // symlinked config path could otherwise redirect the copy to an arbitrary
    // target file, streaming its contents into `.bak`. Back up only a regular
    // file. (The `.bak` *destination* is separately protected by the temp +
    // rename below.)
    let mut source = crate::open_no_follow(path)?;
    if !source.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to back up {}: not a regular file", path.display()),
        ));
    }
    // Stream into a fresh `create_new` temp file — which cannot follow a symlink —
    // and atomically rename it over `.bak`. `rename` replaces whatever is at the
    // path (a regular file, or a symlink an attacker planted) rather than following
    // it, so the backup write is never redirected. This mirrors the userlist
    // backup hardening.
    let (temp_path, mut file) = create_config_temp(path, true)?;
    let write = (|| -> std::io::Result<()> {
        std::io::copy(&mut source, &mut file)?;
        file.sync_all()
    })();
    drop(file);
    if let Err(e) = write.and_then(|()| replace_backup(&temp_path, &backup)) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    Ok(backup)
}

// Unix `rename` replaces a regular file, a symlink, or a read-only entry (the
// directory permission governs, not the file's), so it never follows a symlink
// at the backup path and needs no read-only handling.
#[cfg(not(windows))]
fn replace_backup(temp: &Path, backup: &Path) -> std::io::Result<()> {
    std::fs::rename(temp, backup)
}

// Windows `rename` (MoveFileEx with REPLACE_EXISTING) fails on a read-only
// destination — a read-only config propagates the attribute to its backup — so
// clear the attribute on a regular-file backup and retry. A symlink destination
// is replaced by the rename, not followed.
#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn replace_backup(temp: &Path, backup: &Path) -> std::io::Result<()> {
    match std::fs::rename(temp, backup) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            if let Ok(metadata) = std::fs::symlink_metadata(backup) {
                if metadata.file_type().is_file() {
                    let mut permissions = metadata.permissions();
                    permissions.set_readonly(false);
                    let _ = std::fs::set_permissions(backup, permissions);
                }
            }
            std::fs::rename(temp, backup)
        }
        Err(e) => Err(e),
    }
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

/// Quotes an arbitrary argument for the shell used by the platform's
/// completion-page examples. Unlike `shell_quote_path`, this also handles quote
/// characters because usernames may legally contain shell metacharacters.
fn shell_quote_command_argument(value: &str) -> String {
    #[cfg(windows)]
    let is_safe = !value.is_empty()
        && !value.starts_with('-')
        && value
            .chars()
            // Keep bare PowerShell arguments deliberately conservative. In
            // particular, `@name` is splatting and a comma constructs an
            // array, so values containing either must be quoted.
            .all(|ch| ch.is_ascii_alphanumeric() || r"_:./\-".contains(ch));
    #[cfg(not(windows))]
    let is_safe = !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "_@%+=:,./-".contains(ch));

    if is_safe {
        value.to_string()
    } else if cfg!(windows) {
        // PowerShell single-quoted strings escape an embedded quote by doubling
        // it; no interpolation or command substitution occurs inside them.
        format!("'{}'", value.replace('\'', "''"))
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
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
    let listen_port = prefill.map_or_else(
        || default_listen_port(template).parse::<u16>().unwrap_or(1080),
        |p| p.form.listen_port,
    );
    let trusted_client = prefill.map_or_else(
        || default_trusted_client(template).to_string(),
        |p| p.form.trusted_client.clone(),
    );
    let output_path = prefill.map_or_else(
        || default_output_path.to_path_buf(),
        |p| p.form.output_path.clone(),
    );
    let standard_userlist_default = default_userlist_path(&output_path);
    let public_userlist_default = default_public_userlist_path().display().to_string();
    let userlist_value = prefill
        .and_then(|p| p.form.userlist_path.as_ref())
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| {
            if template == WizardTemplate::PublicTls {
                public_userlist_default.clone()
            } else {
                standard_userlist_default.clone()
            }
        });
    let logfile_value = prefill
        .and_then(|p| p.form.log_file.as_ref())
        .map(|path| path.display().to_string())
        .unwrap_or_default();

    let output = html_escape(&output_path.display().to_string());
    let userlist = html_escape(&userlist_value);
    let standard_userlist = html_escape(&standard_userlist_default);
    let public_userlist = html_escape(&public_userlist_default);
    let logfile = html_escape(&logfile_value);
    let listen_host_attr = html_escape(&listen_host);
    let trusted_attr = html_escape(&trusted_client);
    let public_domain_value = prefill
        .and_then(|p| p.form.public_domain.as_deref())
        .unwrap_or("");
    let acme_email_value = prefill
        .and_then(|p| p.form.acme_email.as_deref())
        .unwrap_or("");
    let initial_username_value = prefill
        .and_then(|p| p.form.initial_username.as_deref())
        .unwrap_or("");
    let acme_cache_value = prefill
        .and_then(|p| p.form.acme_cache_path.as_ref())
        .map_or_else(
            || default_public_acme_cache_path().display().to_string(),
            |path| path.display().to_string(),
        );
    // Local/LAN imports carry `udp_enabled = false` because UDP is not a field
    // of those templates. Do not let that implementation detail change the
    // public profile's default when the operator switches templates.
    let udp_enabled = prefill
        .filter(|p| p.form.template == WizardTemplate::PublicTls)
        .is_none_or(|p| p.form.udp_enabled);
    let udp_range_value = prefill
        .and_then(|p| p.form.udp_port_range.as_deref())
        .unwrap_or(PUBLIC_UDP_RANGE);
    let udp_advertise_value = prefill
        .and_then(|p| p.form.udp_advertise.as_deref())
        .unwrap_or(public_domain_value);
    let acme_staging = prefill.is_some_and(|p| p.form.acme_staging);
    let public_domain = html_escape(public_domain_value);
    let acme_email = html_escape(acme_email_value);
    let initial_username = html_escape(initial_username_value);
    let acme_cache = html_escape(&acme_cache_value);
    let udp_range = html_escape(udp_range_value);
    let udp_advertise = html_escape(udp_advertise_value);
    let (local_checked, lan_checked, public_checked) = match template {
        WizardTemplate::LocalNoAuth => (" checked", "", ""),
        WizardTemplate::LanUsername => ("", " checked", ""),
        WizardTemplate::PublicTls => ("", "", " checked"),
    };
    let userlist_required = if template == WizardTemplate::LocalNoAuth {
        ""
    } else {
        " required"
    };
    let public_hidden = if template == WizardTemplate::PublicTls {
        ""
    } else {
        " hidden"
    };
    let public_disabled = if template == WizardTemplate::PublicTls {
        ""
    } else {
        " disabled"
    };
    let public_required = if template == WizardTemplate::PublicTls {
        " required"
    } else {
        ""
    };
    let public_readonly = if template == WizardTemplate::PublicTls {
        " readonly"
    } else {
        ""
    };
    let udp_hidden = if template == WizardTemplate::PublicTls && udp_enabled {
        ""
    } else {
        " hidden"
    };
    let udp_disabled = if template == WizardTemplate::PublicTls && udp_enabled {
        ""
    } else {
        " disabled"
    };
    let udp_required = if template == WizardTemplate::PublicTls && udp_enabled {
        " required"
    } else {
        ""
    };
    let staging_checked = if acme_staging { " checked" } else { "" };
    let udp_checked = if udp_enabled { " checked" } else { "" };
    let active_template = template.as_form_value();
    let banner = render_import_banner(prefill);

    html_page(
        "Alighieri Config Wizard",
        &format!(
            r##"<main>
<h1>Alighieri Config Wizard</h1>{banner}
<form method="post" action="{action}">
<section>
<h2>Template</h2>
<label><input type="radio" name="template" value="local-no-auth"{local_checked}> Local apps only, no authentication<span class="help">Loopback-only listener for programs on this machine.</span></label>
<label><input type="radio" name="template" value="lan-username"{lan_checked}> LAN clients with username/password<span class="help">Authenticated SOCKS5 for a trusted private network.</span></label>
<label><input type="radio" name="template" value="public-tls"{public_checked}> Public SOCKS5-over-TLS (ProxiFyre)<span class="help">Authenticated public SOCKS5 protected by standard TLS, for ProxiFyre or another TLS-capable SOCKS5 client.</span></label>
</section>
<section>
<h2>Listener</h2>
<p id="public-listener-note" class="help"{public_hidden}>The public profile listens on <code>0.0.0.0:443</code>. TCP 443 is fixed because ACME TLS-ALPN-01 validates on that port.</p>
<label>Listen address <input name="listen_host" value="{listen_host_attr}" required placeholder="127.0.0.1 or 0.0.0.0" autocomplete="off"{public_readonly}></label>
<label>Port <input name="listen_port" type="number" min="1" max="65535" value="{listen_port}" required{public_readonly}></label>
<label>Trusted client range <input name="trusted_client" value="{trusted_attr}" required placeholder="127.0.0.1 or 192.168.0.0/16" autocomplete="off"{public_readonly}></label>
</section>
<section>
<h2>Files</h2>
<label>Config output <input name="output" value="{output}" required placeholder="alighieri.conf" autocomplete="off"></label>
<label>Userlist path <input name="userlist" value="{userlist}" data-standard-default="{standard_userlist}" data-public-default="{public_userlist}" placeholder="required for username profiles" autocomplete="off"{userlist_required}><span class="help">The public service profile requires an absolute path so user creation and the service use the same file.</span></label>
<label>Log file (optional) <input name="logfile" value="{logfile}" placeholder="absolute path recommended; empty = stdout / journald" autocomplete="off"></label>
</section>
<section id="public-profile"{public_hidden}>
<h2>Public TLS endpoint</h2>
<label>Public domain <input class="public-only" name="public_domain" value="{public_domain}" placeholder="proxy.example.com" autocomplete="off"{public_required}{public_disabled}><span class="help">Exactly one DNS hostname with an A record for this VPS. This profile is IPv4-only; publish AAAA only when IPv6 TCP 443 is forwarded to Alighieri. Do not include a scheme, path, wildcard, or IP address.</span></label>
<label>ACME account email (optional) <input class="public-only" name="acme_email" value="{acme_email}" placeholder="admin@example.com" autocomplete="off"{public_disabled}></label>
<label>Initial username (optional) <input class="public-only" name="initial_username" value="{initial_username}" placeholder="proxyuser" autocomplete="off"{public_disabled}><span class="help">Used only in the completion-page command. The wizard never asks for or stores a password.</span></label>
<label>ACME cache path <input class="public-only" name="acme_cache" value="{acme_cache}" autocomplete="off"{public_required}{public_disabled}><span class="help">Absolute path for persisted certificates and account state. The default is writable by the supported service installation.</span></label>
<input class="public-only" type="hidden" name="acme_staging" value="off"{public_disabled}>
<label class="checkbox"><input class="public-only" type="checkbox" name="acme_staging" value="on"{staging_checked}{public_disabled}> Use ACME staging<span class="help">Useful for issuance testing, but staging certificates are not trusted by normal clients.</span></label>
<input class="public-only" type="hidden" name="udp_enabled" value="off"{public_disabled}>
<label class="checkbox"><input id="udp-enabled" class="public-only" type="checkbox" name="udp_enabled" value="on"{udp_checked}{public_disabled}> Enable UDP ASSOCIATE</label>
<div id="udp-fields"{udp_hidden}>
<label>UDP relay port range <input class="public-udp-only" name="udp_port_range" value="{udp_range}" placeholder="40000-40099" autocomplete="off"{udp_required}{udp_disabled}><span class="help">Allow this inbound UDP range in the VPS firewall and cloud security group.</span></label>
<label>UDP advertised host <input class="public-udp-only" name="udp_advertise" value="{udp_advertise}" placeholder="proxy.example.com" autocomplete="off"{udp_required}{udp_disabled}><span class="help">The address clients use for the relay when it differs from the local listener address.</span></label>
<p class="notice"><strong>UDP transport:</strong> the SOCKS5 control connection and authentication use TLS. Relay datagrams travel separately and are not encapsulated in that TLS stream. QUIC, voice, and game traffic may encrypt their own payloads, but Alighieri TLS does not add TLS encryption to these UDP datagrams.</p>
</div>
</section>
<button type="submit">Generate config</button>
</form>
<script>
const presets = {{
  "local-no-auth": {{ listen: "127.0.0.1", port: "1080", trusted: "127.0.0.1" }},
  "lan-username": {{ listen: "0.0.0.0", port: "1080", trusted: "192.168.0.0/16" }},
  "public-tls": {{ listen: "0.0.0.0", port: "443", trusted: "0.0.0.0/0" }}
}};
const listen = document.querySelector("[name=listen_host]");
const port = document.querySelector("[name=listen_port]");
const trusted = document.querySelector("[name=trusted_client]");
const userlist = document.querySelector("[name=userlist]");
const publicSection = document.querySelector("#public-profile");
const publicListenerNote = document.querySelector("#public-listener-note");
const udpEnabled = document.querySelector("#udp-enabled");
const udpFields = document.querySelector("#udp-fields");
const domain = document.querySelector("[name=public_domain]");
const advertise = document.querySelector("[name=udp_advertise]");
const cache = document.querySelector("[name=acme_cache]");
const range = document.querySelector("[name=udp_port_range]");
const states = {{}};
let activeTemplate = "{active_template}";
let advertiseWasEdited = advertise.value !== domain.value;

function templateDefaults(name) {{
  const value = Object.assign({{}}, presets[name]);
  value.userlist = name === "public-tls" ? userlist.dataset.publicDefault : userlist.dataset.standardDefault;
  return value;
}}

function readTemplateState() {{
  return {{ listen: listen.value, port: port.value, trusted: trusted.value, userlist: userlist.value }};
}}

function writeTemplateState(value) {{
  listen.value = value.listen;
  port.value = value.port;
  trusted.value = value.trusted;
  userlist.value = value.userlist;
}}

function updateVisibility() {{
  const isPublic = activeTemplate === "public-tls";
  publicSection.hidden = !isPublic;
  publicListenerNote.hidden = !isPublic;
  document.querySelectorAll(".public-only").forEach((control) => control.disabled = !isPublic);
  domain.required = isPublic;
  cache.required = isPublic;
  userlist.required = activeTemplate !== "local-no-auth";
  listen.readOnly = isPublic;
  port.readOnly = isPublic;
  trusted.readOnly = isPublic;
  const hasUdp = isPublic && udpEnabled.checked;
  udpFields.hidden = !hasUdp;
  document.querySelectorAll(".public-udp-only").forEach((control) => control.disabled = !hasUdp);
  range.required = hasUdp;
  advertise.required = hasUdp;
}}

document.querySelectorAll("[name=template]").forEach((radio) => {{
  radio.addEventListener("change", () => {{
    states[activeTemplate] = readTemplateState();
    activeTemplate = radio.value;
    if (!states[activeTemplate]) states[activeTemplate] = templateDefaults(activeTemplate);
    writeTemplateState(states[activeTemplate]);
    updateVisibility();
  }});
}});
udpEnabled.addEventListener("change", updateVisibility);
advertise.addEventListener("input", () => advertiseWasEdited = true);
domain.addEventListener("input", () => {{
  if (!advertiseWasEdited) advertise.value = domain.value;
}});
states[activeTemplate] = readTemplateState();
updateVisibility();
</script>
</main>"##
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
    if form.template == WizardTemplate::PublicTls {
        return render_public_success(report, form);
    }
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
        (WizardTemplate::PublicTls, _) => String::new(),
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

fn windows_atomic_config_install(source_arg: &str, destination_arg: &str) -> String {
    let mut command = format!("$source = {source_arg}\n$destination = {destination_arg}");
    command.push_str(
        r#"
$backup = "$destination.bak"
$staged = Join-Path (Split-Path -Parent $destination) ([IO.Path]::GetRandomFileName())
try {
    Copy-Item -LiteralPath $source -Destination $staged -ErrorAction Stop
    $checker = (Get-Command alighieri -CommandType Application -ErrorAction Stop).Source
    & $checker --check --config $staged
    if (-not $? -or $LASTEXITCODE -ne 0) {
        throw "staged service configuration failed validation"
    }
    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        if (Test-Path -LiteralPath $backup) {
            if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) {
                throw "service config backup path is not a regular file: $backup"
            }
        }
        [IO.File]::Replace($staged, $destination, $backup, $true)
    } elseif (Test-Path -LiteralPath $destination) {
        throw "service config destination is not a regular file: $destination"
    } else {
        [IO.File]::Move($staged, $destination)
    }
} finally {
    if (Test-Path -LiteralPath $staged) {
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    }
}"#,
    );
    command
}

fn unix_atomic_config_install(source_arg: &str, destination_arg: &str) -> String {
    let script = r#"sudo sh -eu -c '
source_path=$1
destination_path=$2
staged=$(mktemp "${destination_path}.tmp.XXXXXX")
backup_staged=
cleanup() {
    [ -z "${staged:-}" ] || rm -f -- "$staged"
    [ -z "${backup_staged:-}" ] || rm -f -- "$backup_staged"
}
trap cleanup EXIT HUP INT TERM
install -m 640 -o root -g alighieri -- "$source_path" "$staged"
alighieri --check --config "$staged"
if [ -e "$destination_path" ] || [ -L "$destination_path" ]; then
    if [ ! -f "$destination_path" ] || [ -L "$destination_path" ]; then
        echo "refusing to replace non-regular service config: $destination_path" >&2
        exit 1
    fi
    backup_staged=$(mktemp "${destination_path}.bak.tmp.XXXXXX")
    cp -p -- "$destination_path" "$backup_staged"
    mv -fT -- "$backup_staged" "$destination_path.bak"
    backup_staged=
fi
mv -fT -- "$staged" "$destination_path"
staged=
' sh"#;
    format!("{script} {source_arg} {destination_arg}")
}

fn render_public_success(report: &WriteReport, form: &WizardForm) -> String {
    let output_text = report.output_path.display().to_string();
    let output = html_escape(&output_text);
    // Completion commands may be pasted into a newly elevated shell whose
    // working directory differs from the wizard process. Resolve the file that
    // was just written now so those commands always reference that exact file.
    let command_output_path =
        std::path::absolute(&report.output_path).unwrap_or_else(|_| report.output_path.clone());
    let command_output_text = command_output_path.display().to_string();
    let backup = report.backup_path.as_ref().map(|backup| {
        format!(
            "<p>Previous configuration backed up to <code>{}</code>.</p>",
            html_escape(&backup.display().to_string())
        )
    });
    let domain_text = form.public_domain.as_deref().unwrap_or("");
    let domain = html_escape(domain_text);
    let userlist_path = form
        .userlist_path
        .clone()
        .unwrap_or_else(default_public_userlist_path);
    let userlist_text = userlist_path.display().to_string();
    let userlist = html_escape(&userlist_text);
    let username_text = form.initial_username.as_deref().unwrap_or("USERNAME");
    let proxifyre_username = form
        .initial_username
        .as_deref()
        .map_or_else(String::new, |value| {
            format!(
                "<dt>Username</dt><dd><code>{}</code></dd>\n",
                html_escape(value)
            )
        });
    let proxifyre_config = format!(
        r#"{{
  "logLevel": "Error",
  "proxies": [
    {{
      "appNames": ["chrome"],
      "socks5ProxyEndpoint": "{}:443",
      "username": "{}",
      "password": "REPLACE_WITH_USER_ADD_PASSWORD",
      "socks5Transport": "TLS",
      "tlsServerName": "{}",
      "tlsAllowInvalidCertificate": false,
      "supportedProtocols": [{}],
      "supportedAddressFamilies": ["IPv4"]
    }}
  ],
  "excludes": []
}}"#,
        json_escape(domain_text),
        json_escape(username_text),
        json_escape(domain_text),
        if form.udp_enabled {
            r#""TCP", "UDP""#
        } else {
            r#""TCP""#
        }
    );
    let proxifyre_config = html_escape(&proxifyre_config);
    let add_command = format!(
        "{}alighieri user add {} --userlist {}",
        if cfg!(windows) { "" } else { "sudo " },
        shell_quote_command_argument(username_text),
        shell_quote_command_argument(&userlist_text)
    );
    let add_command = html_escape(&add_command);

    let ownership_commands = if cfg!(windows) {
        String::new()
    } else {
        let path = shell_quote_command_argument(&userlist_text);
        html_escape(&format!(
            "sudo chown root:alighieri -- {path}\nsudo chmod 640 -- {path}"
        ))
    };
    let ownership_guidance = if ownership_commands.is_empty() {
        String::new()
    } else {
        format!(
            "<p>Make the new file readable by the hardened systemd service:</p><pre>{ownership_commands}</pre>"
        )
    };

    let output_arg = shell_quote_command_argument(&command_output_text);
    let service_config_text = default_public_service_config_path().display().to_string();
    let service_config_arg = shell_quote_command_argument(&service_config_text);
    let service_preparation = if cfg!(windows) {
        let copy_config = if paths_refer_to_same_file(
            &command_output_path,
            Path::new(&service_config_text),
        ) {
            format!(
                "<p>The generated configuration is already at the canonical service path <code>{}</code>.</p>",
                html_escape(&service_config_text)
            )
        } else {
            let copy_command = html_escape(&windows_atomic_config_install(
                &output_arg,
                &service_config_arg,
            ));
            format!(
                "<p>After either preparation branch, atomically install the generated file into the hardened service-data directory. If a service configuration already exists, PowerShell preserves it as <code>{}.bak</code>:</p><pre>{copy_command}</pre>",
                html_escape(&service_config_text)
            )
        };
        let fresh_commands = html_escape(&format!(
            "alighieri --check --config {output_arg}\nalighieri service install --config {output_arg}\nalighieri service uninstall"
        ));
        format!(
            "<section class=\"notice\"><h2>Prepare the Windows service data directory</h2>\
             <p>Run these commands in an elevated PowerShell. On a fresh installation, the temporary install below atomically creates and hardens the ProgramData directory; it does not start the service:</p>\
             <pre>{fresh_commands}</pre>\
             <p>If Alighieri is already installed, its data directory is already hardened. Unregister that service instead (the command stops it when needed):</p>\
             <pre>alighieri service uninstall</pre>\
             {copy_config}</section>"
        )
    } else {
        "<section class=\"notice\"><strong>Fresh Linux VPS:</strong> run <code>sudo ./scripts/alighieri.sh install --no-start</code> before the steps below. It creates the <code>alighieri</code> account, service directories, binary, and unit without enabling or starting the service. This is safe even when the wizard wrote directly to <code>/etc/alighieri/alighieri.conf</code>. Create the userlist next, then run the normal installer command shown below to enable and start Alighieri.<p>Release archives do not bundle the lifecycle script. Outside a source checkout, download the standalone helper below, use <code>./alighieri.sh</code> wherever the commands show <code>./scripts/alighieri.sh</code>, and pass <code>--binary /path/to/extracted/alighieri</code> when installing a prebuilt binary.</p><pre>curl -fsSLo alighieri.sh https://raw.githubusercontent.com/wiresock/alighieri/main/scripts/alighieri.sh\nchmod +x alighieri.sh</pre></section>".to_string()
    };
    let service_commands = if cfg!(windows) {
        html_escape(&format!(
            "alighieri --check --config {service_config_arg}\nalighieri service install --config {service_config_arg}\nalighieri service start\nalighieri service status\nwevtutil qe Application /q:\"*[System[Provider[@Name='Alighieri']]]\" /f:text /c:20"
        ))
    } else {
        let install_config = if paths_refer_to_same_file(
            &command_output_path,
            Path::new("/etc/alighieri/alighieri.conf"),
        ) {
            String::new()
        } else {
            format!(
                "{}\n",
                unix_atomic_config_install(&output_arg, &service_config_arg)
            )
        };
        html_escape(&format!(
            "sudo alighieri --check --config {output_arg}\n{install_config}sudo ./scripts/alighieri.sh install\nsudo systemctl status alighieri\nsudo journalctl -u alighieri -f"
        ))
    };
    let service_note = if cfg!(windows) {
        "The final install records the canonical ProgramData configuration path and recursively hardens files under the Alighieri service-data directory before the service can start. If you selected a userlist, ACME cache, or logfile outside that directory, explicitly grant LocalService the required access and protect the files from untrusted local users."
    } else {
        "The supported service reads <code>/etc/alighieri/alighieri.conf</code>; when the wizard wrote another path, the command above installs that exact generated file there. Rerunning the installer picks up the port-443 capability and ACME state directory. The hardened unit can write the default state and log directories; custom paths outside them require a corresponding unit permission change."
    };

    let udp_firewall = if form.udp_enabled {
        let range = html_escape(form.udp_port_range.as_deref().unwrap_or(PUBLIC_UDP_RANGE));
        format!("<li>Allow inbound UDP <code>{range}</code> in the host firewall and cloud security group.</li>")
    } else {
        String::new()
    };
    let udp_value = if form.udp_enabled {
        "enabled"
    } else {
        "disabled"
    };
    let staging_warning = if form.acme_staging {
        "<section class=\"warning\"><strong>ACME staging is enabled.</strong> The issued certificate will not be trusted by normal clients. Switch staging off and obtain a production certificate before normal use.</section>"
    } else {
        ""
    };
    let proxifyre_staging_note = if form.acme_staging {
        "<p><strong>Staging note:</strong> the validation-safe ProxiFyre configuration below will connect only after you switch to a production certificate. Do not disable certificate validation to make staging permanent.</p>"
    } else {
        ""
    };

    html_page(
        "Public TLS Configuration Saved",
        &format!(
            r#"<main><h1>Public TLS Configuration Saved</h1>
<section>
<h2>Configuration result</h2>
<p>Wrote <code>{output}</code>.</p>{backup}
<p>The generated file passed the real Alighieri configuration parser before it was written.</p>
</section>
{staging_warning}
{service_preparation}
<section>
<h2>Create the authenticated user</h2>
<p>This endpoint requires username/password authentication from <code>{userlist}</code>. Run this before installing or restarting the service:</p>
<pre>{add_command}</pre>
<p>The command prompts for the password securely and stores its Argon2id hash. No password was requested or generated by this wizard.</p>
{ownership_guidance}
<p>Do not start the public profile until the userlist exists and is readable by the service account.</p>
</section>
<section>
<h2>VPS prerequisites</h2>
<ul>
<li><code>{domain}</code> has a DNS A record for this VPS. Because this profile listens on IPv4, publish an AAAA record only when IPv6 TCP 443 is forwarded to this listener.</li>
<li>Inbound TCP 443 is allowed, and no other service occupies TCP 443.</li>
<li>Outbound TCP 443 is allowed for ACME communication.</li>
{udp_firewall}
<li>The userlist above exists and is service-readable before Alighieri starts or restarts.</li>
</ul>
<p>The wizard does not change DNS records or firewall rules.</p>
</section>
<section>
<h2>Alighieri service commands</h2>
<pre>{service_commands}</pre>
<p>{service_note}</p>
</section>
<section>
<h2>ProxiFyre settings</h2>
<dl>
<dt>Proxy type</dt><dd>SOCKS5</dd>
<dt>Server</dt><dd><code>{domain}</code></dd>
<dt>Port</dt><dd>443</dd>
<dt>TLS</dt><dd>enabled</dd>
{proxifyre_username}<dt>Password</dt><dd>the password entered through <code>alighieri user add</code></dd>
<dt>UDP</dt><dd>{udp_value}</dd>
</dl>
<p>Use ProxiFyre 2.4.0 or later. Save a configuration like this as <code>app-config.json</code> next to <code>ProxiFyre.exe</code>, replacing <code>appNames</code> and the password placeholder. The explicit TLS transport is required because ProxiFyre otherwise defaults to plaintext SOCKS5:</p>
<pre>{proxifyre_config}</pre>
{proxifyre_staging_note}
<p>Normal certificate and hostname validation remains enabled. This IPv4-only destination-family setting matches the generated <code>to: 0.0.0.0/0</code> access policy; the upstream endpoint separately uses the domain's A record.</p>
<p>This endpoint is an application proxy, not a full IP-level VPN.</p>
</section>
</main>"#,
            backup = backup.unwrap_or_default(),
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
.warning {{ border-color: #b42318; background: #fef3f2; }}
label {{ display: block; margin: 10px 0; font-size: 14px; }}
label.checkbox {{ display: flex; gap: 8px; align-items: flex-start; flex-wrap: wrap; }}
.help {{ display: block; margin-top: 4px; color: #59636f; font-size: 13px; line-height: 1.4; }}
.notice {{ padding: 10px 12px; border-left: 3px solid #1f6feb; background: #f1f6fd; font-size: 13px; line-height: 1.45; }}
input[type="text"], input[type="number"], input:not([type]) {{ box-sizing: border-box; display: block; width: 100%; margin-top: 6px; padding: 9px 10px; border: 1px solid #b8c0cc; border-radius: 6px; font: inherit; }}
button {{ margin-top: 12px; padding: 10px 14px; border: 0; border-radius: 6px; background: #1f6feb; color: #fff; font: inherit; cursor: pointer; }}
code, pre {{ background: #eef1f5; border-radius: 6px; }}
code {{ padding: 2px 4px; }}
pre {{ overflow-x: auto; padding: 14px; }}
dt {{ font-weight: 600; float: left; clear: left; width: 120px; }}
dd {{ margin: 0 0 8px 130px; }}
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

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => write!(escaped, "\\u{:04x}", ch as u32).unwrap(),
            ch => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use alighieri::config::{Command as SocksCommand, Protocol};

    fn public_tls_fields() -> HashMap<String, String> {
        HashMap::from([
            ("template".into(), "public-tls".into()),
            ("public_domain".into(), PUBLIC_DOMAIN_EXAMPLE.into()),
        ])
    }

    fn public_tls_form() -> WizardForm {
        wizard_form_from_fields(&public_tls_fields(), Path::new("alighieri.conf")).unwrap()
    }

    fn input_tag<'a>(html: &'a str, name: &str) -> &'a str {
        let marker = format!(r#"name="{name}""#);
        let marker_start = html
            .find(&marker)
            .unwrap_or_else(|| panic!("missing {marker}"));
        let tag_start = html[..marker_start]
            .rfind('<')
            .unwrap_or_else(|| panic!("missing opening tag for {marker}"));
        let tag_end = html[marker_start..]
            .find('>')
            .map(|offset| marker_start + offset + 1)
            .unwrap_or_else(|| panic!("missing closing tag for {marker}"));
        &html[tag_start..tag_end]
    }

    fn write_report() -> WriteReport {
        WriteReport {
            output_path: PathBuf::from("/etc/alighieri/alighieri.conf"),
            backup_path: Some(PathBuf::from("/etc/alighieri/alighieri.conf.bak")),
        }
    }

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
        let text = render_config(&form);
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.internal, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(config.socks_methods.as_slice(), [AuthKind::None]);
        assert!(config.tls.is_none());
        assert!(text.contains("socksmethod: none"));
        assert!(!text.contains("tls.acme."));
        assert!(!text.contains("ratelimit.authfailurerate"));
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
        let text = render_config(&form);
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.internal, "0.0.0.0:1080".parse().unwrap());
        assert_eq!(config.socks_methods.as_slice(), [AuthKind::Username]);
        assert_eq!(config.userlist.as_deref(), Some(Path::new("users")));
        assert!(config.tls.is_none());
        assert!(text.contains("socksmethod: username"));
        assert!(text.contains("userlist: users"));
        assert!(!text.contains("tls.acme."));
        assert!(!text.contains("udp.portrange"));
    }

    #[test]
    fn public_tls_template_identifier_parses() {
        assert_eq!(
            WizardTemplate::from_form("public-tls").unwrap(),
            WizardTemplate::PublicTls
        );
        assert_eq!(WizardTemplate::PublicTls.as_form_value(), "public-tls");
    }

    #[test]
    fn public_tls_default_form_generates_secure_valid_config() {
        let form = public_tls_form();
        assert_eq!(form.template, WizardTemplate::PublicTls);
        assert_eq!(form.listen_host, "0.0.0.0");
        assert_eq!(form.listen_port, 443);
        assert_eq!(form.trusted_client, "0.0.0.0/0");
        assert_eq!(form.userlist_path, Some(default_public_userlist_path()));
        assert_eq!(form.acme_cache_path, Some(default_public_acme_cache_path()));
        assert!(form.udp_enabled);
        assert_eq!(form.udp_port_range.as_deref(), Some(PUBLIC_UDP_RANGE));
        assert_eq!(form.udp_advertise.as_deref(), Some(PUBLIC_DOMAIN_EXAMPLE));

        let text = render_config(&form);
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.internal, "0.0.0.0:443".parse().unwrap());
        assert_eq!(config.socks_methods.as_slice(), [AuthKind::Username]);
        assert!(!config.socks_methods.contains(&AuthKind::None));
        assert_eq!(
            config.udp_port_range,
            Some(PUBLIC_UDP_RANGE.parse::<PortRange>().unwrap())
        );
        assert!(matches!(
            config.udp_advertise.as_ref(),
            Some(UdpAdvertise::Host(host)) if host == PUBLIC_DOMAIN_EXAMPLE
        ));
        assert!(text.contains("socksmethod: username"));
        assert!(!text.contains("socksmethod: none"));
        assert_eq!(config.auth_cache_ttl, Some(Duration::from_secs(300)));

        let Some(TlsConfig::Acme(acme)) = config.tls.as_ref() else {
            panic!("public profile did not generate ACME TLS");
        };
        assert_eq!(acme.domains, [PUBLIC_DOMAIN_EXAMPLE]);
        assert_eq!(acme.email, None);
        assert_eq!(acme.cache_dir, default_public_acme_cache_path());
        assert!(!acme.staging);

        let auth_failures = config
            .rate_limits
            .auth_failure_rate
            .as_ref()
            .expect("public profile must throttle authentication failures");
        assert_eq!(auth_failures.limit, 5);
        assert_eq!(auth_failures.window, Duration::from_secs(300));
        assert_eq!(
            config.dns.deny,
            [
                alighieri::config::DnsDenyCategory::Private,
                alighieri::config::DnsDenyCategory::LinkLocal,
                alighieri::config::DnsDenyCategory::Loopback,
                alighieri::config::DnsDenyCategory::Reserved,
            ]
        );

        let public_rule = config
            .rules
            .rules
            .iter()
            .find(|rule| rule.name.as_deref() == Some("public-internet"))
            .expect("missing public SOCKS rule");
        assert_eq!(public_rule.verdict, Verdict::Pass);
        assert_eq!(public_rule.scope, Scope::Socks);
        assert_eq!(public_rule.methods.as_slice(), [AuthKind::Username]);
        assert_eq!(
            public_rule.commands.as_slice(),
            [SocksCommand::Connect, SocksCommand::UdpAssociate]
        );
        assert_eq!(
            public_rule.protocols.as_slice(),
            [Protocol::Tcp, Protocol::Udp]
        );
    }

    #[test]
    fn public_tls_optional_email_and_staging_are_emitted_only_when_selected() {
        let mut empty = public_tls_fields();
        empty.insert("acme_email".into(), String::new());
        empty.insert("acme_staging".into(), "off".into());
        let empty_text =
            render_config(&wizard_form_from_fields(&empty, Path::new("alighieri.conf")).unwrap());
        assert!(!empty_text.contains("tls.acme.email:"));
        assert!(!empty_text.contains("tls.acme.staging:"));

        let mut selected = public_tls_fields();
        selected.insert("acme_email".into(), "admin@example.com".into());
        selected.insert("acme_staging".into(), "on".into());
        let selected_text = render_config(
            &wizard_form_from_fields(&selected, Path::new("alighieri.conf")).unwrap(),
        );
        let selected_config = Config::parse(&selected_text).unwrap();
        let Some(TlsConfig::Acme(acme)) = selected_config.tls else {
            panic!("public profile did not generate ACME TLS");
        };
        assert_eq!(acme.email.as_deref(), Some("admin@example.com"));
        assert!(acme.staging);
        assert!(selected_text.contains("tls.acme.email: admin@example.com"));
        assert!(selected_text.contains("tls.acme.staging: on"));
    }

    #[test]
    fn public_tls_requires_one_acme_compatible_domain() {
        let mut missing = public_tls_fields();
        missing.remove("public_domain");
        let err = wizard_form_from_fields(&missing, Path::new("alighieri.conf")).unwrap_err();
        assert!(err.contains("public domain is required"), "{err}");

        for bad in [
            "",
            " proxy.example.com",
            "proxy.example.com ",
            "https://proxy.example.com",
            "proxy.example.com/path",
            "*.example.com",
            "203.0.113.10",
            "localhost",
            "proxy example.com",
            "one.example.com two.example.com",
        ] {
            let mut fields = public_tls_fields();
            fields.insert("public_domain".into(), bad.into());
            let result = wizard_form_from_fields(&fields, Path::new("alighieri.conf"));
            assert!(result.is_err(), "accepted invalid public domain {bad:?}");
        }
    }

    #[test]
    fn public_tls_requires_absolute_service_data_paths() {
        let mut relative_userlist = public_tls_fields();
        relative_userlist.insert("userlist".into(), "users".into());
        let err =
            wizard_form_from_fields(&relative_userlist, Path::new("public.conf")).unwrap_err();
        assert!(err.contains("userlist path must be absolute"), "{err}");

        let mut relative_cache = public_tls_fields();
        relative_cache.insert("acme_cache".into(), "acme".into());
        let err = wizard_form_from_fields(&relative_cache, Path::new("public.conf")).unwrap_err();
        assert!(err.contains("ACME cache path must be absolute"), "{err}");

        let whitespace_paths = if cfg!(windows) {
            [
                ("userlist", r"C:\ProgramData\Alighieri\user  db"),
                ("userlist", "C:\\ProgramData\\Alighieri\\user\tdb"),
                ("acme_cache", r"C:\ProgramData\Alighieri\acme  cache"),
                ("acme_cache", "C:\\ProgramData\\Alighieri\\acme\tcache"),
            ]
        } else {
            [
                ("userlist", "/etc/alighieri/user  db"),
                ("userlist", "/etc/alighieri/user\tdb"),
                ("acme_cache", "/var/lib/alighieri/acme  cache"),
                ("acme_cache", "/var/lib/alighieri/acme\tcache"),
            ]
        };
        for (field, value) in whitespace_paths {
            let mut fields = public_tls_fields();
            fields.insert(field.into(), value.into());
            let err = wizard_form_from_fields(&fields, Path::new("public.conf")).unwrap_err();
            assert!(
                err.contains("changes when parsed as configuration"),
                "{field}: {err}"
            );
        }

        let (userlist, cache) = if cfg!(windows) {
            (
                r"C:\ProgramData\Alighieri Data\users",
                r"C:\ProgramData\Alighieri Data\acme",
            )
        } else {
            ("/etc/alighieri data/users", "/var/lib/alighieri data/acme")
        };
        let mut single_spaces = public_tls_fields();
        single_spaces.insert("userlist".into(), userlist.into());
        single_spaces.insert("acme_cache".into(), cache.into());
        let form = wizard_form_from_fields(&single_spaces, Path::new("public.conf")).unwrap();
        assert_eq!(form.userlist_path, Some(PathBuf::from(userlist)));
        assert_eq!(form.acme_cache_path, Some(PathBuf::from(cache)));
        let parsed = Config::parse(&render_config(&form)).unwrap();
        assert_eq!(parsed.userlist, Some(PathBuf::from(userlist)));
        let Some(TlsConfig::Acme(acme)) = parsed.tls else {
            panic!("expected ACME configuration");
        };
        assert_eq!(acme.cache_dir, PathBuf::from(cache));
    }

    #[test]
    fn public_tls_listener_is_fixed_to_public_port_443() {
        let mut wrong_port = public_tls_fields();
        wrong_port.insert("listen_port".into(), "8443".into());
        let err = wizard_form_from_fields(&wrong_port, Path::new("alighieri.conf")).unwrap_err();
        assert!(err.contains("0.0.0.0 port 443"), "{err}");

        let mut wrong_host = public_tls_fields();
        wrong_host.insert("listen_host".into(), "127.0.0.1".into());
        let err = wizard_form_from_fields(&wrong_host, Path::new("alighieri.conf")).unwrap_err();
        assert!(err.contains("0.0.0.0 port 443"), "{err}");
    }

    #[test]
    fn public_tls_udp_defaults_follow_domain_and_manual_advertise_is_preserved() {
        let mut defaults = public_tls_fields();
        defaults.insert("public_domain".into(), "edge.example.net".into());
        let default_form = wizard_form_from_fields(&defaults, Path::new("alighieri.conf")).unwrap();
        assert_eq!(
            default_form.udp_advertise.as_deref(),
            Some("edge.example.net")
        );

        let mut manual = defaults;
        manual.insert("udp_advertise".into(), "203.0.113.25".into());
        let manual_form = wizard_form_from_fields(&manual, Path::new("alighieri.conf")).unwrap();
        assert_eq!(manual_form.udp_advertise.as_deref(), Some("203.0.113.25"));
        let config = Config::parse(&render_config(&manual_form)).unwrap();
        assert!(matches!(
            config.udp_advertise,
            Some(UdpAdvertise::Ip(ip)) if ip == "203.0.113.25".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn public_tls_udp_can_be_disabled_without_leaking_udp_fields_or_permissions() {
        let mut fields = public_tls_fields();
        fields.insert("udp_enabled".into(), "off".into());
        // Disabled subordinate controls are ignored server-side, even in a
        // crafted request that submits invalid values for them.
        fields.insert("udp_port_range".into(), "0-99999".into());
        fields.insert("udp_advertise".into(), "bad host".into());
        let form = wizard_form_from_fields(&fields, Path::new("alighieri.conf")).unwrap();
        assert!(!form.udp_enabled);
        assert_eq!(form.udp_port_range, None);
        assert_eq!(form.udp_advertise, None);

        let text = render_config(&form);
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.udp_port_range, None);
        assert_eq!(config.udp_advertise, None);
        assert!(!text.contains("udp.portrange:"));
        assert!(!text.contains("udp.advertise:"));
        assert!(!text.contains("udpassociate"));
        let public_rule = config
            .rules
            .rules
            .iter()
            .find(|rule| rule.name.as_deref() == Some("public-internet"))
            .unwrap();
        assert_eq!(public_rule.commands.as_slice(), [SocksCommand::Connect]);
        assert_eq!(public_rule.protocols.as_slice(), [Protocol::Tcp]);
    }

    #[test]
    fn public_tls_rejects_invalid_udp_ranges() {
        for bad in [
            "",
            "0-100",
            "40099-40000",
            "65535-65536",
            "40000",
            "nope-nope",
            "40000-40099-40100",
        ] {
            let mut fields = public_tls_fields();
            fields.insert("udp_port_range".into(), bad.into());
            let result = wizard_form_from_fields(&fields, Path::new("alighieri.conf"));
            assert!(result.is_err(), "accepted invalid UDP range {bad:?}");
        }
    }

    #[test]
    fn public_tls_rejects_invalid_udp_advertised_hosts() {
        for bad in [
            "",
            "bad..host",
            ".relay.example.com",
            "relay.example.com..",
            "relay host",
        ] {
            let mut fields = public_tls_fields();
            fields.insert("udp_advertise".into(), bad.into());
            let result = wizard_form_from_fields(&fields, Path::new("alighieri.conf"));
            assert!(
                result.is_err(),
                "accepted invalid UDP advertised host {bad:?}"
            );
        }
    }

    #[test]
    fn public_tls_text_fields_reject_line_nul_and_comment_injection() {
        for (field, values) in [
            (
                "public_domain",
                [
                    "proxy.\rexample.com",
                    "proxy.\nexample.com",
                    "proxy.\0example.com",
                    "proxy.#example.com",
                ],
            ),
            (
                "userlist",
                [
                    "/etc/alighieri/\rusers",
                    "/etc/alighieri/\nusers",
                    "/etc/alighieri/\0users",
                    "/etc/alighieri/#users",
                ],
            ),
            (
                "acme_email",
                [
                    "admin@\rexample.com",
                    "admin@\nexample.com",
                    "admin@\0example.com",
                    "admin@#example.com",
                ],
            ),
            (
                "acme_cache",
                [
                    "/var/lib/\racme",
                    "/var/lib/\nacme",
                    "/var/lib/\0acme",
                    "/var/lib/#acme",
                ],
            ),
            (
                "udp_port_range",
                [
                    "40000-\r40099",
                    "40000-\n40099",
                    "40000-\x0040099",
                    "40000-#40099",
                ],
            ),
            (
                "udp_advertise",
                [
                    "relay.\rexample.com",
                    "relay.\nexample.com",
                    "relay.\0example.com",
                    "relay.#example.com",
                ],
            ),
        ] {
            for value in values {
                let mut fields = public_tls_fields();
                fields.insert(field.into(), value.into());
                let result = wizard_form_from_fields(&fields, Path::new("alighieri.conf"));
                assert!(result.is_err(), "{field} accepted injected value {value:?}");
            }
        }

        for bad in ["proxy\ruser", "proxy\nuser", "proxy\0user", "proxy:user"] {
            let mut fields = public_tls_fields();
            fields.insert("initial_username".into(), bad.into());
            let result = wizard_form_from_fields(&fields, Path::new("alighieri.conf"));
            assert!(result.is_err(), "initial username accepted {bad:?}");
        }
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
        // Every template defaults the log file to empty -> stdout. Template
        // state now tracks the shared listener/userlist values for all three
        // profiles instead of embedding a two-profile logfile preset.
        assert!(input_tag(&html, "logfile").contains(r#"value="""#));
        assert!(html.contains(
            r#""lan-username": { listen: "0.0.0.0", port: "1080", trusted: "192.168.0.0/16" }"#
        ));
        assert!(html
            .contains(r#""public-tls": { listen: "0.0.0.0", port: "443", trusted: "0.0.0.0/0" }"#));
        assert!(html.contains("states[activeTemplate] = readTemplateState()"));
        assert!(html.contains("activeTemplate = radio.value"));
        assert!(!html.contains("dataset.default"));
        assert!(!html.contains("data-default"));
    }

    #[test]
    fn browser_script_executes_three_profile_state_transitions() {
        let node = std::process::Command::new("node").arg("--version").output();
        if !node.is_ok_and(|output| output.status.success()) {
            assert!(
                std::env::var_os("ALIGHIERI_REQUIRE_NODE_TESTS").is_none(),
                "node is required for executable wizard browser-state tests in CI"
            );
            eprintln!("skipping executable wizard browser-state test: node is unavailable");
            return;
        }

        let html = render_wizard_form("token", Path::new("alighieri.conf"), None);
        let script = html
            .split_once("<script>")
            .and_then(|(_, rest)| rest.split_once("</script>"))
            .map(|(script, _)| script)
            .unwrap();
        let prelude = r##"
function control(value = "") {
  return {
    value, checked: false, disabled: false, required: false, readOnly: false,
    hidden: false, dataset: {}, listeners: {},
    addEventListener(kind, callback) { this.listeners[kind] = callback; }
  };
}
const listenControl = control("127.0.0.1");
const portControl = control("1080");
const trustedControl = control("127.0.0.1");
const userlistControl = control("users");
userlistControl.dataset.standardDefault = "users";
userlistControl.dataset.publicDefault = "/etc/alighieri/users";
const publicSectionControl = control();
const publicNoteControl = control();
const udpEnabledControl = control();
udpEnabledControl.checked = true;
const udpFieldsControl = control();
const domainControl = control("");
const advertiseControl = control("");
const cacheControl = control("/var/lib/alighieri/acme");
const rangeControl = control("40000-40099");
const radios = ["local-no-auth", "lan-username", "public-tls"].map(control);
const bySelector = {
  "[name=listen_host]": listenControl,
  "[name=listen_port]": portControl,
  "[name=trusted_client]": trustedControl,
  "[name=userlist]": userlistControl,
  "#public-profile": publicSectionControl,
  "#public-listener-note": publicNoteControl,
  "#udp-enabled": udpEnabledControl,
  "#udp-fields": udpFieldsControl,
  "[name=public_domain]": domainControl,
  "[name=udp_advertise]": advertiseControl,
  "[name=acme_cache]": cacheControl,
  "[name=udp_port_range]": rangeControl
};
const document = {
  querySelector(selector) { return bySelector[selector]; },
  querySelectorAll(selector) {
    if (selector === "[name=template]") return radios;
    if (selector === ".public-only") return [domainControl, cacheControl, udpEnabledControl];
    if (selector === ".public-udp-only") return [rangeControl, advertiseControl];
    throw new Error(`unexpected selector: ${selector}`);
  }
};
"##;
        let assertions = r#"
function check(value, message) { if (!value) throw new Error(message); }
const localRadio = radios.find((radio) => radio.value === "local-no-auth");
const lanRadio = radios.find((radio) => radio.value === "lan-username");
const publicRadio = radios.find((radio) => radio.value === "public-tls");
check(domainControl.value === "", "example domain must not be a submitted default");
listenControl.value = "127.0.0.9";
userlistControl.value = "local-edit";
publicRadio.listeners.change();
check(listenControl.value === "0.0.0.0" && portControl.value === "443", "public preset");
check(userlistControl.value === userlistControl.dataset.publicDefault, "public userlist preset");
check(!publicSectionControl.hidden && domainControl.required && !domainControl.disabled, "public visibility");
domainControl.value = "edge.example.net";
domainControl.listeners.input();
check(advertiseControl.value === "edge.example.net", "domain should seed UDP advertise");
advertiseControl.value = "relay.example.net";
advertiseControl.listeners.input();
domainControl.value = "other.example.net";
domainControl.listeners.input();
check(advertiseControl.value === "relay.example.net", "manual UDP advertise must survive domain edits");
userlistControl.value = "/etc/alighieri/public-users";
lanRadio.listeners.change();
check(portControl.value === "1080" && userlistControl.value === userlistControl.dataset.standardDefault, "LAN preset");
portControl.value = "2080";
localRadio.listeners.change();
check(listenControl.value === "127.0.0.9" && userlistControl.value === "local-edit", "local edit preservation");
publicRadio.listeners.change();
check(userlistControl.value === "/etc/alighieri/public-users", "public edit preservation");
check(domainControl.value === "other.example.net" && advertiseControl.value === "relay.example.net", "public-only edit preservation");
lanRadio.listeners.change();
check(portControl.value === "2080", "LAN edit preservation");
publicRadio.listeners.change();
udpEnabledControl.checked = false;
udpEnabledControl.listeners.change();
check(udpFieldsControl.hidden && rangeControl.disabled && advertiseControl.disabled, "UDP disabled state");
"#;
        let harness = format!("{prelude}\n{script}\n{assertions}");
        let output = std::process::Command::new("node")
            .arg("-e")
            .arg(harness)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "browser state script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn rendered_form_offers_public_profile_and_controls_visibility_server_side() {
        let local_html = render_wizard_form("token", Path::new("alighieri.conf"), None);
        assert!(local_html.contains(r#"value="public-tls""#));
        assert!(local_html.contains("Public SOCKS5-over-TLS (ProxiFyre)"));
        assert!(local_html.contains(r#"<section id="public-profile" hidden>"#));
        assert!(input_tag(&local_html, "public_domain").contains(r#"value="""#));
        assert!(
            input_tag(&local_html, "public_domain").contains(r#"placeholder="proxy.example.com""#)
        );
        assert!(input_tag(&local_html, "public_domain").contains("disabled"));
        assert!(!input_tag(&local_html, "public_domain").contains("required"));
        assert!(!local_html.contains(r#"name="password""#));
        assert!(local_html.contains("advertiseWasEdited"));
        assert!(local_html.contains("if (!advertiseWasEdited) advertise.value = domain.value"));

        let form = public_tls_form();
        let prefill = ImportPrefill {
            form,
            warnings: Vec::new(),
            source: PathBuf::from("public.conf"),
        };
        let public_html = render_wizard_form("token", Path::new("alighieri.conf"), Some(&prefill));
        assert!(public_html.contains(r#"value="public-tls" checked"#));
        assert!(public_html.contains(r#"<section id="public-profile">"#));
        assert!(!input_tag(&public_html, "public_domain").contains("disabled"));
        assert!(input_tag(&public_html, "public_domain").contains("required"));
        assert!(input_tag(&public_html, "listen_host").contains("readonly"));
        assert!(input_tag(&public_html, "listen_port").contains("readonly"));
        assert!(input_tag(&public_html, "trusted_client").contains("readonly"));
        assert!(input_tag(&public_html, "udp_port_range").contains("required"));
        assert!(!input_tag(&public_html, "udp_port_range").contains("disabled"));
    }

    #[test]
    fn non_public_import_keeps_public_udp_default_enabled() {
        let prefill = ImportPrefill {
            form: sample_form(WizardTemplate::LanUsername, Some(PathBuf::from("users"))),
            warnings: Vec::new(),
            source: PathBuf::from("lan.conf"),
        };

        let html = render_wizard_form("token", Path::new("alighieri.conf"), Some(&prefill));

        assert!(html.contains(
            r#"id="udp-enabled" class="public-only" type="checkbox" name="udp_enabled" value="on" checked disabled"#
        ));
    }

    #[test]
    fn rendered_public_fields_are_html_escaped() {
        let mut form = public_tls_form();
        form.public_domain = Some(r#"<proxy>&".example.com"#.into());
        form.initial_username = Some(r#"<user>&""#.into());
        form.userlist_path = Some(PathBuf::from(r#"<users>&""#));
        form.acme_cache_path = Some(PathBuf::from(r#"<cache>&""#));
        form.udp_advertise = Some(r#"<relay>&""#.into());
        let prefill = ImportPrefill {
            form,
            warnings: Vec::new(),
            source: PathBuf::from("public.conf"),
        };

        let html = render_wizard_form("token", Path::new("alighieri.conf"), Some(&prefill));
        assert!(html.contains(r#"value="&lt;proxy&gt;&amp;&quot;.example.com""#));
        assert!(html.contains(r#"value="&lt;user&gt;&amp;&quot;""#));
        assert!(html.contains(r#"value="&lt;users&gt;&amp;&quot;""#));
        assert!(html.contains(r#"value="&lt;cache&gt;&amp;&quot;""#));
        assert!(html.contains(r#"value="&lt;relay&gt;&amp;&quot;""#));
        assert!(!html.contains(r#"value="<proxy>"#));
        assert!(!html.contains(r#"value="<user>"#));
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
    fn auth_command_only_import_gets_a_valid_modelled_userlist_and_warning() {
        for tls in [
            "",
            "tls.acme.domains: proxy.example.com\ntls.acme.cache: /var/lib/alighieri/acme\n",
        ] {
            let config = Config::parse(&format!(
                "internal: 0.0.0.0 port = 443\n\
                 external: 0.0.0.0\n\
                 socksmethod: username\n\
                 auth.command: /usr/local/bin/verify-user\n\
                 {tls}\
                 client pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 }}\n\
                 socks pass {{ from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect method: username }}\n"
            ))
            .unwrap();

            let form = wizard_form_from_config(&config, Path::new("imported.conf"));
            assert_eq!(form.template, WizardTemplate::LanUsername);
            assert_eq!(form.userlist_path, Some(PathBuf::from("users")));
            Config::parse(&render_config(&form)).unwrap();
            let warnings = import_loss_warnings(&config, &form).unwrap();
            assert!(
                warnings
                    .iter()
                    .any(|warning| warning.contains("auth.command")),
                "{warnings:?}"
            );
            if !tls.is_empty() {
                assert!(
                    warnings.iter().any(|warning| warning.contains("TLS")),
                    "{warnings:?}"
                );
            }
        }
    }

    #[test]
    fn acme_username_import_with_private_client_range_stays_lan() {
        let text = render_config(&public_tls_form()).replace(
            "from: 0.0.0.0/0 to: 0.0.0.0/0\n}\n\nsocks block",
            "from: 192.168.0.0/16 to: 0.0.0.0/0\n}\n\nsocks block",
        );
        let config = Config::parse(&text).unwrap();

        let form = wizard_form_from_config(&config, Path::new("imported.conf"));

        assert_eq!(form.template, WizardTemplate::LanUsername);
        assert_eq!(form.trusted_client, "192.168.0.0/16");
        let warnings = import_loss_warnings(&config, &form).unwrap();
        assert!(warnings.iter().any(|warning| warning.contains("TLS")));
    }

    #[test]
    fn acme_username_import_with_relative_service_paths_stays_lan() {
        let original = public_tls_form();
        let text = render_config(&original)
            .replace(
                &format!(
                    "userlist: {}",
                    original.userlist_path.as_ref().unwrap().display()
                ),
                "userlist: users",
            )
            .replace(
                &format!(
                    "tls.acme.cache: {}",
                    original.acme_cache_path.as_ref().unwrap().display()
                ),
                "tls.acme.cache: acme",
            );
        let config = Config::parse(&text).unwrap();

        let form = wizard_form_from_config(&config, Path::new("imported.conf"));

        assert_eq!(form.template, WizardTemplate::LanUsername);
        let warnings = import_loss_warnings(&config, &form).unwrap();
        assert!(warnings.iter().any(|warning| warning.contains("TLS")));
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
            public_domain: None,
            acme_email: None,
            initial_username: None,
            acme_cache_path: None,
            acme_staging: false,
            udp_enabled: false,
            udp_port_range: None,
            udp_advertise: None,
        };
        let original = Config::parse(&render_config(&original_form)).unwrap();
        let extracted = wizard_form_from_config(&original, Path::new("out.conf"));
        let warnings = import_loss_warnings(&original, &extracted).unwrap();
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn public_tls_import_preserves_modelled_acme_and_udp_settings_without_warnings() {
        for udp_enabled in [true, false] {
            let mut fields = public_tls_fields();
            fields.insert("acme_email".into(), "admin@example.com".into());
            fields.insert("acme_staging".into(), "on".into());
            fields.insert(
                "udp_enabled".into(),
                if udp_enabled { "on" } else { "off" }.into(),
            );
            if udp_enabled {
                fields.insert("udp_port_range".into(), "41000-41020".into());
                fields.insert("udp_advertise".into(), "relay.example.net".into());
            }
            let original_form = wizard_form_from_fields(&fields, Path::new("public.conf")).unwrap();
            let original = Config::parse(&render_config(&original_form)).unwrap();

            let extracted = wizard_form_from_config(&original, Path::new("public.conf"));
            assert_eq!(extracted.template, WizardTemplate::PublicTls);
            assert_eq!(
                extracted.public_domain.as_deref(),
                Some(PUBLIC_DOMAIN_EXAMPLE)
            );
            assert_eq!(extracted.acme_email.as_deref(), Some("admin@example.com"));
            assert!(extracted.acme_staging);
            assert_eq!(extracted.udp_enabled, udp_enabled);
            if udp_enabled {
                assert_eq!(extracted.udp_port_range.as_deref(), Some("41000-41020"));
                assert_eq!(
                    extracted.udp_advertise.as_deref(),
                    Some("relay.example.net")
                );
            } else {
                assert_eq!(extracted.udp_port_range, None);
                assert_eq!(extracted.udp_advertise, None);
            }

            let warnings = import_loss_warnings(&original, &extracted).unwrap();
            assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
            assert!(!warnings.iter().any(|warning| warning.contains("TLS")));
            assert!(!warnings.iter().any(|warning| warning.contains("UDP")));
        }
    }

    #[test]
    fn public_tls_import_keeps_certificate_file_and_custom_acl_loss_warnings() {
        let mut lan = sample_form(
            WizardTemplate::LanUsername,
            Some(PathBuf::from("/etc/alighieri/users")),
        );
        lan.listen_host = "0.0.0.0".into();
        lan.listen_port = 443;
        lan.trusted_client = "192.168.0.0/16".into();
        let lan_text = render_config(&lan).replacen(
            "external: 0.0.0.0\n",
            "external: 0.0.0.0\ntls.certfile: server.crt\ntls.keyfile: server.key\n",
            1,
        );
        let cert_config = Config::parse(&lan_text).unwrap();
        let cert_form = wizard_form_from_config(&cert_config, Path::new("cert.conf"));
        assert_eq!(cert_form.template, WizardTemplate::LanUsername);
        let cert_warnings = import_loss_warnings(&cert_config, &cert_form).unwrap();
        assert!(
            cert_warnings.iter().any(|warning| warning.contains("TLS")),
            "{cert_warnings:?}"
        );

        let public_text = format!(
            "{}\nsocks block \"custom-policy\" {{ to: 203.0.113.0/24 }}\n",
            render_config(&public_tls_form())
        );
        let custom_acl = Config::parse(&public_text).unwrap();
        let custom_form = wizard_form_from_config(&custom_acl, Path::new("public.conf"));
        assert_eq!(custom_form.template, WizardTemplate::PublicTls);
        let custom_warnings = import_loss_warnings(&custom_acl, &custom_form).unwrap();
        assert!(
            custom_warnings
                .iter()
                .any(|warning| warning.contains("access-control rules")),
            "{custom_warnings:?}"
        );
    }

    #[test]
    fn public_tls_static_template_parses_and_matches_wizard_security_semantics() {
        let static_config =
            Config::parse(include_str!("../doc/templates/public-tls-proxifyre.conf")).unwrap();
        let mut wizard_form = public_tls_form();
        // The reviewed example is intentionally the Linux VPS form of the
        // profile even when this test runs on Windows CI.
        wizard_form.userlist_path = Some(PathBuf::from("/etc/alighieri/users"));
        wizard_form.acme_cache_path = Some(PathBuf::from("/var/lib/alighieri/acme"));
        let wizard_config = Config::parse(&render_config(&wizard_form)).unwrap();

        let static_to_wizard = config_loss_warnings(&static_config, &wizard_config);
        let wizard_to_static = config_loss_warnings(&wizard_config, &static_config);
        assert!(
            static_to_wizard.is_empty(),
            "static template differs from wizard: {static_to_wizard:?}"
        );
        assert!(
            wizard_to_static.is_empty(),
            "wizard differs from static template: {wizard_to_static:?}"
        );
        assert_eq!(static_config.socks_methods.as_slice(), [AuthKind::Username]);
        assert!(!static_config.socks_methods.contains(&AuthKind::None));
        assert_eq!(
            static_config.udp_port_range,
            Some("40000-40099".parse::<PortRange>().unwrap())
        );
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
                public_domain: None,
                acme_email: None,
                initial_username: None,
                acme_cache_path: None,
                acme_staging: false,
                udp_enabled: false,
                udp_port_range: None,
                udp_advertise: None,
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
    fn rulesets_equivalent_distinguishes_bandwidth() {
        // Two rule sets that differ only in a rule's `bandwidth:` are not
        // equivalent — otherwise the wizard would drop throttling on import
        // without warning.
        let with_bw = Config::parse(
            "internal: 127.0.0.1 port = 1080\n\
             socks pass { to: 0.0.0.0/0 command: connect bandwidth: 1MiB/1 }\n",
        )
        .unwrap();
        let without_bw = Config::parse(
            "internal: 127.0.0.1 port = 1080\n\
             socks pass { to: 0.0.0.0/0 command: connect }\n",
        )
        .unwrap();
        assert!(rulesets_equivalent(&with_bw.rules, &with_bw.rules));
        assert!(!rulesets_equivalent(&with_bw.rules, &without_bw.rules));
    }

    #[test]
    fn import_flags_dropped_per_rule_bandwidth() {
        // The wizard does not model per-rule `bandwidth:`, so regeneration drops
        // it; the loss must be reported rather than silently discarded. The rule
        // shape otherwise round-trips, so `bandwidth` is the only difference.
        let config = Config::parse(
            "internal: 127.0.0.1 port = 1080\n\
             external: 0.0.0.0\n\
             client pass { from: 192.168.0.0/16 to: 0.0.0.0/0 }\n\
             socks pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: connect bandwidth: 1MiB/1 }\n",
        )
        .unwrap();
        let form = wizard_form_from_config(&config, Path::new("out.conf"));
        let warnings = import_loss_warnings(&config, &form).unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("access-control rules")),
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
            public_domain: None,
            acme_email: None,
            initial_username: None,
            acme_cache_path: None,
            acme_staging: false,
            udp_enabled: false,
            udp_port_range: None,
            udp_advertise: None,
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
    fn public_success_page_has_user_firewall_service_and_proxifyre_guidance() {
        let mut form = public_tls_form();
        form.initial_username = Some("proxyuser".into());
        assert!(!render_config(&form).contains("proxyuser"));
        let html = render_success(&write_report(), &form);

        assert!(html.contains("passed the real Alighieri configuration parser"));
        assert!(html.contains("alighieri user add proxyuser --userlist"));
        assert!(html.contains("prompts for the password securely"));
        assert!(html.contains("Inbound TCP 443"));
        assert!(html.contains("Outbound TCP 443"));
        assert!(html.contains("DNS A record"));
        assert!(html.contains("AAAA record only when IPv6 TCP 443"));
        assert!(html.contains("inbound UDP <code>40000-40099</code>"));
        assert!(html.contains("alighieri --check"));
        #[cfg(not(windows))]
        {
            assert!(html.contains("scripts/alighieri.sh install --no-start"));
            assert!(html.contains("Release archives do not bundle the lifecycle script"));
            assert!(html.contains(
                "raw.githubusercontent.com/wiresock/alighieri/main/scripts/alighieri.sh"
            ));
            assert!(html.contains("--binary /path/to/extracted/alighieri"));
        }
        assert!(html.contains("ProxiFyre settings"));
        assert!(html.contains("<dt>Server</dt><dd><code>proxy.example.com</code>"));
        assert!(html.contains("<dt>Port</dt><dd>443</dd>"));
        assert!(html.contains("<dt>TLS</dt><dd>enabled</dd>"));
        assert!(html.contains("<dt>UDP</dt><dd>enabled</dd>"));
        assert!(html.contains("ProxiFyre 2.4.0 or later"));
        assert!(html.contains("&quot;socks5Transport&quot;: &quot;TLS&quot;"));
        assert!(html.contains("&quot;supportedProtocols&quot;: [&quot;TCP&quot;, &quot;UDP&quot;]"));
        assert!(html.contains("&quot;supportedAddressFamilies&quot;: [&quot;IPv4&quot;]"));
        assert!(html.contains("&quot;tlsAllowInvalidCertificate&quot;: false"));
        assert!(html.contains("not a full IP-level VPN"));
        assert!(html.contains("alighieri.conf.bak"));
        assert!(!html.contains("ACME staging is enabled"));
        #[cfg(windows)]
        {
            let bootstrap = html
                .find("Prepare the Windows service data directory")
                .unwrap();
            let user = html.find("Create the authenticated user").unwrap();
            let start = html.find("alighieri service start").unwrap();
            assert!(bootstrap < user && user < start);
            assert!(html.contains("Copy-Item -LiteralPath"));
            assert!(html.contains("Alighieri\\alighieri.conf"));
        }
    }

    #[test]
    fn public_success_page_is_conditional_for_udp_and_staging() {
        let mut form = public_tls_form();
        form.udp_enabled = false;
        form.udp_port_range = None;
        form.udp_advertise = None;
        form.acme_staging = true;
        let html = render_success(&write_report(), &form);

        assert!(html.contains("ACME staging is enabled"));
        assert!(html.contains("will not be trusted by normal clients"));
        assert!(html.contains("will connect only after you switch to a production certificate"));
        assert!(html.contains("Do not disable certificate validation"));
        assert!(html.contains("<dt>UDP</dt><dd>disabled</dd>"));
        assert!(html.contains("&quot;supportedProtocols&quot;: [&quot;TCP&quot;]"));
        assert!(
            !html.contains("&quot;supportedProtocols&quot;: [&quot;TCP&quot;, &quot;UDP&quot;]")
        );
        assert!(!html.contains("inbound UDP"));
        assert!(!html.contains(PUBLIC_UDP_RANGE));
        assert!(!html.contains("<dt>Username</dt>"));
    }

    #[test]
    fn public_success_command_quotes_injected_username_and_path() {
        let mut fields = public_tls_fields();
        fields.insert("initial_username".into(), "proxyuser;echo-owned".into());
        let injected_userlist = if cfg!(windows) {
            r"C:\ProgramData\Alighieri\users;echo-owned"
        } else {
            "/etc/alighieri/users;echo-owned"
        };
        fields.insert("userlist".into(), injected_userlist.into());
        let form = wizard_form_from_fields(&fields, Path::new("public.conf")).unwrap();
        let html = render_success(&write_report(), &form);

        let expected = html_escape(&format!(
            "alighieri user add {} --userlist {}",
            shell_quote_command_argument("proxyuser;echo-owned"),
            shell_quote_command_argument(injected_userlist)
        ));
        assert!(html.contains(&expected));
        assert!(!html.contains("user add proxyuser;echo-owned"));

        let mut markup = form;
        markup.initial_username = Some("<img src=x onerror=alert(1)>".into());
        let markup_html = render_success(&write_report(), &markup);
        assert!(!markup_html.contains("<img src=x"));
        assert!(markup_html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }

    #[test]
    fn public_success_commands_terminate_options() {
        let mut form = public_tls_form();
        form.userlist_path = Some(PathBuf::from("--user-list"));
        let report = WriteReport {
            output_path: PathBuf::from("--generated-config"),
            backup_path: None,
        };

        let html = render_success(&report, &form);
        let absolute_output = std::path::absolute(&report.output_path).unwrap();

        assert!(html.contains("alighieri --check --config"));
        assert!(html.contains(&html_escape(&absolute_output.display().to_string())));
        #[cfg(not(windows))]
        {
            assert!(html.contains("chown root:alighieri -- --user-list"));
            assert!(html.contains("chmod 640 -- --user-list"));
            assert!(html.contains("install -m 640 -o root -g alighieri -- "));
        }
    }

    #[test]
    fn public_success_stages_canonical_config_and_preserves_a_backup() {
        let report = WriteReport {
            output_path: PathBuf::from("generated-public.conf"),
            backup_path: None,
        };
        let html = render_success(&report, &public_tls_form());

        #[cfg(windows)]
        {
            assert!(html.contains("--check --config $staged"));
            assert!(html.contains("[IO.File]::Replace"));
            assert!(html.contains("[IO.File]::Move"));
            assert!(html.contains("Get-Command alighieri -CommandType Application"));
            assert!(html.contains("-not $?"));
            assert!(!html.contains("[IO.File]::Delete"));
            assert!(html.contains("$destination.bak"));
            assert!(html.contains("GetRandomFileName"));
            assert!(html.contains("finally"));
        }
        #[cfg(not(windows))]
        {
            assert!(html.contains("--check --config &quot;$staged&quot;"));
            assert!(html.contains("mktemp"));
            assert!(html.contains("destination_path}.bak.tmp.XXXXXX"));
            assert!(html.contains("mv -fT"));
            assert!(html.contains("$destination_path.bak"));
            assert!(html.contains("trap cleanup"));
        }
    }

    #[cfg(windows)]
    #[test]
    fn powershell_splat_and_array_arguments_are_quoted() {
        assert_eq!(shell_quote_command_argument("@proxyuser"), "'@proxyuser'");
        assert_eq!(shell_quote_command_argument("one,two"), "'one,two'");
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
    fn config_backup_does_not_write_through_a_symlinked_bak() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alighieri.conf");
        std::fs::write(&path, "new config").unwrap();
        let target = dir.path().join("secret");
        std::fs::write(&target, "secret-contents").unwrap();
        // A symlink planted at the backup path must not redirect the backup
        // write; the temp+rename replaces the link rather than following it.
        symlink(&target, backup_path(&path)).unwrap();

        let backup = create_config_backup(&path).unwrap();

        // The symlink target is untouched, and the `.bak` is a real file.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "secret-contents");
        assert!(!std::fs::symlink_metadata(&backup)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "new config");
    }

    #[cfg(unix)]
    #[test]
    fn config_backup_refuses_a_symlinked_source() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "secret-contents").unwrap();
        // The config path itself is a symlink to a sensitive file.
        let path = dir.path().join("alighieri.conf");
        symlink(&secret, &path).unwrap();

        // Backing up must refuse to follow the symlink to its target.
        assert!(create_config_backup(&path).is_err());
        // It fails before any temp/backup is created, so no `.bak` exists at all.
        assert!(!backup_path(&path).exists());
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
