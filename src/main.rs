//! Alighieri — a lightweight SOCKS5 proxy server.

mod management;
mod wizard;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use alighieri::auth::UserDb;
use alighieri::config::{Config, LogOutput, TlsConfig};
use alighieri::runtime::{
    init_console_logging, reload_signal_channel, run_server_reloading_until_shutdown,
    shutdown_signal,
};
use alighieri::tls;
use management::{
    AddResult, CapabilitiesResult, DeleteResult, ListResult, ManagementError, ManagementErrorCode,
    SecretString, VerifyResult,
};
use tracing::{error, info};

const DEFAULT_CONFIG: &str = "alighieri.conf";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Run {
        config_path: PathBuf,
    },
    Check {
        config_path: PathBuf,
        format: CheckOutputFormat,
    },
    Service {
        args: Vec<String>,
    },
    User {
        args: Vec<String>,
    },
    Config {
        args: Vec<String>,
    },
    Capabilities {
        args: Vec<String>,
    },
    Help,
    Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckOutputFormat {
    Text,
    Json,
}

#[derive(Debug, PartialEq, Eq)]
enum ConfigCommand {
    MetadataJson,
    Wizard(wizard::ConfigWizardArgs),
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReloadBehavior {
    Live,
    Restart,
}

impl ReloadBehavior {
    fn as_str(self) -> &'static str {
        match self {
            ReloadBehavior::Live => "live",
            ReloadBehavior::Restart => "restart",
        }
    }
}

struct ConfigSettingMetadata {
    name: &'static str,
    reload: ReloadBehavior,
    applies_to: &'static str,
    note: &'static str,
}

fn parse_args() -> Result<Command, String> {
    parse_args_from(std::env::args().skip(1).collect())
}

fn parse_args_from(args: Vec<String>) -> Result<Command, String> {
    if args.first().map(String::as_str) == Some("capabilities") {
        return Ok(Command::Capabilities {
            args: args.into_iter().skip(1).collect(),
        });
    }
    if args.first().map(String::as_str) == Some("service") {
        return Ok(Command::Service {
            args: args.into_iter().skip(1).collect(),
        });
    }
    if args.first().map(String::as_str) == Some("user") {
        return Ok(Command::User {
            args: args.into_iter().skip(1).collect(),
        });
    }
    if args.first().map(String::as_str) == Some("config")
        && args
            .get(1)
            .is_some_and(|arg| matches!(arg.as_str(), "metadata" | "wizard" | "-h" | "--help"))
    {
        return Ok(Command::Config {
            args: args.into_iter().skip(1).collect(),
        });
    }
    if args
        .first()
        .is_some_and(|arg| arg == "-h" || arg == "--help")
    {
        return Ok(Command::Help);
    }
    if args
        .first()
        .is_some_and(|arg| arg == "-V" || arg == "--version")
    {
        return Ok(Command::Version);
    }

    let mut config_path: Option<PathBuf> = None;
    let mut check_only = false;
    let mut check_format = CheckOutputFormat::Text;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--check" => check_only = true,
            "--json" => {
                check_only = true;
                check_format = CheckOutputFormat::Json;
            }
            "--config" => {
                let Some(path) = iter.next() else {
                    return Err("--config requires a path".into());
                };
                config_path = Some(PathBuf::from(path));
            }
            "-h" | "--help" => {
                return Ok(Command::Help);
            }
            "-V" | "--version" => {
                return Ok(Command::Version);
            }
            _ => {
                if arg.starts_with('-') {
                    return Err(format!(
                        "unknown option '{arg}' (use --help to list options; pass a path starting with '-' via --config)"
                    ));
                }
                if config_path.is_some() {
                    return Err(format!(
                        "unexpected argument '{arg}': the config path is already set"
                    ));
                }
                config_path = Some(PathBuf::from(arg));
            }
        }
    }

    let config_path = config_path.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    if check_only {
        Ok(Command::Check {
            config_path,
            format: check_format,
        })
    } else {
        Ok(Command::Run { config_path })
    }
}

fn print_help() {
    println!("Alighieri — a lightweight SOCKS5 proxy server\n");
    println!("USAGE:");
    println!("    alighieri [CONFIG]                         Run the proxy");
    println!("    alighieri --config CONFIG                  Run the proxy");
    println!("    alighieri --check [CONFIG]                 Validate the configuration and exit");
    println!("    alighieri --json [CONFIG]                  Validate and print JSON output");
    println!("    alighieri --check --json [CONFIG]          Same as --json");
    println!("    alighieri config metadata --json           Print config reload metadata");
    println!("    alighieri config wizard [OPTIONS]          Open local config generator");
    println!("    alighieri capabilities --json              Print management capabilities");
    println!("    alighieri user add USER [OPTIONS]          Add/update an Argon2id user");
    println!("    alighieri user delete USER [OPTIONS]       Remove a user");
    println!("    alighieri user list [OPTIONS]              List users");
    println!("    alighieri user verify USER [OPTIONS]       Verify a user password");
    #[cfg(windows)]
    {
        println!("    alighieri service install --config CONFIG  Install the Windows Service");
        println!("    alighieri service uninstall                Remove the Windows Service");
        println!("    alighieri service start                    Start the Windows Service");
        println!("    alighieri service stop                     Stop the Windows Service");
        println!("    alighieri service reload                   Reload Windows Service config");
        println!("    alighieri service status                   Show Windows Service status");
    }
    println!("    alighieri --version                        Print version and exit");
    println!("    alighieri --help                           Show this help");
    println!("\nLog verbosity is controlled by the RUST_LOG environment variable");
    println!("(e.g. RUST_LOG=debug). The default level is 'info'.");
}

#[tokio::main]
async fn main() -> ExitCode {
    let command = match parse_args() {
        Ok(command) => command,
        Err(e) => {
            eprintln!("alighieri: {e}");
            return ExitCode::FAILURE;
        }
    };

    match command {
        Command::Help => {
            print_help();
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Check {
            config_path,
            format,
        } => validate_config(&config_path, format),
        Command::Run { config_path } => run_console(config_path).await,
        Command::Service { args } => handle_service(args).await,
        Command::User { args } => handle_user(args),
        Command::Config { args } => handle_config(args).await,
        Command::Capabilities { args } => handle_capabilities(args),
    }
}

fn handle_capabilities(args: Vec<String>) -> ExitCode {
    match args.as_slice() {
        [arg] if arg == "--json" => {
            management::emit_success("capabilities", CapabilitiesResult::current())
        }
        [] => {
            println!("usage: alighieri capabilities --json");
            ExitCode::SUCCESS
        }
        [arg] if arg == "-h" || arg == "--help" => {
            println!("usage: alighieri capabilities --json");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("alighieri: usage: alighieri capabilities --json");
            ExitCode::FAILURE
        }
    }
}

/// Success JSON for `--check --json`. Beyond `ok`/`path`/`message` it reports
/// the effective `listen` address (`internal:` is last-wins), whether `acme` is
/// enabled, the resolved `acme_cache` directory (empty when ACME is off), and the
/// effective `userlist` setting (empty when unset), so tooling — e.g. the systemd
/// installer deciding whether to grant `CAP_NET_BIND_SERVICE`, or checking paths
/// from included/last-wins settings as the service account — can read the parsed
/// facts without reparsing config. The declared and canonical configuration
/// source and wildcard-pattern arrays let the installer validate both include
/// spellings, every parsed physical file, and directories that could supply a
/// new wildcard match on reload.
fn check_ok_json(config_path: &Path, config: &Config) -> String {
    let acme = matches!(config.tls, Some(TlsConfig::Acme(_)));
    let acme_cache = match &config.tls {
        Some(TlsConfig::Acme(cfg)) => cfg.cache_dir.display().to_string(),
        _ => String::new(),
    };
    // The file-logging path (empty unless `logoutput` includes `file`), so the
    // installer can check it against the unit's writable log directory.
    let log_file = match (
        config.log_outputs.contains(&LogOutput::File),
        &config.log_file,
    ) {
        (true, Some(path)) => path.display().to_string(),
        _ => String::new(),
    };
    // Keep the parser's effective value verbatim. Relative userlist paths are
    // intentionally resolved by the process working directory at runtime (not
    // relative to the config file), and the file may not exist yet during a
    // `--no-start` deployment bootstrap, so canonicalising here would both alter
    // semantics and reject a supported workflow.
    let userlist = config
        .userlist
        .as_deref()
        .map_or_else(String::new, |path| path.display().to_string());
    let declared_config_sources = json_path_array(
        config
            .loaded_config_sources()
            .iter()
            .map(|source| source.declared_path()),
    );
    let canonical_config_sources = json_path_array(
        config
            .loaded_config_sources()
            .iter()
            .map(|source| source.canonical_path()),
    );
    let declared_config_include_patterns = json_path_array(
        config
            .loaded_include_patterns()
            .iter()
            .map(|pattern| pattern.declared_path()),
    );
    let canonical_config_include_patterns = json_path_array(
        config
            .loaded_include_patterns()
            .iter()
            .map(|pattern| pattern.canonical_path()),
    );
    format!(
        "{{\"ok\":true,\"path\":\"{}\",\"message\":\"configuration is valid\",\"listen\":\"{}\",\"acme\":{},\"acme_cache\":\"{}\",\"log_file\":\"{}\",\"userlist\":\"{}\",\"declared_config_sources\":{},\"canonical_config_sources\":{},\"declared_config_include_patterns\":{},\"canonical_config_include_patterns\":{}}}",
        json_escape(&config_path.display().to_string()),
        json_escape(&config.internal.to_string()),
        acme,
        json_escape(&acme_cache),
        json_escape(&log_file),
        json_escape(&userlist),
        declared_config_sources,
        canonical_config_sources,
        declared_config_include_patterns,
        canonical_config_include_patterns,
    )
}

fn json_path_array<'a>(paths: impl IntoIterator<Item = &'a Path>) -> String {
    let mut json = String::from("[");
    for (index, path) in paths.into_iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        json.push('"');
        json.push_str(&json_escape(&path.display().to_string()));
        json.push('"');
    }
    json.push(']');
    json
}

fn validate_config(config_path: &Path, format: CheckOutputFormat) -> ExitCode {
    match Config::load(config_path).and_then(|config| {
        config.validate_startup()?;
        tls::validate_config(&config)?;
        Ok(config)
    }) {
        Ok(config) => {
            match format {
                CheckOutputFormat::Text => {
                    println!(
                        "alighieri: configuration '{}' is valid",
                        config_path.display()
                    );
                }
                CheckOutputFormat::Json => println!("{}", check_ok_json(config_path, &config)),
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            match format {
                CheckOutputFormat::Text => eprintln!("alighieri: {e}"),
                CheckOutputFormat::Json => {
                    println!(
                        "{{\"ok\":false,\"path\":\"{}\",\"error\":\"{}\"}}",
                        json_escape(&config_path.display().to_string()),
                        json_escape(&e.to_string())
                    );
                }
            }
            ExitCode::FAILURE
        }
    }
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
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
}

fn parse_config_command(args: Vec<String>) -> Result<ConfigCommand, String> {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        return Ok(ConfigCommand::Help);
    }
    let Some(command) = args.first().map(String::as_str) else {
        return Err(config_usage());
    };
    match command {
        "metadata" => {
            if args.get(1).map(String::as_str) == Some("--json") && args.len() == 2 {
                Ok(ConfigCommand::MetadataJson)
            } else if args.iter().skip(1).any(|arg| arg == "--json") {
                Err(config_usage())
            } else {
                Err("config metadata requires --json".into())
            }
        }
        "wizard" => {
            let wizard_args = wizard::parse_config_wizard_args(&args[1..])?;
            Ok(ConfigCommand::Wizard(wizard_args))
        }
        _ => Err(config_usage()),
    }
}

async fn handle_config(args: Vec<String>) -> ExitCode {
    match parse_config_command(args) {
        Ok(ConfigCommand::MetadataJson) => {
            println!("{}", config_metadata_json());
            ExitCode::SUCCESS
        }
        Ok(ConfigCommand::Wizard(args)) => match wizard::run_config_wizard(args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("alighieri: {e}");
                ExitCode::FAILURE
            }
        },
        Ok(ConfigCommand::Help) => {
            println!("{}", config_usage());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("alighieri: {e}");
            ExitCode::FAILURE
        }
    }
}

fn config_usage() -> String {
    "usage: alighieri config metadata --json | alighieri config wizard [--listen 127.0.0.1:PORT] [--output PATH]".into()
}

/// Reload metadata for every config setting, surfaced by
/// `config metadata --json`. Lists the canonical (documented) name of each
/// setting; the parser also accepts aliases (e.g. `proxy.protocol`,
/// `dns.try_all`, `tls.cert`), which are intentionally not repeated here. **When
/// you add a setting to the parser in `config.rs`, add it here too** (and to the
/// `expected` list in the `config_metadata_covers_every_setting` test). That
/// test checks every name here is a real setting key, matches the canonical list
/// it maintains, and has no duplicates — it cannot, however, notice a parser
/// setting that is left out of both, so the manual step matters.
const CONFIG_SETTINGS_METADATA: &[ConfigSettingMetadata] = &[
    ConfigSettingMetadata {
        name: "internal",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "listener address is bound when the process starts",
    },
    ConfigSettingMetadata {
        name: "egress",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "outbound transport and any RDP session bridge are initialised when the process starts",
    },
    ConfigSettingMetadata {
        name: "external",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "outbound bind address is used by newly accepted requests",
    },
    ConfigSettingMetadata {
        name: "proxyprotocol",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "trusted PROXY-protocol upstreams are consulted on new connections",
    },
    ConfigSettingMetadata {
        name: "socksmethod",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "offered authentication methods are used by new SOCKS handshakes",
    },
    ConfigSettingMetadata {
        name: "userlist",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "user database is reloaded before accepting new authenticated sessions",
    },
    ConfigSettingMetadata {
        name: "connecttimeout",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "timeout applies to newly accepted requests",
    },
    ConfigSettingMetadata {
        name: "handshaketimeout",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "timeout applies to newly accepted client connections",
    },
    ConfigSettingMetadata {
        name: "iotimeout",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "timeout applies to newly accepted relays",
    },
    ConfigSettingMetadata {
        name: "udptimeout",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "timeout applies to newly accepted UDP associations",
    },
    ConfigSettingMetadata {
        name: "udp.portrange",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "client-facing UDP relay port range is applied to new UDP associations",
    },
    ConfigSettingMetadata {
        name: "udp.strictreply",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "UDP reply matching mode is applied to new UDP associations",
    },
    ConfigSettingMetadata {
        name: "udp.advertise",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "advertised UDP ASSOCIATE reply address is applied to new UDP associations",
    },
    ConfigSettingMetadata {
        name: "shutdown.draintimeout",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "drain timeout is read from the startup configuration at shutdown; 0 cuts in-flight connections immediately (it is not an unlimited drain)",
    },
    ConfigSettingMetadata {
        name: "maxconnections",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "connection semaphore is created when the listener starts",
    },
    ConfigSettingMetadata {
        name: "logoutput",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "logging sinks are initialised when the process starts",
    },
    ConfigSettingMetadata {
        name: "logfile",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "file logging is initialised when the process starts",
    },
    ConfigSettingMetadata {
        name: "logformat",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "subscriber formatting is initialised when the process starts",
    },
    ConfigSettingMetadata {
        name: "logrotate.size",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "rotating file writer is initialised when the process starts",
    },
    ConfigSettingMetadata {
        name: "logrotate.keep",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "rotating file writer is initialised when the process starts",
    },
    ConfigSettingMetadata {
        name: "dns.prefer",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "DNS policy is used by newly accepted requests",
    },
    ConfigSettingMetadata {
        name: "dns.tryall",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "DNS policy is used by newly accepted requests",
    },
    ConfigSettingMetadata {
        name: "dns.deny",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "DNS policy is used by newly accepted requests",
    },
    ConfigSettingMetadata {
        name: "dns.cachettl",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "DNS cache settings are applied to newly accepted requests",
    },
    ConfigSettingMetadata {
        name: "dns.timeout",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "DNS lookup timeout is used by newly accepted requests",
    },
    ConfigSettingMetadata {
        name: "auth.cachettl",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "verified-credential cache TTL; reloads also clear the cache with the user database",
    },
    ConfigSettingMetadata {
        name: "auth.command",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "external auth command is used by newly authenticated sessions",
    },
    ConfigSettingMetadata {
        name: "metrics.listen",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "metrics listener is bound when the process starts",
    },
    ConfigSettingMetadata {
        name: "metrics.allowpublic",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "checked at startup when the metrics listener is bound",
    },
    ConfigSettingMetadata {
        name: "tls.certfile",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "TLS acceptor is initialised when the listener starts",
    },
    ConfigSettingMetadata {
        name: "tls.keyfile",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "TLS acceptor is initialised when the listener starts",
    },
    ConfigSettingMetadata {
        name: "tls.acme.domains",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "ACME acceptor is initialised when the listener starts",
    },
    ConfigSettingMetadata {
        name: "tls.acme.email",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "ACME acceptor is initialised when the listener starts",
    },
    ConfigSettingMetadata {
        name: "tls.acme.cache",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "ACME acceptor is initialised when the listener starts",
    },
    ConfigSettingMetadata {
        name: "tls.acme.staging",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "ACME acceptor is initialised when the listener starts",
    },
    ConfigSettingMetadata {
        name: "ratelimit.connectionrate",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "rate limit config is swapped during reload",
    },
    ConfigSettingMetadata {
        name: "ratelimit.authfailurerate",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "rate limit config is swapped during reload",
    },
    ConfigSettingMetadata {
        name: "ratelimit.concurrentconnections",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "rate limit config is swapped during reload",
    },
    ConfigSettingMetadata {
        name: "ratelimit.byterate",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "rate limit config is swapped during reload",
    },
    ConfigSettingMetadata {
        name: "client",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "client ACL rules are used for new client connections",
    },
    ConfigSettingMetadata {
        name: "socks",
        reload: ReloadBehavior::Live,
        applies_to: "new_connections",
        note: "SOCKS ACL rules are used for new SOCKS requests",
    },
    ConfigSettingMetadata {
        name: "include",
        reload: ReloadBehavior::Live,
        applies_to: "next_reload",
        note: "included files are re-read when the configuration is loaded",
    },
];

fn config_metadata_json() -> String {
    let mut json = String::from("{\"version\":1,\"settings\":[");
    for (index, setting) in CONFIG_SETTINGS_METADATA.iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        json.push_str(&format!(
            "{{\"name\":\"{}\",\"reload\":\"{}\",\"applies_to\":\"{}\",\"note\":\"{}\"}}",
            json_escape(setting.name),
            setting.reload.as_str(),
            json_escape(setting.applies_to),
            json_escape(setting.note)
        ));
    }
    json.push_str("]}");
    json
}

async fn run_console(config_path: PathBuf) -> ExitCode {
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("alighieri: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Held for the life of the process; dropping it flushes queued records.
    let _log_guard = match init_console_logging(&config) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("alighieri: failed to initialise logging: {e}");
            return ExitCode::FAILURE;
        }
    };

    info!(
        config = %config_path.display(),
        listen = %config.internal,
        external = %config.external,
        rules = config.rules.rules.len(),
        "starting Alighieri"
    );

    if let Err(e) = run_server_reloading_until_shutdown(
        config_path.clone(),
        shutdown_signal(),
        reload_signal_channel(),
    )
    .await
    {
        error!(error = %e, "server exited with error");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

#[cfg(windows)]
async fn handle_service(args: Vec<String>) -> ExitCode {
    match alighieri::platform::windows::handle_service_cli(args) {
        Ok(message) => {
            if !message.is_empty() {
                println!("{message}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("alighieri: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
async fn handle_service(_args: Vec<String>) -> ExitCode {
    eprintln!("alighieri: Windows Service commands are only available on Windows");
    ExitCode::FAILURE
}

#[derive(Debug, PartialEq, Eq)]
enum UserTarget {
    Userlist(PathBuf),
    Config(PathBuf),
}

#[derive(Debug, PartialEq, Eq)]
enum UserCommand {
    Add {
        username: String,
        target: UserTarget,
        password_stdin: bool,
        json: bool,
    },
    Delete {
        username: String,
        target: UserTarget,
        if_present: bool,
        json: bool,
    },
    List {
        target: UserTarget,
        json: bool,
    },
    Verify {
        username: String,
        target: UserTarget,
        password_stdin: bool,
        json: bool,
    },
    Help,
}

#[derive(Default)]
struct UserOptions {
    target: Option<UserTarget>,
    password_stdin: bool,
    if_present: bool,
    json: bool,
    help: bool,
}

fn parse_user_command(args: Vec<String>) -> Result<UserCommand, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(user_usage());
    };
    if is_help_arg(command) {
        if args.iter().skip(1).any(|arg| arg == "--json") {
            return Err("--json cannot be combined with user help".into());
        }
        return Ok(UserCommand::Help);
    }

    match command {
        "add" | "delete" | "verify" => {
            let username = args
                .get(1)
                .cloned()
                .ok_or_else(|| format!("{command} requires USER"))?;
            if is_user_option_token(&username) {
                return Err(format!("{command} requires USER"));
            }
            if args.len() == 2 && is_help_arg(&username) {
                return Ok(UserCommand::Help);
            }
            let options = parse_user_options(&args[2..])?;
            if options.help {
                return Ok(UserCommand::Help);
            }
            let target = options.target.ok_or_else(missing_user_target_error)?;
            match command {
                "add" => {
                    if options.if_present {
                        return Err("--if-present is valid only for user delete".into());
                    }
                    Ok(UserCommand::Add {
                        username,
                        target,
                        password_stdin: options.password_stdin,
                        json: options.json,
                    })
                }
                "delete" => {
                    if options.password_stdin {
                        return Err("--password-stdin is valid only for user add and verify".into());
                    }
                    Ok(UserCommand::Delete {
                        username,
                        target,
                        if_present: options.if_present,
                        json: options.json,
                    })
                }
                "verify" => {
                    if options.if_present {
                        return Err("--if-present is valid only for user delete".into());
                    }
                    Ok(UserCommand::Verify {
                        username,
                        target,
                        password_stdin: options.password_stdin,
                        json: options.json,
                    })
                }
                _ => unreachable!(),
            }
        }
        "list" => {
            let options = parse_user_options(&args[1..])?;
            if options.help {
                return Ok(UserCommand::Help);
            }
            if options.password_stdin {
                return Err("--password-stdin is valid only for user add and verify".into());
            }
            if options.if_present {
                return Err("--if-present is valid only for user delete".into());
            }
            Ok(UserCommand::List {
                target: options.target.ok_or_else(missing_user_target_error)?,
                json: options.json,
            })
        }
        _ if args.iter().skip(1).any(|arg| is_help_arg(arg))
            && !args.iter().any(|arg| arg == "--json") =>
        {
            Ok(UserCommand::Help)
        }
        _ => Err(user_usage()),
    }
}

fn parse_user_options(args: &[String]) -> Result<UserOptions, String> {
    let mut options = UserOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--userlist" | "--config" => {
                let option = args[index].as_str();
                let Some(path) = args.get(index + 1) else {
                    return Err(format!("{option} requires a path"));
                };
                if is_user_option_token(path) {
                    return Err(format!("{option} requires a path"));
                }
                if options.target.is_some() {
                    return Err(
                        "--userlist and --config are mutually exclusive and may be supplied only once"
                            .into(),
                    );
                }
                options.target = Some(if option == "--userlist" {
                    UserTarget::Userlist(PathBuf::from(path))
                } else {
                    UserTarget::Config(PathBuf::from(path))
                });
                index += 2;
            }
            "--password-stdin" => {
                if options.password_stdin {
                    return Err("duplicate option '--password-stdin'".into());
                }
                options.password_stdin = true;
                index += 1;
            }
            "--if-present" => {
                if options.if_present {
                    return Err("duplicate option '--if-present'".into());
                }
                options.if_present = true;
                index += 1;
            }
            "--json" => {
                if options.json {
                    return Err("duplicate option '--json'".into());
                }
                options.json = true;
                index += 1;
            }
            "-h" | "--help" => {
                options.help = true;
                index += 1;
            }
            _ => return Err("unknown user option".into()),
        }
    }
    if options.help && options.json {
        return Err("--json cannot be combined with user help".into());
    }
    Ok(options)
}

fn missing_user_target_error() -> String {
    "exactly one of --userlist PATH or --config CONFIG is required".into()
}

fn is_help_arg(arg: &str) -> bool {
    arg == "-h" || arg == "--help"
}

fn is_user_option_token(arg: &str) -> bool {
    matches!(
        arg,
        "--userlist" | "--config" | "--password-stdin" | "--if-present" | "--json"
    )
}

fn user_operation(args: &[String]) -> &'static str {
    match args.first().map(String::as_str) {
        Some("add") => "user.add",
        Some("delete") => "user.delete",
        Some("list") => "user.list",
        Some("verify") => "user.verify",
        _ => "user",
    }
}

fn handle_user(args: Vec<String>) -> ExitCode {
    let json_requested = args.iter().any(|arg| arg == "--json");
    let operation = user_operation(&args);
    match parse_user_command(args) {
        Ok(UserCommand::Add {
            username,
            target,
            password_stdin,
            json,
        }) => add_user(username, target, password_stdin, json),
        Ok(UserCommand::Delete {
            username,
            target,
            if_present,
            json,
        }) => delete_user(username, target, if_present, json),
        Ok(UserCommand::List { target, json }) => list_users(target, json),
        Ok(UserCommand::Verify {
            username,
            target,
            password_stdin,
            json,
        }) => verify_user(username, target, password_stdin, json),
        Ok(UserCommand::Help) => {
            println!("{}", user_usage());
            ExitCode::SUCCESS
        }
        Err(error) if json_requested => management::emit_error(
            operation,
            ManagementError::new(ManagementErrorCode::InvalidArguments, error),
        ),
        Err(error) => {
            eprintln!("alighieri: {error}");
            ExitCode::FAILURE
        }
    }
}

struct ResolvedUserTarget {
    userlist: PathBuf,
    config: Option<PathBuf>,
    creation_policy: UserlistCreationPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserlistCreationPolicy {
    // Preserve the legacy direct-path behavior for ad-hoc userlists.
    Private,
    // The managed installer makes the selected config root:alighieri 0640.
    // Match that exact identity before bootstrapping so ACL-based or custom
    // layouts cannot receive a misleading success or broader hash visibility.
    ConfigBacked {
        #[cfg(unix)]
        uid: u32,
        #[cfg(unix)]
        gid: u32,
        #[cfg(unix)]
        managed_bootstrap: bool,
    },
}

#[cfg(target_os = "linux")]
fn managed_service_group_gid() -> std::io::Result<Option<u32>> {
    const INITIAL_BUFFER_SIZE: usize = 1_024;
    const MAX_BUFFER_SIZE: usize = 1_048_576;

    let mut group: libc::group = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0 as libc::c_char; INITIAL_BUFFER_SIZE];
    loop {
        let status = unsafe {
            libc::getgrnam_r(
                c"alighieri".as_ptr(),
                &mut group,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if status == 0 {
            return if result.is_null() {
                Ok(None)
            } else {
                Ok(Some(group.gr_gid))
            };
        }
        if status != libc::ERANGE {
            return Err(std::io::Error::from_raw_os_error(status));
        }
        if buffer.len() >= MAX_BUFFER_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "alighieri service group record exceeds the lookup limit",
            ));
        }
        buffer.resize(buffer.len() * 2, 0);
    }
}

#[cfg(unix)]
fn supports_managed_userlist_bootstrap(
    is_regular_file: bool,
    has_no_access_acl: bool,
    uid: u32,
    gid: u32,
    mode: u32,
    expected_uid: u32,
    service_gid: Option<u32>,
) -> bool {
    is_regular_file
        && has_no_access_acl
        && uid == expected_uid
        && service_gid == Some(gid)
        && mode == 0o640
}

impl UserlistCreationPolicy {
    fn config_backed(config_path: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            #[cfg(target_os = "linux")]
            let service_gid = managed_service_group_gid().ok().flatten();
            #[cfg(not(target_os = "linux"))]
            let service_gid = None;

            Self::config_backed_with_expected_identity(config_path, 0, service_gid)
        }
        #[cfg(not(unix))]
        {
            let _ = config_path;
            Ok(Self::ConfigBacked {})
        }
    }

    #[cfg(unix)]
    fn config_backed_with_expected_identity(
        config_path: &Path,
        expected_uid: u32,
        service_gid: Option<u32>,
    ) -> std::io::Result<Self> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let path_metadata = std::fs::metadata(config_path)?;
        #[cfg(target_os = "linux")]
        let (metadata, has_no_access_acl) = if path_metadata.is_file() {
            use std::os::unix::fs::OpenOptionsExt;

            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            match options.open(config_path) {
                Ok(file) => {
                    let metadata = file.metadata()?;
                    let has_no_access_acl =
                        metadata.is_file() && matches!(linux_access_acl(&file), Ok(None));
                    (metadata, has_no_access_acl)
                }
                Err(_) => (path_metadata, false),
            }
        } else {
            // Avoid a blocking second open for FIFOs and other special config
            // sources. These can never authorize managed userlist creation.
            (path_metadata, false)
        };
        #[cfg(not(target_os = "linux"))]
        let metadata = path_metadata;
        let uid = metadata.uid();
        let gid = metadata.gid();
        let mode = metadata.permissions().mode() & 0o7777;
        #[cfg(not(target_os = "linux"))]
        let has_no_access_acl = false;
        Ok(Self::ConfigBacked {
            uid,
            gid,
            managed_bootstrap: cfg!(target_os = "linux")
                && supports_managed_userlist_bootstrap(
                    metadata.is_file(),
                    has_no_access_acl,
                    uid,
                    gid,
                    mode,
                    expected_uid,
                    service_gid,
                ),
        })
    }
}

impl ResolvedUserTarget {
    fn userlist_json(&self) -> String {
        self.userlist.display().to_string()
    }

    fn config_json(&self) -> Option<String> {
        self.config
            .as_deref()
            .map(|path| path.display().to_string())
    }
}

fn resolve_user_target(target: UserTarget) -> Result<ResolvedUserTarget, ManagementError> {
    match target {
        UserTarget::Userlist(userlist) => Ok(ResolvedUserTarget {
            userlist,
            config: None,
            creation_policy: UserlistCreationPolicy::Private,
        }),
        UserTarget::Config(config_path) => {
            let config = Config::load_user_management_facts(&config_path).map_err(|_| {
                ManagementError::new(
                    ManagementErrorCode::ConfigLoadFailed,
                    format!("failed to load configuration {}", config_path.display()),
                )
            })?;
            if !config.username_auth_active {
                return Err(ManagementError::new(
                    ManagementErrorCode::UserlistNotActive,
                    "username/password authentication is not active in the configuration",
                ));
            }
            if config.external_auth_backend {
                return Err(ManagementError::new(
                    ManagementErrorCode::ExternalAuthBackend,
                    "the configuration uses an external authentication backend",
                ));
            }
            let userlist = config.userlist.ok_or_else(|| {
                ManagementError::new(
                    ManagementErrorCode::UserlistNotConfigured,
                    "the configuration does not define a userlist",
                )
            })?;
            if !userlist.is_absolute() {
                return Err(ManagementError::new(
                    ManagementErrorCode::RelativeUserlistNotSupported,
                    "the effective userlist path must be absolute in --config mode",
                ));
            }
            let creation_policy =
                UserlistCreationPolicy::config_backed(&config_path).map_err(|_| {
                    ManagementError::new(
                        ManagementErrorCode::ConfigLoadFailed,
                        format!("failed to load configuration {}", config_path.display()),
                    )
                })?;
            Ok(ResolvedUserTarget {
                userlist,
                config: Some(config_path),
                creation_policy,
            })
        }
    }
}

fn user_failure(
    json: bool,
    operation: &'static str,
    error: ManagementError,
    human_message: String,
) -> ExitCode {
    if json {
        management::emit_error(operation, error)
    } else {
        eprintln!("alighieri: {human_message}");
        ExitCode::FAILURE
    }
}

fn validate_cli_username(
    username: &str,
    json: bool,
    operation: &'static str,
) -> Result<(), ExitCode> {
    UserDb::validate_username(username).map_err(|error| {
        user_failure(
            json,
            operation,
            ManagementError::new(ManagementErrorCode::InvalidUsername, error.to_string()),
            error.to_string(),
        )
    })
}

fn resolve_cli_target(
    target: UserTarget,
    json: bool,
    operation: &'static str,
) -> Result<ResolvedUserTarget, ExitCode> {
    resolve_user_target(target).map_err(|error| {
        let human = error.message.clone();
        user_failure(json, operation, error, human)
    })
}

fn read_cli_password(
    password_stdin: bool,
    confirm: bool,
    json: bool,
    operation: &'static str,
) -> Result<SecretString, ExitCode> {
    let password = if password_stdin {
        management::read_password_stdin()
    } else if confirm {
        prompt_password_twice()
    } else {
        rpassword::prompt_password("Password: ")
            .map(SecretString::new)
            .map_err(|error| {
                ManagementError::new(
                    ManagementErrorCode::InternalError,
                    format!("failed to read password: {error}"),
                )
            })
    };
    password.map_err(|error| {
        let human = error.message.clone();
        user_failure(json, operation, error, human)
    })
}

fn add_user(username: String, target: UserTarget, password_stdin: bool, json: bool) -> ExitCode {
    const OPERATION: &str = "user.add";
    if let Err(exit) = validate_cli_username(&username, json, OPERATION) {
        return exit;
    }
    let target = match resolve_cli_target(target, json, OPERATION) {
        Ok(target) => target,
        Err(exit) => return exit,
    };
    let password = match read_cli_password(password_stdin, true, json, OPERATION) {
        Ok(password) => password,
        Err(exit) => return exit,
    };
    if password.is_empty() {
        drop(password);
        return user_failure(
            json,
            OPERATION,
            ManagementError::new(
                ManagementErrorCode::InvalidPassword,
                "password must not be empty",
            ),
            "password must not be empty".into(),
        );
    }
    if let Err(error) = UserDb::validate_password(password.as_str()) {
        let human = error.to_string();
        drop(password);
        return user_failure(
            json,
            OPERATION,
            ManagementError::new(
                ManagementErrorCode::InvalidPassword,
                "password must not exceed 255 bytes",
            ),
            human,
        );
    }
    let line = match UserDb::hash_user_line(&username, password.as_str()) {
        Ok(line) => line,
        Err(error) => {
            let human = error.to_string();
            drop(password);
            return user_failure(
                json,
                OPERATION,
                ManagementError::new(
                    ManagementErrorCode::InternalError,
                    "failed to hash password",
                ),
                human,
            );
        }
    };
    drop(password);

    let outcome =
        match upsert_userlist_entry(&target.userlist, &username, &line, target.creation_policy) {
            Ok(outcome) => outcome,
            Err(error) => {
                let code = error.management_code();
                let action = if code == ManagementErrorCode::UserlistReadFailed {
                    "read"
                } else {
                    "update"
                };
                return user_failure(
                    json,
                    OPERATION,
                    ManagementError::new(
                        code,
                        format!("failed to {action} userlist {}", target.userlist.display()),
                    ),
                    format!("failed to update {}: {error}", target.userlist.display()),
                );
            }
        };
    if json {
        management::emit_success(
            OPERATION,
            AddResult {
                username,
                userlist: target.userlist_json(),
                config: target.config_json(),
                action: outcome.as_str(),
                changed: true,
            },
        )
    } else {
        println!(
            "alighieri: updated user '{username}' in {}",
            target.userlist.display()
        );
        ExitCode::SUCCESS
    }
}

fn delete_user(username: String, target: UserTarget, if_present: bool, json: bool) -> ExitCode {
    const OPERATION: &str = "user.delete";
    if let Err(exit) = validate_cli_username(&username, json, OPERATION) {
        return exit;
    }
    let target = match resolve_cli_target(target, json, OPERATION) {
        Ok(target) => target,
        Err(exit) => return exit,
    };
    let deleted = match delete_userlist_entry(&target.userlist, &username) {
        Ok(deleted) => deleted,
        Err(error) => {
            let code = error.management_code();
            let action = if code == ManagementErrorCode::UserlistReadFailed {
                "read"
            } else {
                "update"
            };
            return user_failure(
                json,
                OPERATION,
                ManagementError::new(
                    code,
                    format!("failed to {action} userlist {}", target.userlist.display()),
                ),
                format!("failed to update {}: {error}", target.userlist.display()),
            );
        }
    };
    if !deleted && !if_present {
        return user_failure(
            json,
            OPERATION,
            ManagementError::new(
                ManagementErrorCode::UserNotFound,
                "user was not found in the userlist",
            ),
            format!(
                "user '{username}' was not found in {}",
                target.userlist.display()
            ),
        );
    }
    if json {
        management::emit_success(
            OPERATION,
            DeleteResult {
                username,
                userlist: target.userlist_json(),
                config: target.config_json(),
                deleted,
                changed: deleted,
            },
        )
    } else {
        if deleted {
            println!(
                "alighieri: removed user '{username}' from {}",
                target.userlist.display()
            );
        } else {
            println!(
                "alighieri: user '{username}' was already absent from {}",
                target.userlist.display()
            );
        }
        ExitCode::SUCCESS
    }
}

fn list_users(target: UserTarget, json: bool) -> ExitCode {
    const OPERATION: &str = "user.list";
    let target = match resolve_cli_target(target, json, OPERATION) {
        Ok(target) => target,
        Err(exit) => return exit,
    };
    let text = match std::fs::read_to_string(&target.userlist) {
        Ok(text) => text,
        Err(error) => {
            return user_failure(
                json,
                OPERATION,
                ManagementError::new(
                    ManagementErrorCode::UserlistReadFailed,
                    format!("failed to read userlist {}", target.userlist.display()),
                ),
                format!("failed to read {}: {error}", target.userlist.display()),
            )
        }
    };
    let usernames = match userlist_usernames(&text) {
        Ok(usernames) => usernames,
        Err(error) => {
            return user_failure(
                json,
                OPERATION,
                ManagementError::new(
                    ManagementErrorCode::UserlistParseFailed,
                    "userlist is malformed",
                ),
                error.to_string(),
            )
        }
    };
    if json {
        management::emit_success(
            OPERATION,
            ListResult {
                userlist: target.userlist_json(),
                config: target.config_json(),
                count: usernames.len(),
                users: usernames,
            },
        )
    } else {
        for username in usernames {
            println!("{username}");
        }
        ExitCode::SUCCESS
    }
}

fn verify_user(username: String, target: UserTarget, password_stdin: bool, json: bool) -> ExitCode {
    const OPERATION: &str = "user.verify";
    if let Err(exit) = validate_cli_username(&username, json, OPERATION) {
        return exit;
    }
    let target = match resolve_cli_target(target, json, OPERATION) {
        Ok(target) => target,
        Err(exit) => return exit,
    };
    let text = match std::fs::read_to_string(&target.userlist) {
        Ok(text) => text,
        Err(error) => {
            return user_failure(
                json,
                OPERATION,
                ManagementError::new(
                    ManagementErrorCode::UserlistReadFailed,
                    format!("failed to read userlist {}", target.userlist.display()),
                ),
                format!("failed to read {}: {error}", target.userlist.display()),
            )
        }
    };
    let db = match UserDb::parse(&text) {
        Ok(db) => db,
        Err(error) => {
            return user_failure(
                json,
                OPERATION,
                ManagementError::new(
                    ManagementErrorCode::UserlistParseFailed,
                    "userlist is malformed",
                ),
                error.to_string(),
            )
        }
    };
    let password = match read_cli_password(password_stdin, false, json, OPERATION) {
        Ok(password) => password,
        Err(exit) => return exit,
    };
    if password_stdin {
        if let Err(error) = UserDb::validate_password(password.as_str()) {
            let human = error.to_string();
            drop(password);
            return user_failure(
                json,
                OPERATION,
                ManagementError::new(
                    ManagementErrorCode::InvalidPassword,
                    "password must not exceed 255 bytes",
                ),
                human,
            );
        }
    }
    let verified = db.verify(&username, password.as_str());
    drop(password);
    if !verified {
        return user_failure(
            json,
            OPERATION,
            ManagementError::new(
                ManagementErrorCode::CredentialsRejected,
                "password verification failed",
            ),
            "password verification failed".into(),
        );
    }
    if json {
        management::emit_success(
            OPERATION,
            VerifyResult {
                username,
                userlist: target.userlist_json(),
                config: target.config_json(),
                verified: true,
            },
        )
    } else {
        println!("alighieri: password verified");
        ExitCode::SUCCESS
    }
}

fn prompt_password_twice() -> Result<SecretString, ManagementError> {
    prompt_password_twice_with(|prompt| {
        rpassword::prompt_password(prompt).map_err(|error| error.to_string())
    })
}

fn prompt_password_twice_with(
    mut prompt: impl FnMut(&str) -> Result<String, String>,
) -> Result<SecretString, ManagementError> {
    let password = SecretString::new(prompt("Password: ").map_err(|error| {
        ManagementError::new(
            ManagementErrorCode::InternalError,
            format!("failed to read password: {error}"),
        )
    })?);
    let confirm = SecretString::new(prompt("Confirm password: ").map_err(|error| {
        ManagementError::new(
            ManagementErrorCode::InternalError,
            format!("failed to read password confirmation: {error}"),
        )
    })?);
    if password.as_str() != confirm.as_str() {
        return Err(ManagementError::new(
            ManagementErrorCode::InvalidPassword,
            "passwords do not match",
        ));
    }
    if password.is_empty() {
        return Err(ManagementError::new(
            ManagementErrorCode::InvalidPassword,
            "password must not be empty",
        ));
    }
    Ok(password)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpsertOutcome {
    Created,
    Updated,
}

impl UpsertOutcome {
    fn as_str(self) -> &'static str {
        match self {
            UpsertOutcome::Created => "created",
            UpsertOutcome::Updated => "updated",
        }
    }
}

#[derive(Debug)]
enum UserlistMutationError {
    Read(std::io::Error),
    Update(std::io::Error),
}

impl UserlistMutationError {
    fn management_code(&self) -> ManagementErrorCode {
        match self {
            UserlistMutationError::Read(_) => ManagementErrorCode::UserlistReadFailed,
            UserlistMutationError::Update(_) => ManagementErrorCode::UserlistUpdateFailed,
        }
    }
}

impl std::fmt::Display for UserlistMutationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserlistMutationError::Read(error) | UserlistMutationError::Update(error) => {
                error.fmt(formatter)
            }
        }
    }
}

impl std::error::Error for UserlistMutationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UserlistMutationError::Read(error) | UserlistMutationError::Update(error) => {
                Some(error)
            }
        }
    }
}

fn upsert_userlist_entry(
    userlist: &Path,
    username: &str,
    line: &str,
    creation_policy: UserlistCreationPolicy,
) -> Result<UpsertOutcome, UserlistMutationError> {
    // Preserve recursive parent creation for the legacy direct-path workflow.
    // Config-backed targets must use a pre-provisioned directory: creating that
    // ancestry with the elevated caller's umask or inherited ACL could leave
    // the service unable to traverse to the correctly protected userlist.
    if creation_policy == UserlistCreationPolicy::Private {
        if let Some(parent) = userlist.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(UserlistMutationError::Update)?;
            }
        }
    }
    let _lock = acquire_userlist_lock(userlist).map_err(UserlistMutationError::Update)?;
    let (existing, existed) = match std::fs::read_to_string(userlist) {
        Ok(text) => (text, true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), false),
        Err(error) => return Err(UserlistMutationError::Read(error)),
    };
    let mut replaced = false;
    let mut lines = Vec::new();
    for existing_line in existing.lines() {
        if UserDb::entry_username(existing_line)
            .is_some_and(|existing_user| existing_user == username)
        {
            lines.push(line.to_string());
            replaced = true;
        } else {
            lines.push(existing_line.to_string());
        }
    }
    if !replaced {
        lines.push(line.to_string());
    }
    let mut output = lines.join("\n");
    output.push('\n');
    write_userlist(userlist, output.as_bytes(), existed, creation_policy)
        .map_err(UserlistMutationError::Update)?;
    Ok(if replaced {
        UpsertOutcome::Updated
    } else {
        UpsertOutcome::Created
    })
}

fn delete_userlist_entry(userlist: &Path, username: &str) -> Result<bool, UserlistMutationError> {
    let _lock = acquire_userlist_lock(userlist).map_err(UserlistMutationError::Update)?;
    let existing = std::fs::read_to_string(userlist).map_err(UserlistMutationError::Read)?;
    let mut removed = false;
    let mut lines = Vec::new();
    for existing_line in existing.lines() {
        if UserDb::entry_username(existing_line)
            .is_some_and(|existing_user| existing_user == username)
        {
            removed = true;
        } else {
            lines.push(existing_line.to_string());
        }
    }
    if !removed {
        return Ok(false);
    }

    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    write_userlist(
        userlist,
        output.as_bytes(),
        true,
        UserlistCreationPolicy::Private,
    )
    .map_err(UserlistMutationError::Update)?;
    Ok(true)
}

fn userlist_usernames(text: &str) -> alighieri::errors::Result<Vec<String>> {
    use std::collections::BTreeSet;

    // Parse with the same loader used at server startup before producing the
    // friendly sorted view. In particular, do not let `user list` silently
    // skip malformed plaintext lines or invalid Argon2 directives: lifecycle
    // tooling uses this non-interactive command as its startup preflight.
    UserDb::parse(text)?;
    let mut users = BTreeSet::new();
    for line in text.lines() {
        if let Some(username) = UserDb::entry_username(line) {
            users.insert(username);
        }
    }
    Ok(users.into_iter().collect())
}

#[derive(Debug)]
struct UserlistLock {
    file: std::fs::File,
}

impl Drop for UserlistLock {
    fn drop(&mut self) {
        let _ = unlock_userlist_file(&self.file);
    }
}

/// Rejects a userlist `.lock` path that already exists as a symlink. The lock is
/// created in the userlist's own directory; if an attacker can write there, a
/// pre-placed symlink would otherwise be truncated (the lock's `set_len(0)`)
/// when `alighieri user ...` runs with elevated privileges. The lock open also
/// passes `O_NOFOLLOW` on Unix to make this atomic. This catches the
/// file-redirect vector on both platforms (`is_symlink` is true for Unix
/// symlinks and Windows file symlinks); Windows junctions are directory-only
/// reparse points and so cannot redirect a file sidecar. The temporary file and
/// the backup are protected differently — the temp uses `create_new` (`O_EXCL`)
/// and the backup is renamed into place (which replaces a link rather than
/// following it).
fn reject_symlink_sidecar(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to use userlist sidecar that is a symlink: {}",
                path.display()
            ),
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn acquire_userlist_lock(userlist: &Path) -> std::io::Result<UserlistLock> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let path = userlist_lock_path(userlist);
    reject_symlink_sidecar(&path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Atomically refuse to open the lock if it is (or races into being) a
        // symlink, closing the TOCTOU window the check above leaves open.
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&path)?;
    lock_userlist_file(&file)?;
    file.set_len(0)?;
    writeln!(file, "pid={}", std::process::id())?;
    file.sync_all()?;
    Ok(UserlistLock { file })
}

fn userlist_lock_path(userlist: &Path) -> PathBuf {
    use std::ffi::{OsStr, OsString};

    let parent = userlist
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = userlist.file_name().unwrap_or_else(|| OsStr::new("users"));

    let mut lock_name = OsString::from(".");
    lock_name.push(file_name);
    lock_name.push(".lock");
    parent.join(lock_name)
}

#[cfg(unix)]
fn lock_userlist_file(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock_userlist_file(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn lock_userlist_file(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn unlock_userlist_file(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let ok = unsafe { UnlockFileEx(file.as_raw_handle(), 0, u32::MAX, u32::MAX, &mut overlapped) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn lock_userlist_file(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn unlock_userlist_file(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_userlist(
    userlist: &Path,
    contents: &[u8],
    existed: bool,
    creation_policy: UserlistCreationPolicy,
) -> std::io::Result<()> {
    write_userlist_atomically(userlist, contents, existed, creation_policy)
}

#[cfg(windows)]
fn write_userlist(
    userlist: &Path,
    contents: &[u8],
    _existed: bool,
    creation_policy: UserlistCreationPolicy,
) -> std::io::Result<()> {
    write_userlist_atomically(userlist, contents, _existed, creation_policy)
}

#[cfg(not(any(unix, windows)))]
fn write_userlist(
    userlist: &Path,
    contents: &[u8],
    _existed: bool,
    creation_policy: UserlistCreationPolicy,
) -> std::io::Result<()> {
    write_userlist_atomically(userlist, contents, _existed, creation_policy)
}

fn write_userlist_atomically(
    userlist: &Path,
    contents: &[u8],
    existed: bool,
    creation_policy: UserlistCreationPolicy,
) -> std::io::Result<()> {
    use std::io::Write;

    let (temp_path, mut file) = create_userlist_temp(userlist, existed, creation_policy)?;
    let write_result = file.write_all(contents).and_then(|_| file.sync_all());
    drop(file);

    let result = write_result
        .and_then(|_| backup_userlist(userlist, existed))
        .and_then(|_| replace_userlist(&temp_path, userlist, existed))
        .and_then(|_| sync_userlist_parent(userlist));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

/// Opens `path` read-only, refusing a final-component symlink: `O_NOFOLLOW` on
/// Unix, and `FILE_FLAG_OPEN_REPARSE_POINT` on Windows (which opens a
/// symlink/reparse point itself instead of following it, so the caller's
/// `is_file()` check then rejects it). Backup sources are opened this way so a
/// symlinked target path cannot redirect the copy to an arbitrary file. Shared
/// by the userlist and config-wizard backups.
pub(crate) fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn backup_userlist(userlist: &Path, existed: bool) -> std::io::Result<()> {
    if !existed {
        return Ok(());
    }
    let backup = userlist_backup_path(userlist);
    // Open the backup *source* first and no-follow: a symlinked `userlist` path
    // could otherwise redirect the copy to an arbitrary target file, streaming
    // its contents (e.g. credentials) into `.bak` under a privileged run. Back up
    // only a regular file. (The `.bak` *destination* is separately protected by
    // the temp + rename below.)
    let mut source = open_no_follow(userlist)?;
    if !source.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to back up {}: not a regular file",
                userlist.display()
            ),
        ));
    }
    // Stream into a fresh temp file (`create_new` / `O_EXCL`, so it cannot follow
    // a pre-placed symlink), then atomically rename it over `.bak`. `rename`
    // replaces the destination link itself rather than writing through it. The
    // temp inherits the userlist's mode/uid/gid on Unix (via
    // `create_userlist_temp`); on Windows it inherits the parent directory ACL,
    // as the previous `fs::copy` did.
    let (temp_path, mut temp_file) =
        create_userlist_temp(userlist, existed, UserlistCreationPolicy::Private)?;
    let write_result = (|| -> std::io::Result<()> {
        std::io::copy(&mut source, &mut temp_file)?;
        temp_file.sync_all()
    })();
    drop(temp_file);
    if let Err(e) = write_result.and_then(|()| std::fs::rename(&temp_path, &backup)) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    Ok(())
}

fn userlist_backup_path(userlist: &Path) -> PathBuf {
    use std::ffi::{OsStr, OsString};

    let parent = userlist
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = userlist.file_name().unwrap_or_else(|| OsStr::new("users"));

    let mut backup_name = OsString::from(file_name);
    backup_name.push(".bak");
    parent.join(backup_name)
}

fn create_userlist_temp(
    userlist: &Path,
    _existed: bool,
    _creation_policy: UserlistCreationPolicy,
) -> std::io::Result<(PathBuf, std::fs::File)> {
    use std::fs::OpenOptions;

    #[cfg(unix)]
    let metadata = userlist_unix_metadata(userlist, _existed, _creation_policy)?;

    for _ in 0..100 {
        let temp_path = next_userlist_temp_path(userlist);
        let mut options = OpenOptions::new();
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
                    if let Err(error) = apply_userlist_unix_metadata(&temp_path, &file, &metadata) {
                        drop(file);
                        let _ = std::fs::remove_file(&temp_path);
                        return Err(error);
                    }
                }
                return Ok((temp_path, file));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to create unique temporary userlist path",
    ))
}

fn next_userlist_temp_path(userlist: &Path) -> PathBuf {
    use std::ffi::{OsStr, OsString};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = userlist
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = userlist.file_name().unwrap_or_else(|| OsStr::new("users"));
    let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut temp_name = OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".tmp-{}-{nonce}", std::process::id()));
    parent.join(temp_name)
}

#[cfg(unix)]
struct UserlistUnixMetadata {
    mode: u32,
    uid: u32,
    gid: u32,
    #[cfg(target_os = "linux")]
    access_acl: Option<Vec<u8>>,
}

#[cfg(unix)]
fn userlist_unix_metadata(
    userlist: &Path,
    existed: bool,
    creation_policy: UserlistCreationPolicy,
) -> std::io::Result<UserlistUnixMetadata> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if existed {
        let file = open_no_follow(userlist)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to update {}: not a regular file",
                    userlist.display()
                ),
            ));
        }
        Ok(UserlistUnixMetadata {
            mode: metadata.permissions().mode() & 0o777,
            uid: metadata.uid(),
            gid: metadata.gid(),
            #[cfg(target_os = "linux")]
            access_acl: linux_access_acl(&file)?,
        })
    } else {
        match creation_policy {
            UserlistCreationPolicy::Private => Ok(UserlistUnixMetadata {
                mode: 0o600,
                uid: u32::MAX,
                gid: u32::MAX,
                #[cfg(target_os = "linux")]
                access_acl: None,
            }),
            UserlistCreationPolicy::ConfigBacked {
                uid,
                gid,
                managed_bootstrap,
            } => {
                if !managed_bootstrap {
                    #[cfg(target_os = "linux")]
                    let message = "config-backed userlist auto-creation requires a regular config \
                                   owned by root:alighieri with mode 0640 and no extended access \
                                   ACL; pre-create the userlist for other ownership or ACL layouts";
                    #[cfg(not(target_os = "linux"))]
                    let message = "config-backed userlist auto-creation is supported only on \
                                   Linux; pre-create the userlist on this platform";
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        message,
                    ));
                }
                Ok(UserlistUnixMetadata {
                    mode: 0o640,
                    uid,
                    gid,
                    #[cfg(target_os = "linux")]
                    access_acl: None,
                })
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_access_acl(file: &std::fs::File) -> std::io::Result<Option<Vec<u8>>> {
    use std::os::unix::io::AsRawFd;

    const XATTR_SIZE_MAX: usize = 65_536;

    let mut value = vec![0_u8; XATTR_SIZE_MAX];
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if size >= 0 {
        value.truncate(size as usize);
        return Ok(Some(value));
    }

    let error = std::io::Error::last_os_error();
    if linux_acl_missing_or_unsupported(&error) {
        Ok(None)
    } else {
        Err(error)
    }
}

#[cfg(target_os = "linux")]
fn linux_acl_missing_or_unsupported(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENODATA) || error.raw_os_error() == Some(libc::EOPNOTSUPP)
}

#[cfg(target_os = "linux")]
fn set_linux_access_acl(file: &std::fs::File, access_acl: Option<&[u8]>) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let status = match access_acl {
        Some(value) => unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c"system.posix_acl_access".as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        },
        None => unsafe {
            libc::fremovexattr(file.as_raw_fd(), c"system.posix_acl_access".as_ptr())
        },
    };
    if status == 0 {
        return Ok(());
    }

    let error = std::io::Error::last_os_error();
    if access_acl.is_none() && linux_acl_missing_or_unsupported(&error) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(unix)]
fn apply_userlist_unix_metadata(
    _temp_path: &Path,
    file: &std::fs::File,
    metadata: &UserlistUnixMetadata,
) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;

    #[cfg(target_os = "linux")]
    set_linux_access_acl(file, None)?;

    if metadata.uid != u32::MAX || metadata.gid != u32::MAX {
        let current = file.metadata()?;
        if current.uid() != metadata.uid || current.gid() != metadata.gid {
            let rc = unsafe { libc::fchown(file.as_raw_fd(), metadata.uid, metadata.gid) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    file.set_permissions(std::fs::Permissions::from_mode(metadata.mode))?;
    #[cfg(target_os = "linux")]
    if let Some(access_acl) = metadata.access_acl.as_deref() {
        set_linux_access_acl(file, Some(access_acl))?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_userlist(temp_path: &Path, userlist: &Path, _existed: bool) -> std::io::Result<()> {
    std::fs::rename(temp_path, userlist)
}

#[cfg(windows)]
fn replace_userlist(temp_path: &Path, userlist: &Path, existed: bool) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        REPLACEFILE_WRITE_THROUGH,
    };

    let from: Vec<u16> = temp_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = userlist.as_os_str().encode_wide().chain(Some(0)).collect();
    let ok = if existed {
        unsafe {
            ReplaceFileW(
                to.as_ptr(),
                from.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        }
    } else {
        unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_userlist_parent(userlist: &Path) -> std::io::Result<()> {
    let parent = userlist
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_userlist_parent(_userlist: &Path) -> std::io::Result<()> {
    Ok(())
}

fn user_usage() -> String {
    "usage:\n    alighieri user add USER (--userlist PATH | --config CONFIG) [--password-stdin] [--json]\n    alighieri user delete USER (--userlist PATH | --config CONFIG) [--if-present] [--json]\n    alighieri user list (--userlist PATH | --config CONFIG) [--json]\n    alighieri user verify USER (--userlist PATH | --config CONFIG) [--password-stdin] [--json]"
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn test_posix_acl(owner_permissions: u16, named_uid: u32) -> Vec<u8> {
        const ACL_USER_OBJ: u16 = 0x01;
        const ACL_USER: u16 = 0x02;
        const ACL_GROUP_OBJ: u16 = 0x04;
        const ACL_MASK: u16 = 0x10;
        const ACL_OTHER: u16 = 0x20;
        const ACL_UNDEFINED_ID: u32 = u32::MAX;

        let entries = [
            (ACL_USER_OBJ, owner_permissions, ACL_UNDEFINED_ID),
            (ACL_USER, 0o4, named_uid),
            (ACL_GROUP_OBJ, 0, ACL_UNDEFINED_ID),
            (ACL_MASK, 0o4, ACL_UNDEFINED_ID),
            (ACL_OTHER, 0, ACL_UNDEFINED_ID),
        ];
        let mut value = Vec::with_capacity(4 + entries.len() * 8);
        value.extend_from_slice(&2_u32.to_le_bytes());
        for (tag, permissions, id) in entries {
            value.extend_from_slice(&tag.to_le_bytes());
            value.extend_from_slice(&permissions.to_le_bytes());
            value.extend_from_slice(&id.to_le_bytes());
        }
        value
    }

    #[cfg(target_os = "linux")]
    fn set_test_linux_xattr(
        file: &std::fs::File,
        name: &std::ffi::CStr,
        value: &[u8],
    ) -> std::io::Result<()> {
        use std::os::unix::io::AsRawFd;

        let status = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "linux")]
    fn acl_test_unavailable(error: &std::io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(libc::EOPNOTSUPP | libc::ENOSYS | libc::EPERM | libc::EACCES)
        )
    }

    #[cfg(unix)]
    #[test]
    fn acquire_userlist_lock_rejects_symlink_sidecar() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        let target = dir.path().join("secret");
        std::fs::write(&target, b"secret-contents").unwrap();
        // Attacker pre-places the lock path as a symlink to a sensitive file.
        symlink(&target, userlist_lock_path(&userlist)).unwrap();

        let err = acquire_userlist_lock(&userlist).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        // The symlink target must not have been truncated.
        assert_eq!(std::fs::read(&target).unwrap(), b"secret-contents");
    }

    #[cfg(unix)]
    #[test]
    fn backup_userlist_replaces_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        std::fs::write(&userlist, b"user:$argon2id$hash").unwrap();
        let target = dir.path().join("secret");
        std::fs::write(&target, b"secret-contents").unwrap();
        // Attacker pre-places the backup path as a symlink to a sensitive file.
        let bak = userlist_backup_path(&userlist);
        symlink(&target, &bak).unwrap();

        // The backup is written to a temp file and renamed into place, so it
        // succeeds while replacing the symlink rather than following it.
        backup_userlist(&userlist, true).unwrap();

        // The symlink target is untouched: credentials were not written through.
        assert_eq!(std::fs::read(&target).unwrap(), b"secret-contents");
        // The backup is now a real file (the link was replaced) with the
        // userlist content.
        assert!(!std::fs::symlink_metadata(&bak)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&bak).unwrap(), b"user:$argon2id$hash");
    }

    #[cfg(unix)]
    #[test]
    fn backup_userlist_refuses_a_symlinked_source() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"secret-contents").unwrap();
        // The userlist path itself is a symlink to a sensitive file.
        let userlist = dir.path().join("users");
        symlink(&secret, &userlist).unwrap();

        // Backing up must refuse to follow the symlink to its target.
        assert!(backup_userlist(&userlist, true).is_err());
        // It fails before any temp/backup is created, so no `.bak` exists at all.
        assert!(!userlist_backup_path(&userlist).exists());
    }

    #[test]
    fn config_flag_requires_value() {
        let err = parse_args_from(vec!["--config".into()]).unwrap_err();
        assert_eq!(err, "--config requires a path");
    }

    #[test]
    fn service_help_is_routed_to_service_parser() {
        let command =
            parse_args_from(vec!["service".into(), "install".into(), "--help".into()]).unwrap();
        assert_eq!(
            command,
            Command::Service {
                args: vec!["install".into(), "--help".into()]
            }
        );
    }

    #[test]
    fn capabilities_command_is_routed_before_config_paths() {
        assert_eq!(
            parse_args_from(vec!["capabilities".into(), "--json".into()]).unwrap(),
            Command::Capabilities {
                args: vec!["--json".into()]
            }
        );
    }

    #[test]
    fn config_metadata_command_is_routed_to_config_parser() {
        let command =
            parse_args_from(vec!["config".into(), "metadata".into(), "--json".into()]).unwrap();
        assert_eq!(
            command,
            Command::Config {
                args: vec!["metadata".into(), "--json".into()]
            }
        );
        assert_eq!(
            parse_config_command(vec!["metadata".into(), "--json".into()]).unwrap(),
            ConfigCommand::MetadataJson
        );
    }

    #[test]
    fn config_wizard_command_is_routed_to_config_parser() {
        let command = parse_args_from(vec![
            "config".into(),
            "wizard".into(),
            "--output".into(),
            "generated.conf".into(),
        ])
        .unwrap();
        assert!(matches!(command, Command::Config { .. }));
        assert!(matches!(
            parse_config_command(vec![
                "wizard".into(),
                "--listen".into(),
                "127.0.0.1:18080".into()
            ])
            .unwrap(),
            ConfigCommand::Wizard(_)
        ));
    }

    #[test]
    fn config_wizard_rejects_public_listener() {
        assert_eq!(
            parse_config_command(vec![
                "wizard".into(),
                "--listen".into(),
                "0.0.0.0:18080".into()
            ])
            .unwrap_err(),
            "config wizard must listen on a loopback address"
        );
    }

    #[test]
    fn positional_config_file_named_config_still_runs() {
        let command = parse_args_from(vec!["config".into()]).unwrap();
        assert_eq!(
            command,
            Command::Run {
                config_path: PathBuf::from("config")
            }
        );
    }

    #[test]
    fn config_metadata_requires_json_output() {
        assert_eq!(
            parse_config_command(vec!["metadata".into()]).unwrap_err(),
            "config metadata requires --json"
        );
    }

    #[test]
    fn config_metadata_extra_args_show_usage() {
        assert_eq!(
            parse_config_command(vec!["metadata".into(), "--json".into(), "extra".into()])
                .unwrap_err(),
            config_usage()
        );
    }

    #[test]
    fn config_metadata_json_describes_live_and_restart_settings() {
        let metadata = config_metadata_json();
        assert!(metadata.contains("\"name\":\"internal\",\"reload\":\"restart\""));
        assert!(metadata.contains("\"name\":\"egress\",\"reload\":\"restart\""));
        assert!(metadata.contains("\"name\":\"dns.prefer\",\"reload\":\"live\""));
        assert!(metadata.contains("\"name\":\"include\",\"reload\":\"live\""));
    }

    #[test]
    fn config_metadata_covers_every_setting() {
        use std::collections::BTreeSet;

        // Rule scopes and the `include` directive are listed in the metadata but
        // are not `key: value` settings, so they are checked separately from the
        // parser keys below.
        let scopes_and_directives: BTreeSet<&str> =
            ["client", "socks", "include"].into_iter().collect();

        // Collect names as a list first so a duplicate entry is caught here rather
        // than silently deduplicated (it would still emit a duplicate object in
        // the `config metadata --json` settings array).
        let all_names: Vec<&str> = CONFIG_SETTINGS_METADATA.iter().map(|s| s.name).collect();
        let unique_names: BTreeSet<&str> = all_names.iter().copied().collect();
        assert_eq!(
            all_names.len(),
            unique_names.len(),
            "config metadata contains duplicate entries"
        );

        let metadata_settings: BTreeSet<&str> = unique_names
            .into_iter()
            .filter(|name| !scopes_and_directives.contains(name))
            .collect();

        // Every name the metadata lists must be a real setting key: assigning it a
        // value yields some result, but never the parser's "unknown keyword".
        for name in &metadata_settings {
            if let Err(e) = Config::parse(&format!("internal: 127.0.0.1:1080\n{name}: x")) {
                assert!(
                    !e.to_string().contains("unknown keyword"),
                    "metadata lists '{name}', which the parser does not recognise"
                );
            }
        }

        // The canonical name of every `key: value` setting the parser accepts;
        // aliases (e.g. `proxy.protocol`, `dns.try_all`, `tls.cert`) are
        // intentionally not listed. When a new setting is added to the parser it
        // must be added here and to CONFIG_SETTINGS_METADATA, so
        // `config metadata --json` stays complete.
        let expected: BTreeSet<&str> = [
            "internal",
            "egress",
            "external",
            "proxyprotocol",
            "socksmethod",
            "connecttimeout",
            "handshaketimeout",
            "iotimeout",
            "udptimeout",
            "udp.portrange",
            "udp.strictreply",
            "udp.advertise",
            "shutdown.draintimeout",
            "userlist",
            "maxconnections",
            "logoutput",
            "logfile",
            "logformat",
            "logrotate.size",
            "logrotate.keep",
            "dns.prefer",
            "dns.tryall",
            "dns.deny",
            "dns.cachettl",
            "dns.timeout",
            "auth.cachettl",
            "auth.command",
            "metrics.listen",
            "metrics.allowpublic",
            "tls.certfile",
            "tls.keyfile",
            "tls.acme.domains",
            "tls.acme.email",
            "tls.acme.cache",
            "tls.acme.staging",
            "ratelimit.connectionrate",
            "ratelimit.authfailurerate",
            "ratelimit.concurrentconnections",
            "ratelimit.byterate",
        ]
        .into_iter()
        .collect();

        assert_eq!(
            metadata_settings, expected,
            "config metadata drifted from the parser's settings (missing or extra entries)"
        );

        // The rule scopes and directive are represented too.
        for name in &scopes_and_directives {
            assert!(
                CONFIG_SETTINGS_METADATA.iter().any(|s| s.name == *name),
                "config metadata is missing rule scope/directive '{name}'"
            );
        }
    }

    #[test]
    fn check_json_reports_effective_runtime_paths() {
        let config = Config::parse(
            "internal: 0.0.0.0:443\nsocksmethod: username\nuserlist: /etc/alighieri/users\ntls.acme.domains: x.example.com\ntls.acme.cache: /tmp/acme",
        )
        .unwrap();
        let json = check_ok_json(Path::new("test.conf"), &config);
        assert!(json.contains("\"listen\":\"0.0.0.0:443\""), "{json}");
        assert!(json.contains("\"acme\":true"), "{json}");
        assert!(json.contains("\"acme_cache\":\"/tmp/acme\""), "{json}");
        assert!(json.contains("\"log_file\":\"\""), "{json}");
        assert!(
            json.contains("\"userlist\":\"/etc/alighieri/users\""),
            "{json}"
        );
        assert!(json.contains("\"declared_config_sources\":[]"), "{json}");
        assert!(json.contains("\"canonical_config_sources\":[]"), "{json}");
        assert!(
            json.contains("\"declared_config_include_patterns\":[]"),
            "{json}"
        );
        assert!(
            json.contains("\"canonical_config_include_patterns\":[]"),
            "{json}"
        );

        let config = Config::parse("internal: 127.0.0.1:1080").unwrap();
        let json = check_ok_json(Path::new("test.conf"), &config);
        assert!(json.contains("\"listen\":\"127.0.0.1:1080\""), "{json}");
        assert!(json.contains("\"acme\":false"), "{json}");
        assert!(json.contains("\"acme_cache\":\"\""), "{json}");
        assert!(json.contains("\"log_file\":\"\""), "{json}");
        assert!(json.contains("\"userlist\":\"\""), "{json}");

        // File logging reports the configured logfile path.
        let config = Config::parse(
            "internal: 127.0.0.1:1080\nlogoutput: file\nlogfile: /var/log/alighieri/app.log",
        )
        .unwrap();
        let json = check_ok_json(Path::new("test.conf"), &config);
        assert!(
            json.contains("\"log_file\":\"/var/log/alighieri/app.log\""),
            "{json}"
        );
    }

    #[test]
    fn check_json_reports_last_userlist_from_includes() {
        let dir = tempfile::tempdir().unwrap();
        let fragments = dir.path().join("conf.d");
        std::fs::create_dir(&fragments).unwrap();
        std::fs::write(
            dir.path().join("alighieri.conf"),
            "internal: 127.0.0.1:1080\ninclude: conf.d/*.conf\n",
        )
        .unwrap();
        std::fs::write(fragments.join("10-users.conf"), "userlist: first-users\n").unwrap();
        std::fs::write(fragments.join("20-users.conf"), "userlist: final-users\n").unwrap();

        let config = Config::load(&dir.path().join("alighieri.conf")).unwrap();
        let json = check_ok_json(Path::new("test.conf"), &config);

        assert!(json.contains("\"userlist\":\"final-users\""), "{json}");
    }

    #[test]
    fn check_json_reports_declared_and_canonical_config_sources() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("main config.conf");
        let include = dir.path().join("policy fragment.conf");
        std::fs::write(
            &main,
            "internal: 127.0.0.1:1080\ninclude: policy fragment.conf\n",
        )
        .unwrap();
        std::fs::write(&include, "socks pass { command: connect }\n").unwrap();

        let config = Config::load(&main).unwrap();
        let json = check_ok_json(&main, &config);
        let canonical_main = std::fs::canonicalize(&main).unwrap();
        let canonical_include = std::fs::canonicalize(&include).unwrap();
        let declared_include = canonical_main
            .parent()
            .unwrap()
            .join("policy fragment.conf");

        assert!(
            json.contains(&format!(
                "\"declared_config_sources\":[\"{}\",\"{}\"]",
                json_escape(&main.display().to_string()),
                json_escape(&declared_include.display().to_string())
            )),
            "{json}"
        );
        assert!(
            json.contains(&format!(
                "\"canonical_config_sources\":[\"{}\",\"{}\"]",
                json_escape(&canonical_main.display().to_string()),
                json_escape(&canonical_include.display().to_string())
            )),
            "{json}"
        );
        assert!(
            json.contains("\"declared_config_include_patterns\":[]"),
            "{json}"
        );
        assert!(
            json.contains("\"canonical_config_include_patterns\":[]"),
            "{json}"
        );
    }

    #[test]
    fn check_json_reports_declared_and_canonical_include_patterns() {
        let dir = tempfile::tempdir().unwrap();
        let fragments = dir.path().join("policy fragments");
        std::fs::create_dir(&fragments).unwrap();
        let main = dir.path().join("main.conf");
        std::fs::write(
            &main,
            "internal: 127.0.0.1:1080\ninclude: policy fragments/*.conf\n",
        )
        .unwrap();
        std::fs::write(
            fragments.join("current safe.conf"),
            "socks pass { command: connect }\n",
        )
        .unwrap();

        let config = Config::load(&main).unwrap();
        let json = check_ok_json(&main, &config);
        let canonical_main = std::fs::canonicalize(&main).unwrap();
        let declared_pattern = canonical_main
            .parent()
            .unwrap()
            .join("policy fragments/*.conf");
        let canonical_pattern = std::fs::canonicalize(&fragments).unwrap().join("*.conf");

        assert!(
            json.contains(&format!(
                "\"declared_config_include_patterns\":[\"{}\"]",
                json_escape(&declared_pattern.display().to_string())
            )),
            "{json}"
        );
        assert!(
            json.contains(&format!(
                "\"canonical_config_include_patterns\":[\"{}\"]",
                json_escape(&canonical_pattern.display().to_string())
            )),
            "{json}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_json_keeps_symlinked_include_spellings_separate_from_targets() {
        let dir = tempfile::tempdir().unwrap();
        let fragments = dir.path().join("real-fragments");
        let fragments_alias = dir.path().join("fragments-alias");
        std::fs::create_dir(&fragments).unwrap();
        std::os::unix::fs::symlink(&fragments, &fragments_alias).unwrap();
        let included = fragments.join("policy.conf");
        std::fs::write(&included, "socks pass { command: connect }\n").unwrap();
        let main = dir.path().join("main.conf");
        std::fs::write(
            &main,
            "internal: 127.0.0.1:1080\ninclude: fragments-alias/*.conf\n",
        )
        .unwrap();

        let config = Config::load(&main).unwrap();
        let json = check_ok_json(&main, &config);
        let canonical_main = std::fs::canonicalize(&main).unwrap();
        let declared_parent = canonical_main.parent().unwrap().join("fragments-alias");
        let canonical_parent = std::fs::canonicalize(&fragments).unwrap();
        let canonical_included = std::fs::canonicalize(&included).unwrap();

        assert!(
            json.contains(&json_escape(
                &declared_parent.join("policy.conf").display().to_string()
            )),
            "{json}"
        );
        assert!(
            json.contains(&json_escape(&canonical_included.display().to_string())),
            "{json}"
        );
        assert!(
            json.contains(&json_escape(
                &declared_parent.join("*.conf").display().to_string()
            )),
            "{json}"
        );
        assert!(
            json.contains(&json_escape(
                &canonical_parent.join("*.conf").display().to_string()
            )),
            "{json}"
        );
    }

    #[test]
    fn json_path_array_preserves_spaces_quotes_and_backslashes() {
        let path = Path::new("config dir/part \"quoted\"\\tail.conf");
        assert_eq!(
            json_path_array([path]),
            r#"["config dir/part \"quoted\"\\tail.conf"]"#
        );
    }

    #[test]
    fn check_json_implies_check_mode() {
        let command = parse_args_from(vec!["--json".into(), "alighieri.conf".into()]).unwrap();
        assert_eq!(
            command,
            Command::Check {
                config_path: PathBuf::from("alighieri.conf"),
                format: CheckOutputFormat::Json
            }
        );
    }

    #[test]
    fn parses_version_flag() {
        assert_eq!(
            parse_args_from(vec!["--version".into()]).unwrap(),
            Command::Version
        );
        assert_eq!(
            parse_args_from(vec!["-V".into()]).unwrap(),
            Command::Version
        );
        // Also recognised later in the run/check parser, not only as arg one.
        assert_eq!(
            parse_args_from(vec!["--check".into(), "--version".into()]).unwrap(),
            Command::Version
        );
        assert_eq!(
            parse_args_from(vec!["alighieri.conf".into(), "-V".into()]).unwrap(),
            Command::Version
        );
        assert_eq!(
            parse_args_from(vec!["--config".into(), "p.conf".into(), "--version".into()]).unwrap(),
            Command::Version
        );
    }

    #[test]
    fn rejects_unknown_option() {
        let err = parse_args_from(vec!["--frobnicate".into()]).unwrap_err();
        assert!(err.contains("unknown option"), "{err}");
        // A typo'd known flag is reported, not silently treated as a config path.
        let err = parse_args_from(vec!["--chek".into()]).unwrap_err();
        assert!(err.contains("unknown option"), "{err}");
    }

    #[test]
    fn rejects_a_second_positional_argument() {
        let err = parse_args_from(vec!["a.conf".into(), "b.conf".into()]).unwrap_err();
        assert!(err.contains("unexpected argument"), "{err}");
    }

    #[test]
    fn accepts_flags_after_the_config_path() {
        // A flag after the positional config path is still parsed (only an
        // unknown option or a second positional is an error).
        assert_eq!(
            parse_args_from(vec!["a.conf".into(), "--check".into()]).unwrap(),
            Command::Check {
                config_path: PathBuf::from("a.conf"),
                format: CheckOutputFormat::Text,
            }
        );
    }

    #[test]
    fn json_escape_handles_control_characters() {
        assert_eq!(
            json_escape("C:\\Alighieri\\\"config\"\n"),
            "C:\\\\Alighieri\\\\\\\"config\\\"\\n"
        );
    }

    #[test]
    fn user_command_requires_target() {
        let err = parse_user_command(vec!["add".into(), "alice".into()]).unwrap_err();
        assert_eq!(
            err,
            "exactly one of --userlist PATH or --config CONFIG is required"
        );
    }

    #[test]
    fn user_commands_do_not_consume_option_tokens_as_usernames() {
        for command in ["add", "delete", "verify"] {
            for option in [
                "--userlist",
                "--config",
                "--password-stdin",
                "--if-present",
                "--json",
            ] {
                assert_eq!(
                    parse_user_command(vec![command.into(), option.into()]).unwrap_err(),
                    format!("{command} requires USER"),
                    "{command} consumed {option} as USER"
                );
            }
        }

        assert_eq!(
            parse_user_command(vec![
                "add".into(),
                "--json".into(),
                "--userlist".into(),
                "users".into(),
                "--password-stdin".into(),
            ])
            .unwrap_err(),
            "add requires USER"
        );
    }

    #[test]
    fn user_usage_includes_full_subcommands() {
        let usage = user_usage();
        assert!(usage.contains("alighieri user delete USER (--userlist PATH | --config CONFIG)"));
        assert!(usage.contains("alighieri user list (--userlist PATH | --config CONFIG)"));
        assert!(usage.contains("alighieri user verify USER (--userlist PATH | --config CONFIG)"));
        assert!(usage.contains("--password-stdin"));
        assert!(usage.contains("--if-present"));
        assert!(usage.contains("--json"));
    }

    #[test]
    fn parses_user_add_command() {
        let command = parse_user_command(vec![
            "add".into(),
            "alice".into(),
            "--userlist".into(),
            "users.txt".into(),
        ])
        .unwrap();
        assert_eq!(
            command,
            UserCommand::Add {
                username: "alice".into(),
                target: UserTarget::Userlist(PathBuf::from("users.txt")),
                password_stdin: false,
                json: false,
            }
        );
    }

    #[test]
    fn user_help_tokens_are_valid_positional_values_in_a_complete_command() {
        assert_eq!(
            parse_user_command(vec![
                "add".into(),
                "--help".into(),
                "--userlist".into(),
                "-h".into(),
            ])
            .unwrap(),
            UserCommand::Add {
                username: "--help".into(),
                target: UserTarget::Userlist(PathBuf::from("-h")),
                password_stdin: false,
                json: false,
            }
        );
        assert_eq!(
            parse_user_command(vec!["add".into(), "--help".into()]).unwrap(),
            UserCommand::Help
        );
        assert_eq!(
            parse_user_command(vec!["list".into(), "--userlist".into(), "--help".into()]).unwrap(),
            UserCommand::List {
                target: UserTarget::Userlist(PathBuf::from("--help")),
                json: false,
            }
        );
        assert_eq!(
            parse_user_command(vec!["add".into(), "--help".into(), "--userlist".into()])
                .unwrap_err(),
            "--userlist requires a path"
        );
    }

    #[test]
    fn unconsumed_user_help_tokens_show_help() {
        assert_eq!(
            parse_user_command(vec!["add".into(), "alice".into(), "--help".into()]).unwrap(),
            UserCommand::Help
        );
        assert_eq!(
            parse_user_command(vec![
                "list".into(),
                "--userlist".into(),
                "users.txt".into(),
                "-h".into(),
            ])
            .unwrap(),
            UserCommand::Help
        );
    }

    #[test]
    fn parses_user_delete_command() {
        let command = parse_user_command(vec![
            "delete".into(),
            "alice".into(),
            "--userlist".into(),
            "users.txt".into(),
        ])
        .unwrap();
        assert_eq!(
            command,
            UserCommand::Delete {
                username: "alice".into(),
                target: UserTarget::Userlist(PathBuf::from("users.txt")),
                if_present: false,
                json: false,
            }
        );
    }

    #[test]
    fn parses_user_list_command() {
        let command =
            parse_user_command(vec!["list".into(), "--userlist".into(), "users.txt".into()])
                .unwrap();
        assert_eq!(
            command,
            UserCommand::List {
                target: UserTarget::Userlist(PathBuf::from("users.txt")),
                json: false,
            }
        );
    }

    #[test]
    fn parses_machine_user_options_and_config_target() {
        assert_eq!(
            parse_user_command(vec![
                "add".into(),
                "alice".into(),
                "--config".into(),
                "alighieri.conf".into(),
                "--password-stdin".into(),
                "--json".into(),
            ])
            .unwrap(),
            UserCommand::Add {
                username: "alice".into(),
                target: UserTarget::Config(PathBuf::from("alighieri.conf")),
                password_stdin: true,
                json: true,
            }
        );
        assert_eq!(
            parse_user_command(vec![
                "delete".into(),
                "alice".into(),
                "--userlist".into(),
                "users".into(),
                "--if-present".into(),
                "--json".into(),
            ])
            .unwrap(),
            UserCommand::Delete {
                username: "alice".into(),
                target: UserTarget::Userlist(PathBuf::from("users")),
                if_present: true,
                json: true,
            }
        );
    }

    #[test]
    fn rejects_invalid_user_option_combinations() {
        let invalid = [
            vec!["list", "--json"],
            vec!["list", "--userlist", "users", "--config", "config"],
            vec!["list", "--userlist", "one", "--userlist", "two"],
            vec!["list", "--userlist", "users", "--json", "--json"],
            vec!["list", "--userlist", "users", "--password-stdin"],
            vec!["delete", "alice", "--userlist", "users", "--password-stdin"],
            vec!["add", "alice", "--userlist", "users", "--if-present"],
            vec!["verify", "alice", "--userlist", "users", "--if-present"],
            vec!["list", "--userlist", "users", "--unknown"],
        ];
        for args in invalid {
            assert!(
                parse_user_command(args.into_iter().map(str::to_string).collect()).is_err(),
                "invalid command was accepted"
            );
        }
    }

    #[test]
    fn interactive_add_prompts_for_password_and_confirmation() {
        use std::collections::VecDeque;

        let mut responses = VecDeque::from([Ok("secret".into()), Ok("secret".into())]);
        let mut prompts = Vec::new();
        let password = prompt_password_twice_with(|prompt| {
            prompts.push(prompt.to_string());
            responses
                .pop_front()
                .unwrap_or_else(|| Err("unexpected prompt".into()))
        })
        .unwrap();

        assert_eq!(prompts, ["Password: ", "Confirm password: "]);
        assert_eq!(password.as_str(), "secret");
    }

    #[test]
    fn interactive_add_rejects_mismatched_and_empty_passwords() {
        for responses in [
            [Ok("secret".into()), Ok("different".into())],
            [Ok(String::new()), Ok(String::new())],
        ] {
            let mut responses = responses.into_iter();
            let error = match prompt_password_twice_with(|_| {
                responses.next().unwrap_or_else(|| Err("missing".into()))
            }) {
                Ok(_) => panic!("invalid interactive password was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.code, ManagementErrorCode::InvalidPassword);
        }
    }

    #[test]
    fn upsert_userlist_entry_replaces_existing_user() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        std::fs::write(&userlist, "# comment\nalice:old\nbob:pw\n").unwrap();
        assert_eq!(
            upsert_userlist_entry(
                &userlist,
                "alice",
                "alice:new",
                UserlistCreationPolicy::Private,
            )
            .unwrap(),
            UpsertOutcome::Updated
        );
        let updated = std::fs::read_to_string(userlist).unwrap();
        assert_eq!(updated, "# comment\nalice:new\nbob:pw\n");
    }

    #[test]
    fn upsert_userlist_entry_reports_creation_under_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("nested").join("users");
        assert_eq!(
            upsert_userlist_entry(
                &userlist,
                "alice",
                "alice:new",
                UserlistCreationPolicy::Private,
            )
            .unwrap(),
            UpsertOutcome::Created
        );
        assert_eq!(std::fs::read_to_string(userlist).unwrap(), "alice:new\n");
    }

    #[test]
    fn upsert_userlist_entry_creates_backup_for_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        std::fs::write(&userlist, "alice:old\n").unwrap();

        upsert_userlist_entry(
            &userlist,
            "alice",
            "alice:new",
            UserlistCreationPolicy::Private,
        )
        .unwrap();

        let backup = std::fs::read_to_string(userlist_backup_path(&userlist)).unwrap();
        assert_eq!(backup, "alice:old\n");
    }

    #[test]
    fn upsert_userlist_entry_replaces_existing_argon2_user() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        let old = UserDb::hash_user_line("alice", "old").unwrap();
        std::fs::write(&userlist, format!("{old}\nbob:pw\n")).unwrap();

        upsert_userlist_entry(
            &userlist,
            "alice",
            "alice:new",
            UserlistCreationPolicy::Private,
        )
        .unwrap();

        let updated = std::fs::read_to_string(userlist).unwrap();
        assert_eq!(updated, "alice:new\nbob:pw\n");
    }

    #[test]
    fn upsert_userlist_entry_replaces_corrupted_argon2_user() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        std::fs::write(
            &userlist,
            "# alighieri:user:argon2:616c696365:$argon2id$not-a-valid-phc\nbob:pw\n",
        )
        .unwrap();

        upsert_userlist_entry(
            &userlist,
            "alice",
            "alice:new",
            UserlistCreationPolicy::Private,
        )
        .unwrap();

        let updated = std::fs::read_to_string(userlist).unwrap();
        assert_eq!(updated, "alice:new\nbob:pw\n");
    }

    #[test]
    fn upsert_userlist_entry_supports_current_directory_file() {
        struct Cleanup(Vec<PathBuf>);

        impl Drop for Cleanup {
            fn drop(&mut self) {
                for path in &self.0 {
                    let _ = std::fs::remove_file(path);
                }
            }
        }

        let filename = format!(".alighieri-users-test-{}", std::process::id());
        let userlist = PathBuf::from(&filename);
        let lock = userlist_lock_path(&userlist);
        let backup = userlist_backup_path(&userlist);
        let _cleanup = Cleanup(vec![userlist.clone(), lock.clone(), backup.clone()]);
        let _ = std::fs::remove_file(&userlist);
        let _ = std::fs::remove_file(&lock);
        let _ = std::fs::remove_file(&backup);

        upsert_userlist_entry(
            Path::new(&filename),
            "alice",
            "alice:new",
            UserlistCreationPolicy::Private,
        )
        .unwrap();
        let updated = std::fs::read_to_string(&userlist).unwrap();
        assert_eq!(updated, "alice:new\n");
    }

    #[test]
    fn delete_userlist_entry_removes_plain_and_argon2_entries() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        let hashed = UserDb::hash_user_line("alice", "old").unwrap();
        std::fs::write(
            &userlist,
            format!("# comment\n{hashed}\nalice:legacy\nbob:pw\n"),
        )
        .unwrap();

        delete_userlist_entry(&userlist, "alice").unwrap();

        let updated = std::fs::read_to_string(&userlist).unwrap();
        assert_eq!(updated, "# comment\nbob:pw\n");
        let backup = std::fs::read_to_string(userlist_backup_path(&userlist)).unwrap();
        assert!(backup.contains("alice:legacy"));
    }

    #[test]
    fn delete_userlist_entry_reports_missing_user() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        std::fs::write(&userlist, "bob:pw\n").unwrap();

        assert!(!delete_userlist_entry(&userlist, "alice").unwrap());
        assert_eq!(std::fs::read_to_string(&userlist).unwrap(), "bob:pw\n");
        assert!(!userlist_backup_path(&userlist).exists());
    }

    #[test]
    fn missing_userlist_is_not_reported_as_missing_user() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("missing-users");

        let err = delete_userlist_entry(&userlist, "alice").unwrap_err();

        assert!(matches!(
            err,
            UserlistMutationError::Read(error)
                if error.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn userlist_usernames_are_sorted_and_deduplicated() {
        let hashed = UserDb::hash_user_line("alice", "pw").unwrap();
        let users =
            userlist_usernames(&format!("bob:pw\n{hashed}\nbob:other\n# comment\n")).unwrap();

        assert_eq!(users, vec!["alice".to_string(), "bob".to_string()]);
    }

    #[test]
    fn userlist_usernames_reject_malformed_runtime_entries() {
        for malformed in [
            "missing-colon\n",
            "# alighieri:user:argon2:616c696365:$argon2id$not-a-valid-phc\n",
        ] {
            let err = userlist_usernames(malformed).unwrap_err();
            assert!(err.to_string().contains("userlist line 1"), "{err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn new_userlist_file_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        upsert_userlist_entry(
            &userlist,
            "alice",
            "alice:new",
            UserlistCreationPolicy::Private,
        )
        .unwrap();
        let mode = std::fs::metadata(userlist).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn managed_userlist_bootstrap_requires_the_service_identity_on_unix() {
        assert!(supports_managed_userlist_bootstrap(
            true,
            true,
            0,
            4242,
            0o640,
            0,
            Some(4242)
        ));
        for (is_regular_file, has_no_access_acl, uid, gid, mode, expected_uid, service_gid) in [
            (false, true, 0, 4242, 0o640, 0, Some(4242)),
            (true, false, 0, 4242, 0o640, 0, Some(4242)),
            (true, true, 1000, 4242, 0o640, 0, Some(4242)),
            (true, true, 0, 7, 0o640, 0, Some(4242)),
            (true, true, 0, 4242, 0o600, 0, Some(4242)),
            (true, true, 0, 4242, 0o644, 0, Some(4242)),
            (true, true, 0, 4242, 0o660, 0, Some(4242)),
            (true, true, 0, 4242, 0o4640, 0, Some(4242)),
            (true, true, 0, 4242, 0o640, 0, None),
        ] {
            assert!(!supports_managed_userlist_bootstrap(
                is_regular_file,
                has_no_access_acl,
                uid,
                gid,
                mode,
                expected_uid,
                service_gid
            ));
        }

        let metadata = userlist_unix_metadata(
            Path::new("unused"),
            false,
            UserlistCreationPolicy::ConfigBacked {
                uid: 0,
                gid: 4242,
                managed_bootstrap: true,
            },
        )
        .unwrap();
        assert_eq!(metadata.mode, 0o640);
        assert_eq!(metadata.uid, 0);
        assert_eq!(metadata.gid, 4242);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn config_backed_bootstrap_rejects_a_fifo_without_opening_it_on_linux() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("alighieri.conf");
        let config_c = CString::new(config.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(config_c.as_ptr(), 0o640) }, 0);
        let metadata = std::fs::metadata(&config).unwrap();

        let policy = UserlistCreationPolicy::config_backed_with_expected_identity(
            &config,
            metadata.uid(),
            Some(metadata.gid()),
        )
        .unwrap();
        assert!(matches!(
            policy,
            UserlistCreationPolicy::ConfigBacked {
                managed_bootstrap: false,
                ..
            }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_bootstrap_strips_inherited_access_acl_on_linux() {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("alighieri.conf");
        let userlist = dir.path().join("users");
        std::fs::write(&config, "userlist: users\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o640)).unwrap();
        let config_metadata = std::fs::metadata(&config).unwrap();
        let current_uid = unsafe { libc::geteuid() };
        let named_uid = if current_uid == u32::MAX {
            u32::MAX - 1
        } else {
            current_uid + 1
        };
        let default_acl = test_posix_acl(0o7, named_uid);
        let directory = std::fs::File::open(dir.path()).unwrap();
        if let Err(error) =
            set_test_linux_xattr(&directory, c"system.posix_acl_default", &default_acl)
        {
            if acl_test_unavailable(&error) {
                return;
            }
            panic!("failed to install test default ACL: {error}");
        }

        let control = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(dir.path().join("control"))
            .unwrap();
        assert!(linux_access_acl(&control).unwrap().is_some());

        let policy = UserlistCreationPolicy::config_backed_with_expected_identity(
            &config,
            config_metadata.uid(),
            Some(config_metadata.gid()),
        )
        .unwrap();
        assert_eq!(
            upsert_userlist_entry(&userlist, "alice", "alice:new", policy).unwrap(),
            UpsertOutcome::Created
        );

        let created = open_no_follow(&userlist).unwrap();
        let created_metadata = created.metadata().unwrap();
        assert_eq!(created_metadata.permissions().mode() & 0o777, 0o640);
        assert_eq!(created_metadata.uid(), config_metadata.uid());
        assert_eq!(created_metadata.gid(), config_metadata.gid());
        assert!(linux_access_acl(&created).unwrap().is_none());
        assert_eq!(std::fs::read_to_string(userlist).unwrap(), "alice:new\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_userlist_access_acl_is_preserved_on_linux() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        std::fs::write(&userlist, "alice:old\n").unwrap();
        std::fs::set_permissions(&userlist, std::fs::Permissions::from_mode(0o640)).unwrap();
        let current_uid = unsafe { libc::geteuid() };
        let named_uid = if current_uid == u32::MAX {
            u32::MAX - 1
        } else {
            current_uid + 1
        };
        let access_acl = test_posix_acl(0o6, named_uid);
        let original = open_no_follow(&userlist).unwrap();
        if let Err(error) = set_test_linux_xattr(&original, c"system.posix_acl_access", &access_acl)
        {
            if acl_test_unavailable(&error) {
                return;
            }
            panic!("failed to install test access ACL: {error}");
        }
        let expected_acl = linux_access_acl(&original).unwrap().unwrap();
        drop(original);

        upsert_userlist_entry(
            &userlist,
            "alice",
            "alice:new",
            UserlistCreationPolicy::Private,
        )
        .unwrap();

        let updated = open_no_follow(&userlist).unwrap();
        let backup = open_no_follow(&userlist_backup_path(&userlist)).unwrap();
        assert_eq!(
            linux_access_acl(&updated).unwrap(),
            Some(expected_acl.clone())
        );
        assert_eq!(linux_access_acl(&backup).unwrap(), Some(expected_acl));
        assert_eq!(std::fs::read_to_string(&userlist).unwrap(), "alice:new\n");
        assert_eq!(
            std::fs::read_to_string(userlist_backup_path(&userlist)).unwrap(),
            "alice:old\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn config_backed_bootstrap_rejects_an_extended_config_acl_on_linux() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("alighieri.conf");
        let userlist = dir.path().join("users");
        std::fs::write(&config, "userlist: users\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o640)).unwrap();
        let current_uid = unsafe { libc::geteuid() };
        let named_uid = if current_uid == u32::MAX {
            u32::MAX - 1
        } else {
            current_uid + 1
        };
        let access_acl = test_posix_acl(0o6, named_uid);
        let config_file = open_no_follow(&config).unwrap();
        if let Err(error) =
            set_test_linux_xattr(&config_file, c"system.posix_acl_access", &access_acl)
        {
            if acl_test_unavailable(&error) {
                return;
            }
            panic!("failed to install test config ACL: {error}");
        }
        let config_metadata = config_file.metadata().unwrap();
        assert_eq!(config_metadata.permissions().mode() & 0o777, 0o640);
        drop(config_file);

        let policy = UserlistCreationPolicy::config_backed_with_expected_identity(
            &config,
            config_metadata.uid(),
            Some(config_metadata.gid()),
        )
        .unwrap();
        let error = upsert_userlist_entry(&userlist, "alice", "alice:new", policy).unwrap_err();
        assert!(matches!(error, UserlistMutationError::Update(_)));
        assert!(!userlist.exists());
    }

    #[cfg(unix)]
    #[test]
    fn config_backed_new_userlist_rejects_unsupported_config_modes_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        for mode in [0o600, 0o644] {
            let case_dir = dir.path().join(format!("{mode:04o}"));
            std::fs::create_dir(&case_dir).unwrap();
            let config = case_dir.join("alighieri.conf");
            let userlist = case_dir.join("users");
            std::fs::write(&config, "userlist: users\n").unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(mode)).unwrap();

            let error = upsert_userlist_entry(
                &userlist,
                "alice",
                "alice:new",
                UserlistCreationPolicy::config_backed(&config).unwrap(),
            )
            .unwrap_err();

            match error {
                UserlistMutationError::Update(error) => {
                    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                    let message = error.to_string();
                    #[cfg(target_os = "linux")]
                    {
                        assert!(message.contains("root:alighieri"), "{message}");
                        assert!(message.contains("mode 0640"), "{message}");
                    }
                    #[cfg(not(target_os = "linux"))]
                    assert!(message.contains("only on Linux"), "{message}");
                    assert!(message.contains("pre-create"), "{message}");
                }
                UserlistMutationError::Read(error) => {
                    panic!("unexpected userlist read error: {error}")
                }
            }
            assert!(!userlist.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_userlist_file_metadata_is_preserved_on_unix() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("alighieri.conf");
        let userlist = dir.path().join("users");
        std::fs::write(&config, "userlist: users\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&userlist, "alice:old\n").unwrap();
        std::fs::set_permissions(&userlist, std::fs::Permissions::from_mode(0o600)).unwrap();
        let original_metadata = std::fs::metadata(&userlist).unwrap();

        upsert_userlist_entry(
            &userlist,
            "alice",
            "alice:new",
            UserlistCreationPolicy::config_backed(&config).unwrap(),
        )
        .unwrap();

        let updated_metadata = std::fs::metadata(&userlist).unwrap();
        assert_eq!(
            updated_metadata.permissions().mode() & 0o777,
            original_metadata.permissions().mode() & 0o777
        );
        assert_eq!(updated_metadata.uid(), original_metadata.uid());
        assert_eq!(updated_metadata.gid(), original_metadata.gid());
        assert_eq!(std::fs::read_to_string(userlist).unwrap(), "alice:new\n");
    }
}
