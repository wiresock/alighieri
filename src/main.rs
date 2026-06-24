//! Alighieri — a lightweight SOCKS5 proxy server.

mod wizard;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use alighieri::auth::UserDb;
use alighieri::config::{Config, TlsConfig};
use alighieri::runtime::{
    init_console_logging, reload_signal_channel, run_server_reloading_until_shutdown,
    shutdown_signal,
};
use alighieri::tls;
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
    println!("    alighieri user add USER --userlist PATH    Add/update an Argon2id user");
    println!("    alighieri user delete USER --userlist PATH Remove a user");
    println!("    alighieri user list --userlist PATH        List users");
    println!("    alighieri user verify USER --userlist PATH Verify a user password");
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
    }
}

/// Success JSON for `--check --json`. Beyond `ok`/`path`/`message` it reports
/// the effective `listen` address (`internal:` is last-wins) and whether `acme`
/// is enabled, so tooling — e.g. the systemd installer deciding whether to grant
/// `CAP_NET_BIND_SERVICE` — can read the resolved facts without reparsing config.
fn check_ok_json(config_path: &Path, config: &Config) -> String {
    let acme = matches!(config.tls, Some(TlsConfig::Acme(_)));
    format!(
        "{{\"ok\":true,\"path\":\"{}\",\"message\":\"configuration is valid\",\"listen\":\"{}\",\"acme\":{}}}",
        json_escape(&config_path.display().to_string()),
        json_escape(&config.internal.to_string()),
        acme
    )
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

/// Reload metadata for every config setting, surfaced by `config metadata
/// --json`. Keep in sync with the parser in `config.rs`; the
/// `config_metadata_covers_every_setting` test enforces that every documented
/// setting is listed here and that each name is a real one.
const CONFIG_SETTINGS_METADATA: &[ConfigSettingMetadata] = &[
    ConfigSettingMetadata {
        name: "internal",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "listener address is bound when the process starts",
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
        name: "shutdown.draintimeout",
        reload: ReloadBehavior::Restart,
        applies_to: "process",
        note: "drain timeout is read from the startup configuration at shutdown",
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
enum UserCommand {
    Add { username: String, userlist: PathBuf },
    Delete { username: String, userlist: PathBuf },
    List { userlist: PathBuf },
    Verify { username: String, userlist: PathBuf },
    Help,
}

fn parse_user_command(args: Vec<String>) -> Result<UserCommand, String> {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        return Ok(UserCommand::Help);
    }
    let Some(command) = args.first().map(String::as_str) else {
        return Err(user_usage());
    };
    match command {
        "add" | "delete" | "verify" => {
            let username = args
                .get(1)
                .cloned()
                .ok_or_else(|| format!("{command} requires USER"))?;
            let userlist = parse_userlist_arg(&args[2..])?;
            match command {
                "add" => Ok(UserCommand::Add { username, userlist }),
                "delete" => Ok(UserCommand::Delete { username, userlist }),
                "verify" => Ok(UserCommand::Verify { username, userlist }),
                _ => unreachable!(),
            }
        }
        "list" => Ok(UserCommand::List {
            userlist: parse_userlist_arg(&args[1..])?,
        }),
        _ => Err(user_usage()),
    }
}

fn parse_userlist_arg(args: &[String]) -> Result<PathBuf, String> {
    let mut userlist = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--userlist" => {
                let Some(path) = iter.next() else {
                    return Err("--userlist requires a path".into());
                };
                userlist = Some(PathBuf::from(path));
            }
            _ => return Err(user_usage()),
        }
    }
    userlist.ok_or_else(|| "--userlist requires a path".into())
}

fn handle_user(args: Vec<String>) -> ExitCode {
    match parse_user_command(args) {
        Ok(UserCommand::Add { username, userlist }) => add_user(&username, &userlist),
        Ok(UserCommand::Delete { username, userlist }) => delete_user(&username, &userlist),
        Ok(UserCommand::List { userlist }) => list_users(&userlist),
        Ok(UserCommand::Verify { username, userlist }) => verify_user(&username, &userlist),
        Ok(UserCommand::Help) => {
            println!("{}", user_usage());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("alighieri: {e}");
            ExitCode::FAILURE
        }
    }
}

fn add_user(username: &str, userlist: &Path) -> ExitCode {
    let password = match prompt_password_twice() {
        Ok(password) => password,
        Err(e) => {
            eprintln!("alighieri: {e}");
            return ExitCode::FAILURE;
        }
    };
    let line = match UserDb::hash_user_line(username, &password) {
        Ok(line) => line,
        Err(e) => {
            eprintln!("alighieri: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = upsert_userlist_entry(userlist, username, &line) {
        eprintln!("alighieri: failed to update {}: {e}", userlist.display());
        return ExitCode::FAILURE;
    }
    println!(
        "alighieri: updated user '{username}' in {}",
        userlist.display()
    );
    ExitCode::SUCCESS
}

fn delete_user(username: &str, userlist: &Path) -> ExitCode {
    match delete_userlist_entry(userlist, username) {
        Ok(()) => {
            println!(
                "alighieri: removed user '{username}' from {}",
                userlist.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) if is_user_not_found_error(&e) => {
            eprintln!(
                "alighieri: user '{username}' was not found in {}",
                userlist.display()
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("alighieri: failed to update {}: {e}", userlist.display());
            ExitCode::FAILURE
        }
    }
}

fn is_user_not_found_error(e: &std::io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.downcast_ref::<UserNotFound>().is_some())
}

fn list_users(userlist: &Path) -> ExitCode {
    let text = match std::fs::read_to_string(userlist) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("alighieri: failed to read {}: {e}", userlist.display());
            return ExitCode::FAILURE;
        }
    };
    for username in userlist_usernames(&text) {
        println!("{username}");
    }
    ExitCode::SUCCESS
}

fn verify_user(username: &str, userlist: &Path) -> ExitCode {
    let db = match UserDb::load(userlist) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("alighieri: {e}");
            return ExitCode::FAILURE;
        }
    };
    let password = match rpassword::prompt_password("Password: ") {
        Ok(password) => password,
        Err(e) => {
            eprintln!("alighieri: failed to read password: {e}");
            return ExitCode::FAILURE;
        }
    };
    if db.verify(username, &password) {
        println!("alighieri: password verified");
        ExitCode::SUCCESS
    } else {
        eprintln!("alighieri: password verification failed");
        ExitCode::FAILURE
    }
}

fn prompt_password_twice() -> Result<String, String> {
    let password = rpassword::prompt_password("Password: ")
        .map_err(|e| format!("failed to read password: {e}"))?;
    let confirm = rpassword::prompt_password("Confirm password: ")
        .map_err(|e| format!("failed to read password confirmation: {e}"))?;
    if password != confirm {
        return Err("passwords do not match".into());
    }
    if password.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(password)
}

fn upsert_userlist_entry(userlist: &Path, username: &str, line: &str) -> std::io::Result<()> {
    if let Some(parent) = userlist.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let _lock = acquire_userlist_lock(userlist)?;
    let (existing, existed) = match std::fs::read_to_string(userlist) {
        Ok(text) => (text, true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), false),
        Err(e) => return Err(e),
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
    write_userlist(userlist, output.as_bytes(), existed)
}

fn delete_userlist_entry(userlist: &Path, username: &str) -> std::io::Result<()> {
    let _lock = acquire_userlist_lock(userlist)?;
    let existing = std::fs::read_to_string(userlist)?;
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
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            UserNotFound,
        ));
    }

    let mut output = lines.join("\n");
    if !output.is_empty() {
        output.push('\n');
    }
    write_userlist(userlist, output.as_bytes(), true)
}

fn userlist_usernames(text: &str) -> Vec<String> {
    use std::collections::BTreeSet;

    let mut users = BTreeSet::new();
    for line in text.lines() {
        if let Some(username) = UserDb::entry_username(line) {
            users.insert(username);
        }
    }
    users.into_iter().collect()
}

#[derive(Debug)]
struct UserNotFound;

impl std::fmt::Display for UserNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("user not found")
    }
}

impl std::error::Error for UserNotFound {}

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
fn write_userlist(userlist: &Path, contents: &[u8], existed: bool) -> std::io::Result<()> {
    write_userlist_atomically(userlist, contents, existed)
}

#[cfg(windows)]
fn write_userlist(userlist: &Path, contents: &[u8], _existed: bool) -> std::io::Result<()> {
    write_userlist_atomically(userlist, contents, _existed)
}

#[cfg(not(any(unix, windows)))]
fn write_userlist(userlist: &Path, contents: &[u8], _existed: bool) -> std::io::Result<()> {
    write_userlist_atomically(userlist, contents, _existed)
}

fn write_userlist_atomically(
    userlist: &Path,
    contents: &[u8],
    existed: bool,
) -> std::io::Result<()> {
    use std::io::Write;

    let (temp_path, mut file) = create_userlist_temp(userlist, existed)?;
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
    let (temp_path, mut temp_file) = create_userlist_temp(userlist, existed)?;
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
) -> std::io::Result<(PathBuf, std::fs::File)> {
    use std::fs::OpenOptions;

    #[cfg(unix)]
    let metadata = userlist_unix_metadata(userlist, _existed)?;

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
                    apply_userlist_unix_metadata(&temp_path, &file, metadata)?;
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
#[derive(Clone, Copy)]
struct UserlistUnixMetadata {
    mode: u32,
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
fn userlist_unix_metadata(userlist: &Path, existed: bool) -> std::io::Result<UserlistUnixMetadata> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if existed {
        let metadata = std::fs::metadata(userlist)?;
        Ok(UserlistUnixMetadata {
            mode: metadata.permissions().mode() & 0o777,
            uid: metadata.uid(),
            gid: metadata.gid(),
        })
    } else {
        Ok(UserlistUnixMetadata {
            mode: 0o600,
            uid: u32::MAX,
            gid: u32::MAX,
        })
    }
}

#[cfg(unix)]
fn apply_userlist_unix_metadata(
    _temp_path: &Path,
    file: &std::fs::File,
    metadata: UserlistUnixMetadata,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;

    file.set_permissions(std::fs::Permissions::from_mode(metadata.mode))?;
    if metadata.uid != u32::MAX || metadata.gid != u32::MAX {
        let rc = unsafe { libc::fchown(file.as_raw_fd(), metadata.uid, metadata.gid) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
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
    "usage: alighieri user add USER --userlist PATH | alighieri user delete USER --userlist PATH | alighieri user list --userlist PATH | alighieri user verify USER --userlist PATH"
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let metadata_settings: BTreeSet<&str> = CONFIG_SETTINGS_METADATA
            .iter()
            .map(|s| s.name)
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

        // The complete set of `key: value` settings the parser accepts. When a new
        // setting is added to the parser it must be added here and to
        // CONFIG_SETTINGS_METADATA, so `config metadata --json` stays complete.
        let expected: BTreeSet<&str> = [
            "internal",
            "external",
            "proxyprotocol",
            "socksmethod",
            "connecttimeout",
            "handshaketimeout",
            "iotimeout",
            "udptimeout",
            "udp.portrange",
            "udp.strictreply",
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
    fn check_json_reports_listen_and_acme() {
        let config = Config::parse(
            "internal: 0.0.0.0:443\ntls.acme.domains: x.example.com\ntls.acme.cache: /tmp/acme",
        )
        .unwrap();
        let json = check_ok_json(Path::new("test.conf"), &config);
        assert!(json.contains("\"listen\":\"0.0.0.0:443\""), "{json}");
        assert!(json.contains("\"acme\":true"), "{json}");

        let config = Config::parse("internal: 127.0.0.1:1080").unwrap();
        let json = check_ok_json(Path::new("test.conf"), &config);
        assert!(json.contains("\"listen\":\"127.0.0.1:1080\""), "{json}");
        assert!(json.contains("\"acme\":false"), "{json}");
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
    fn user_command_requires_userlist() {
        let err = parse_user_command(vec!["add".into(), "alice".into()]).unwrap_err();
        assert_eq!(err, "--userlist requires a path");
    }

    #[test]
    fn user_usage_includes_full_subcommands() {
        let usage = user_usage();
        assert!(usage.contains("alighieri user delete USER --userlist PATH"));
        assert!(usage.contains("alighieri user list --userlist PATH"));
        assert!(usage.contains("alighieri user verify USER --userlist PATH"));
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
                userlist: PathBuf::from("users.txt")
            }
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
                userlist: PathBuf::from("users.txt")
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
                userlist: PathBuf::from("users.txt")
            }
        );
    }

    #[test]
    fn upsert_userlist_entry_replaces_existing_user() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        std::fs::write(&userlist, "# comment\nalice:old\nbob:pw\n").unwrap();
        upsert_userlist_entry(&userlist, "alice", "alice:new").unwrap();
        let updated = std::fs::read_to_string(userlist).unwrap();
        assert_eq!(updated, "# comment\nalice:new\nbob:pw\n");
    }

    #[test]
    fn upsert_userlist_entry_creates_backup_for_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        std::fs::write(&userlist, "alice:old\n").unwrap();

        upsert_userlist_entry(&userlist, "alice", "alice:new").unwrap();

        let backup = std::fs::read_to_string(userlist_backup_path(&userlist)).unwrap();
        assert_eq!(backup, "alice:old\n");
    }

    #[test]
    fn upsert_userlist_entry_replaces_existing_argon2_user() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        let old = UserDb::hash_user_line("alice", "old").unwrap();
        std::fs::write(&userlist, format!("{old}\nbob:pw\n")).unwrap();

        upsert_userlist_entry(&userlist, "alice", "alice:new").unwrap();

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

        upsert_userlist_entry(&userlist, "alice", "alice:new").unwrap();

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

        upsert_userlist_entry(Path::new(&filename), "alice", "alice:new").unwrap();
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

        let err = delete_userlist_entry(&userlist, "alice").unwrap_err();

        assert!(is_user_not_found_error(&err));
        assert_eq!(std::fs::read_to_string(&userlist).unwrap(), "bob:pw\n");
        assert!(!userlist_backup_path(&userlist).exists());
    }

    #[test]
    fn missing_userlist_is_not_reported_as_missing_user() {
        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("missing-users");

        let err = delete_userlist_entry(&userlist, "alice").unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(!is_user_not_found_error(&err));
    }

    #[test]
    fn userlist_usernames_are_sorted_and_deduplicated() {
        let hashed = UserDb::hash_user_line("alice", "pw").unwrap();
        let users = userlist_usernames(&format!("bob:pw\n{hashed}\nbob:other\n# comment\n"));

        assert_eq!(users, vec!["alice".to_string(), "bob".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn new_userlist_file_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        upsert_userlist_entry(&userlist, "alice", "alice:new").unwrap();
        let mode = std::fs::metadata(userlist).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn existing_userlist_file_mode_is_preserved_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let userlist = dir.path().join("users");
        std::fs::write(&userlist, "alice:old\n").unwrap();
        std::fs::set_permissions(&userlist, std::fs::Permissions::from_mode(0o640)).unwrap();

        upsert_userlist_entry(&userlist, "alice", "alice:new").unwrap();

        let mode = std::fs::metadata(userlist).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }
}
