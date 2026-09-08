#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use std::io;

    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init()
        .map_err(|error| io::Error::other(format!("initialize logging: {error}")))?;

    match parse_command(std::env::args().skip(1))? {
        Command::Run => alighieri::rdp::windows::transport::run(),
        Command::Register { machine_wide } => {
            alighieri::rdp::windows::registration::register(machine_wide)?;
            println!(
                "Registered the Alighieri RDP transport for {}.",
                if machine_wide {
                    "this machine"
                } else {
                    "the current user"
                }
            );
            Ok(())
        }
        Command::Unregister { machine_wide } => {
            alighieri::rdp::windows::registration::unregister(machine_wide)?;
            println!(
                "Unregistered the Alighieri RDP transport for {}.",
                if machine_wide {
                    "this machine"
                } else {
                    "the current user"
                }
            );
            Ok(())
        }
        Command::Help => {
            print_help();
            Ok(())
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Run,
    Register { machine_wide: bool },
    Unregister { machine_wide: bool },
    Help,
}

#[cfg(windows)]
fn parse_command(arguments: impl IntoIterator<Item = String>) -> std::io::Result<Command> {
    use std::io;

    let mut action = None;
    let mut machine_wide = false;
    let mut embedding = false;
    for argument in arguments {
        match argument.to_ascii_lowercase().as_str() {
            "--register" | "register" | "/register" => set_action(&mut action, true)?,
            "--unregister" | "unregister" | "/unregister" => set_action(&mut action, false)?,
            "--machine" | "/machine" => machine_wide = true,
            "-embedding" | "/embedding" => embedding = true,
            "--help" | "-h" | "/?" => return Ok(Command::Help),
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown option '{unknown}'; use --help for usage"),
                ));
            }
        }
    }

    match action {
        Some(true) => Ok(Command::Register { machine_wide }),
        Some(false) => Ok(Command::Unregister { machine_wide }),
        None if machine_wide => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--machine requires --register or --unregister",
        )),
        None => {
            let _ = embedding;
            Ok(Command::Run)
        }
    }
}

#[cfg(windows)]
fn set_action(action: &mut Option<bool>, register: bool) -> std::io::Result<()> {
    if action.replace(register).is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "specify exactly one of --register or --unregister",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn print_help() {
    println!("Usage: alighieri-rdp-transport.exe [command] [options]");
    println!("  --register       Register the mstsc DVC AddIn and COM LocalServer");
    println!("  --unregister     Remove the Alighieri registration");
    println!("  --machine        Use machine-wide registration (requires elevation)");
    println!("  -Embedding       Run the COM LocalServer (normally passed by COM)");
    println!("  --help           Show this help");
    println!("With no command, the COM LocalServer runs in the foreground.");
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> std::io::Result<Command> {
        parse_command(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    #[test]
    fn parses_registration_scope_and_com_activation() {
        assert_eq!(
            parse(&["--register"]).unwrap(),
            Command::Register {
                machine_wide: false
            }
        );
        assert_eq!(
            parse(&["--unregister", "--machine"]).unwrap(),
            Command::Unregister { machine_wide: true }
        );
        assert_eq!(parse(&["-Embedding"]).unwrap(), Command::Run);
        assert_eq!(parse(&["--help"]).unwrap(), Command::Help);
    }

    #[test]
    fn rejects_ambiguous_commands_and_orphaned_scope() {
        assert!(parse(&["--register", "--unregister"]).is_err());
        assert!(parse(&["--register", "--register"]).is_err());
        assert!(parse(&["--machine"]).is_err());
        assert!(parse(&["--unknown"]).is_err());
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("alighieri-rdp-transport is available only on Windows");
    std::process::exit(1);
}
