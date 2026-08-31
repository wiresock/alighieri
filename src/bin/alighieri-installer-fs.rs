//! Narrow filesystem companion for the Linux systemd installer.
//!
//! This binary is deliberately separate from the service payload selected by
//! `alighieri.sh --binary`. Release archives provide a version-matched copy,
//! which the installer stages in a root-controlled directory before invoking.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const PROTOCOL_VERSION: &str = "alighieri-installer-fs-v2";
const UNIT_DIRECTORY_PREFIX: &str = "/etc/systemd/system/";
const MIGRATION_DIRECTORY_PREFIX: &str = "/etc/systemd/system/alighieri.service.migration/";
const UNIT_NAME: &str = "alighieri.service";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    HardLink,
    Exchange,
    RenameNoReplace,
    BinaryHardLink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationPath {
    Candidate,
    CandidateWitness,
    LinkProbe,
    Previous,
    PreviousStaged,
    RollbackDisplaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedPath {
    Live,
    Staged(u32),
    Witness(u32),
    Rejected(u32),
    Retained,
    Migration(MigrationPath),
}

#[derive(Debug, PartialEq, Eq)]
struct Request {
    operation: Operation,
    parent: Option<PathBuf>,
    source: PathBuf,
    destination: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    ProtocolVersion,
    Validate,
    Mutate(Request),
}

fn main() -> ExitCode {
    let command = match parse_args_from(std::env::args_os().skip(1).collect()) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("alighieri-installer-fs: {error}");
            return ExitCode::FAILURE;
        }
    };

    let request = match command {
        Command::ProtocolVersion => {
            println!("{PROTOCOL_VERSION}");
            return ExitCode::SUCCESS;
        }
        Command::Validate => return ExitCode::SUCCESS,
        Command::Mutate(request) => request,
    };

    match execute(&request) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(parent) = &request.parent {
                eprintln!(
                    "alighieri-installer-fs: {:?} failed under '{}' for '{}' and '{}': {error}",
                    request.operation,
                    parent.display(),
                    request.source.display(),
                    request.destination.display()
                );
            } else {
                eprintln!(
                    "alighieri-installer-fs: {:?} failed for '{}' and '{}': {error}",
                    request.operation,
                    request.source.display(),
                    request.destination.display()
                );
            }
            ExitCode::FAILURE
        }
    }
}

fn parse_args_from(args: Vec<OsString>) -> Result<Command, String> {
    if args.len() == 1 && args[0] == "protocol-version" {
        return Ok(Command::ProtocolVersion);
    }

    if args.first().is_some_and(|arg| arg == "validate-request") {
        return parse_request(&args[1..]).map(|_| Command::Validate);
    }
    parse_request(&args).map(Command::Mutate)
}

fn parse_request(args: &[OsString]) -> Result<Request, String> {
    let operation = match args.first().and_then(|arg| arg.to_str()) {
        Some("hard-link") => Operation::HardLink,
        Some("exchange") => Operation::Exchange,
        Some("rename-noreplace") => Operation::RenameNoReplace,
        Some("binary-hard-link") => Operation::BinaryHardLink,
        Some(_) => return Err("unknown installer filesystem operation".into()),
        None => return Err(request_usage()),
    };

    if operation == Operation::BinaryHardLink {
        return parse_binary_hard_link_request(args);
    }
    if args.len() != 3 {
        return Err(request_usage());
    }

    let source = PathBuf::from(&args[1]);
    let destination = PathBuf::from(&args[2]);
    let source_kind = classify_unit_file_path(&source)?;
    let destination_kind = classify_unit_file_path(&destination)?;
    if source == destination {
        return Err("source and destination must be different paths".into());
    }
    validate_operation_paths(operation, source_kind, destination_kind)?;

    Ok(Request {
        operation,
        parent: None,
        source,
        destination,
    })
}

fn request_usage() -> String {
    "usage: alighieri-installer-fs protocol-version | [validate-request] OPERATION SOURCE DESTINATION | [validate-request] binary-hard-link PHYSICAL_PARENT SOURCE_LEAF WITNESS_LEAF".into()
}

fn parse_binary_hard_link_request(args: &[OsString]) -> Result<Request, String> {
    if args.len() != 4 {
        return Err(request_usage());
    }

    let parent = PathBuf::from(&args[1]);
    validate_physical_binary_parent(&parent)?;

    let source = PathBuf::from(&args[2]);
    let destination = PathBuf::from(&args[3]);
    let source_name = source
        .to_str()
        .ok_or("binary staged leaf is not valid UTF-8")?;
    let destination_name = destination
        .to_str()
        .ok_or("binary witness leaf is not valid UTF-8")?;
    if source.components().count() != 1 || destination.components().count() != 1 {
        return Err("binary witness source and destination must be exact leaf names".into());
    }

    let Some((binary_name, pid)) = source_name.rsplit_once(".new.") else {
        return Err("binary witness source must end in .new.<pid>".into());
    };
    if binary_name.is_empty() || parse_pid(pid).is_none() {
        return Err("binary witness source must end in .new.<positive-pid>".into());
    }
    if destination_name != format!("{source_name}.commit-witness") {
        return Err("binary witness destination must be SOURCE.commit-witness".into());
    }

    Ok(Request {
        operation: Operation::BinaryHardLink,
        parent: Some(parent),
        source,
        destination,
    })
}

fn validate_physical_binary_parent(parent: &Path) -> Result<(), String> {
    let parent = parent
        .to_str()
        .ok_or("binary witness parent is not valid UTF-8")?;
    if !parent.starts_with('/') {
        return Err("binary witness parent must be absolute".into());
    }
    if parent.len() > 1 && parent.ends_with('/') {
        return Err("binary witness parent must not have a trailing slash".into());
    }
    if parent != "/"
        && parent
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err("binary witness parent must be a canonical physical path".into());
    }
    Ok(())
}

fn classify_unit_file_path(path: &Path) -> Result<ManagedPath, String> {
    let Some(path) = path.to_str() else {
        return Err("unit-file path is not valid UTF-8".into());
    };

    if let Some(name) = path.strip_prefix(MIGRATION_DIRECTORY_PREFIX) {
        if name.is_empty() || name.contains('/') {
            return Err("migration path is not an exact managed directory entry".into());
        }
        let artifact = match name {
            "candidate" => MigrationPath::Candidate,
            "candidate.witness" => MigrationPath::CandidateWitness,
            "link.probe" => MigrationPath::LinkProbe,
            "previous" => MigrationPath::Previous,
            "previous.staged" => MigrationPath::PreviousStaged,
            "rollback.displaced" => MigrationPath::RollbackDisplaced,
            _ => return Err("migration artifact name is not permitted".into()),
        };
        return Ok(ManagedPath::Migration(artifact));
    }

    let Some(name) = path.strip_prefix(UNIT_DIRECTORY_PREFIX) else {
        return Err("unit-file path is outside the managed systemd directory".into());
    };
    if name.is_empty() || name.contains('/') {
        return Err("unit-file path is not an exact managed directory entry".into());
    }
    if name == UNIT_NAME {
        return Ok(ManagedPath::Live);
    }
    if name == "alighieri.service.pre-migration" {
        return Ok(ManagedPath::Retained);
    }

    let Some(suffix) = name.strip_prefix("alighieri.service.") else {
        return Err("unit-file path is not an Alighieri transaction artifact".into());
    };
    if let Some(tail) = suffix.strip_prefix("new.") {
        if let Some(pid) = tail.strip_suffix(".candidate").and_then(parse_pid) {
            return Ok(ManagedPath::Witness(pid));
        }
        if let Some(pid) = parse_pid(tail) {
            return Ok(ManagedPath::Staged(pid));
        }
    }
    if let Some(pid) = suffix.strip_prefix("rejected.").and_then(parse_pid) {
        return Ok(ManagedPath::Rejected(pid));
    }

    Err("unit-file transaction artifact name is invalid".into())
}

fn parse_pid(value: &str) -> Option<u32> {
    value
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 0 && !value.starts_with('0'))
}

fn validate_operation_paths(
    operation: Operation,
    source: ManagedPath,
    destination: ManagedPath,
) -> Result<(), String> {
    use ManagedPath::{Live, Migration, Rejected, Retained, Staged, Witness};
    use MigrationPath::{
        Candidate, CandidateWitness, LinkProbe, Previous, PreviousStaged, RollbackDisplaced,
    };

    let allowed = match (operation, source, destination) {
        (Operation::HardLink, Staged(source), Witness(destination)) => source == destination,
        (Operation::HardLink, Migration(Candidate), Migration(CandidateWitness | LinkProbe))
        | (Operation::HardLink, Migration(Candidate), Retained)
        | (Operation::HardLink, Migration(Previous | RollbackDisplaced), Live)
        | (Operation::RenameNoReplace, Staged(_), Migration(Candidate))
        | (Operation::RenameNoReplace, Staged(_), Live)
        | (Operation::RenameNoReplace, Live, Rejected(_))
        | (Operation::RenameNoReplace, Rejected(_), Live)
        | (Operation::RenameNoReplace, Migration(PreviousStaged), Migration(Previous))
        | (Operation::RenameNoReplace, Live, Migration(RollbackDisplaced))
        | (Operation::RenameNoReplace, Migration(RollbackDisplaced), Live) => true,
        (Operation::Exchange, Staged(_), Live)
        | (Operation::Exchange, Live, Staged(_))
        | (Operation::Exchange, Migration(Candidate), Live)
        | (Operation::Exchange, Live, Migration(Candidate)) => true,
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err("operation is not permitted for these transaction paths".into())
    }
}

#[cfg(target_os = "linux")]
fn execute(request: &Request) -> io::Result<()> {
    use alighieri::platform::linux::{self, Entry, MigrationEntry};

    if request.operation == Operation::BinaryHardLink {
        let parent = request.parent.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "binary hard-link request has no physical parent",
            )
        })?;
        return linux::hard_link_binary_witness(
            parent,
            request.source.as_os_str(),
            request.destination.as_os_str(),
        );
    }

    fn entry(path: &Path) -> io::Result<Entry> {
        let classified = classify_unit_file_path(path)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(match classified {
            ManagedPath::Live => Entry::Live,
            ManagedPath::Staged(pid) => Entry::Staged(pid),
            ManagedPath::Witness(pid) => Entry::Witness(pid),
            ManagedPath::Rejected(pid) => Entry::Rejected(pid),
            ManagedPath::Retained => Entry::Retained,
            ManagedPath::Migration(path) => Entry::Migration(match path {
                MigrationPath::Candidate => MigrationEntry::Candidate,
                MigrationPath::CandidateWitness => MigrationEntry::CandidateWitness,
                MigrationPath::LinkProbe => MigrationEntry::LinkProbe,
                MigrationPath::Previous => MigrationEntry::Previous,
                MigrationPath::PreviousStaged => MigrationEntry::PreviousStaged,
                MigrationPath::RollbackDisplaced => MigrationEntry::RollbackDisplaced,
            }),
        })
    }

    let operation = match request.operation {
        Operation::HardLink => linux::Operation::HardLink,
        Operation::Exchange => linux::Operation::Exchange,
        Operation::RenameNoReplace => linux::Operation::RenameNoReplace,
        Operation::BinaryHardLink => unreachable!("handled above"),
    };
    linux::perform(
        operation,
        entry(&request.source)?,
        entry(&request.destination)?,
    )
}

#[cfg(not(target_os = "linux"))]
fn execute(_request: &Request) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "installer filesystem operations are available only on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn request(values: &[&str]) -> Request {
        let Command::Mutate(request) = parse_args_from(args(values)).unwrap() else {
            panic!("expected a mutating request");
        };
        request
    }

    #[test]
    fn protocol_version_is_an_exact_standalone_command() {
        assert_eq!(
            parse_args_from(args(&["protocol-version"])),
            Ok(Command::ProtocolVersion)
        );
        assert_eq!(PROTOCOL_VERSION, "alighieri-installer-fs-v2");
        assert!(parse_args_from(args(&[
            "protocol-version",
            "/etc/systemd/system/alighieri.service"
        ]))
        .is_err());
    }

    #[test]
    fn validation_command_reuses_the_mutation_parser_and_allowlist() {
        let staged = "/etc/systemd/system/alighieri.service.new.42";
        let live = "/etc/systemd/system/alighieri.service";
        assert_eq!(
            parse_args_from(args(&["validate-request", "exchange", staged, live])),
            Ok(Command::Validate)
        );
        assert_eq!(
            parse_args_from(args(&[
                "validate-request",
                "binary-hard-link",
                "/usr/local/bin",
                "alighieri.new.42",
                "alighieri.new.42.commit-witness",
            ])),
            Ok(Command::Validate)
        );

        assert!(parse_args_from(args(&["validate-request", "hard-link", staged, live])).is_err());
        assert!(parse_args_from(args(&["validate-request", "exchange", staged])).is_err());
        assert!(parse_args_from(args(&[
            "validate-request",
            "exchange",
            staged,
            live,
            "extra"
        ]))
        .is_err());
    }

    #[test]
    fn parses_exact_binary_witness_siblings_under_a_physical_parent() {
        assert_eq!(
            request(&[
                "binary-hard-link",
                "/usr/local/bin",
                "alighieri.new.42",
                "alighieri.new.42.commit-witness",
            ]),
            Request {
                operation: Operation::BinaryHardLink,
                parent: Some(PathBuf::from("/usr/local/bin")),
                source: PathBuf::from("alighieri.new.42"),
                destination: PathBuf::from("alighieri.new.42.commit-witness"),
            }
        );
    }

    #[test]
    fn rejects_aliased_parents_and_non_exact_binary_witness_names() {
        for arguments in [
            [
                "binary-hard-link",
                "usr/local/bin",
                "alighieri.new.42",
                "alighieri.new.42.commit-witness",
            ],
            [
                "binary-hard-link",
                "/usr//local/bin",
                "alighieri.new.42",
                "alighieri.new.42.commit-witness",
            ],
            [
                "binary-hard-link",
                "/usr/local/../bin",
                "alighieri.new.42",
                "alighieri.new.42.commit-witness",
            ],
            [
                "binary-hard-link",
                "/usr/local/bin",
                "subdir/alighieri.new.42",
                "alighieri.new.42.commit-witness",
            ],
            [
                "binary-hard-link",
                "/usr/local/bin",
                "alighieri.new.0",
                "alighieri.new.0.commit-witness",
            ],
            [
                "binary-hard-link",
                "/usr/local/bin",
                "alighieri.new.042",
                "alighieri.new.042.commit-witness",
            ],
            [
                "binary-hard-link",
                "/usr/local/bin",
                "alighieri.new.42",
                "other.new.42.commit-witness",
            ],
        ] {
            assert!(
                parse_args_from(args(&arguments)).is_err(),
                "expected {arguments:?} to be rejected"
            );
        }
    }

    #[test]
    fn parses_every_permitted_flat_operation_shape() {
        let staged = "/etc/systemd/system/alighieri.service.new.42";
        let witness = "/etc/systemd/system/alighieri.service.new.42.candidate";
        let rejected = "/etc/systemd/system/alighieri.service.rejected.42";
        let live = "/etc/systemd/system/alighieri.service";

        for values in [
            ["hard-link", staged, witness],
            ["exchange", staged, live],
            ["exchange", live, staged],
            ["rename-noreplace", staged, live],
            ["rename-noreplace", live, rejected],
            ["rename-noreplace", rejected, live],
        ] {
            request(&values);
        }
    }

    #[test]
    fn parses_every_permitted_migration_operation_shape() {
        let live = "/etc/systemd/system/alighieri.service";
        let staged = "/etc/systemd/system/alighieri.service.new.42";
        let retained = "/etc/systemd/system/alighieri.service.pre-migration";
        let candidate = "/etc/systemd/system/alighieri.service.migration/candidate";
        let witness = "/etc/systemd/system/alighieri.service.migration/candidate.witness";
        let probe = "/etc/systemd/system/alighieri.service.migration/link.probe";
        let previous = "/etc/systemd/system/alighieri.service.migration/previous";
        let previous_staged = "/etc/systemd/system/alighieri.service.migration/previous.staged";
        let displaced = "/etc/systemd/system/alighieri.service.migration/rollback.displaced";

        for values in [
            ["hard-link", candidate, witness],
            ["hard-link", candidate, probe],
            ["hard-link", candidate, retained],
            ["hard-link", previous, live],
            ["hard-link", displaced, live],
            ["exchange", candidate, live],
            ["exchange", live, candidate],
            ["rename-noreplace", staged, candidate],
            ["rename-noreplace", previous_staged, previous],
            ["rename-noreplace", live, displaced],
            ["rename-noreplace", displaced, live],
        ] {
            request(&values);
        }
    }

    #[test]
    fn accepts_only_exact_managed_paths() {
        for (path, expected) in [
            ("/etc/systemd/system/alighieri.service", ManagedPath::Live),
            (
                "/etc/systemd/system/alighieri.service.new.42",
                ManagedPath::Staged(42),
            ),
            (
                "/etc/systemd/system/alighieri.service.new.42.candidate",
                ManagedPath::Witness(42),
            ),
            (
                "/etc/systemd/system/alighieri.service.rejected.42",
                ManagedPath::Rejected(42),
            ),
            (
                "/etc/systemd/system/alighieri.service.pre-migration",
                ManagedPath::Retained,
            ),
            (
                "/etc/systemd/system/alighieri.service.migration/candidate",
                ManagedPath::Migration(MigrationPath::Candidate),
            ),
            (
                "/etc/systemd/system/alighieri.service.migration/rollback.displaced",
                ManagedPath::Migration(MigrationPath::RollbackDisplaced),
            ),
            (
                "/etc/systemd/system/alighieri.service.migration/previous.staged",
                ManagedPath::Migration(MigrationPath::PreviousStaged),
            ),
        ] {
            assert_eq!(classify_unit_file_path(Path::new(path)), Ok(expected));
        }
    }

    #[test]
    fn rejects_traversal_aliases_and_unmanaged_artifacts() {
        for path in [
            "/tmp/alighieri.service",
            "/etc/systemd/system/other.service",
            "/etc/systemd/system//alighieri.service",
            "/etc/systemd/system/./alighieri.service",
            "/etc/systemd/system/subdir/../alighieri.service",
            "/etc/systemd/system/alighieri.service/../alighieri.service",
            "/etc/systemd/system/alighieri.service.new",
            "/etc/systemd/system/alighieri.service.new.0",
            "/etc/systemd/system/alighieri.service.new.042",
            "/etc/systemd/system/alighieri.service.new.not-a-pid",
            "/etc/systemd/system/alighieri.service.rejected.42.candidate",
            "/etc/systemd/system/alighieri.service.migration",
            "/etc/systemd/system/alighieri.service.migration/",
            "/etc/systemd/system/alighieri.service.migration/../alighieri.service",
            "/etc/systemd/system/alighieri.service.migration/./candidate",
            "/etc/systemd/system/alighieri.service.migration/subdir/candidate",
            "/etc/systemd/system/alighieri.service.migration/candidate.snapshot",
            "/etc/systemd/system/alighieri.service.migration/binary-commit-intent",
            "/etc/systemd/system/alighieri.service.migration/previous.extra",
        ] {
            assert!(
                classify_unit_file_path(Path::new(path)).is_err(),
                "expected {path} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_valid_paths_in_unapproved_combinations() {
        let live = "/etc/systemd/system/alighieri.service";
        let staged = "/etc/systemd/system/alighieri.service.new.42";
        let other_witness = "/etc/systemd/system/alighieri.service.new.43.candidate";
        let retained = "/etc/systemd/system/alighieri.service.pre-migration";
        let candidate = "/etc/systemd/system/alighieri.service.migration/candidate";
        let previous = "/etc/systemd/system/alighieri.service.migration/previous";
        let previous_staged = "/etc/systemd/system/alighieri.service.migration/previous.staged";
        for arguments in [
            ["hard-link", staged, live],
            ["hard-link", staged, other_witness],
            ["hard-link", previous, retained],
            ["exchange", previous, live],
            ["rename-noreplace", previous, previous_staged],
            ["rename-noreplace", previous_staged, live],
            ["rename-noreplace", live, candidate],
            ["rename-noreplace", candidate, live],
        ] {
            assert!(
                parse_args_from(args(&arguments)).is_err(),
                "expected {arguments:?} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_unknown_missing_extra_and_same_path_arguments() {
        let live = "/etc/systemd/system/alighieri.service";
        let staged = "/etc/systemd/system/alighieri.service.new.42";
        assert!(parse_args_from(args(&["unknown", staged, live])).is_err());
        assert!(parse_args_from(args(&["exchange", staged])).is_err());
        assert!(parse_args_from(args(&["exchange", staged, live, "extra"])).is_err());
        assert!(parse_args_from(args(&["exchange", live, live])).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt;

        let invalid = OsString::from_vec(vec![b'/', 0xff]);
        assert!(parse_args_from(vec![
            OsString::from("exchange"),
            invalid,
            OsString::from("/etc/systemd/system/alighieri.service"),
        ])
        .is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_build_fails_closed() {
        let request = request(&[
            "exchange",
            "/etc/systemd/system/alighieri.service.new.42",
            "/etc/systemd/system/alighieri.service",
        ]);
        assert_eq!(
            execute(&request).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
