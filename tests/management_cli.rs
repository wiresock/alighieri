use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde::de::DeserializeOwned;
use serde::Deserialize;

const HASH_MARKER: &[u8] = b"$argon2id$";

#[derive(Debug, Deserialize)]
struct SuccessEnvelope<T> {
    schema_version: u32,
    ok: bool,
    operation: String,
    result: T,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    schema_version: u32,
    ok: bool,
    operation: String,
    error: ErrorBody,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    code: ErrorCode,
    message: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ErrorCode {
    InvalidArguments,
    InvalidUsername,
    InvalidPassword,
    PasswordInputTooLarge,
    ConfigLoadFailed,
    UserlistNotConfigured,
    UserlistNotActive,
    ExternalAuthBackend,
    RelativeUserlistNotSupported,
    UserlistReadFailed,
    UserlistParseFailed,
    UserlistUpdateFailed,
    UserNotFound,
    CredentialsRejected,
}

#[derive(Debug, Deserialize)]
struct CapabilitiesResult {
    product: String,
    version: String,
    target_os: String,
    target_arch: String,
    management_protocol_version: u32,
    features: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AddResult {
    username: String,
    userlist: String,
    config: Option<String>,
    action: String,
    changed: bool,
}

#[derive(Debug, Deserialize)]
struct DeleteResult {
    username: String,
    userlist: String,
    config: Option<String>,
    deleted: bool,
    changed: bool,
}

#[derive(Debug, Deserialize)]
struct ListResult {
    userlist: String,
    config: Option<String>,
    count: usize,
    users: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyResult {
    username: String,
    userlist: String,
    config: Option<String>,
    verified: bool,
}

fn invoke(args: Vec<OsString>, stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_alighieri"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    if let Some(mut child_stdin) = child.stdin.take() {
        child_stdin.write_all(stdin).unwrap();
    }
    child.wait_with_output().unwrap()
}

fn string_args(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn direct_user_args(
    command: &str,
    username: Option<&str>,
    userlist: &Path,
    options: &[&str],
) -> Vec<OsString> {
    let mut args = vec![OsString::from("user"), OsString::from(command)];
    if let Some(username) = username {
        args.push(OsString::from(username));
    }
    args.push(OsString::from("--userlist"));
    args.push(userlist.as_os_str().to_owned());
    args.extend(options.iter().map(OsString::from));
    args
}

fn config_user_args(
    command: &str,
    username: Option<&str>,
    config: &Path,
    options: &[&str],
) -> Vec<OsString> {
    let mut args = vec![OsString::from("user"), OsString::from(command)];
    if let Some(username) = username {
        args.push(OsString::from(username));
    }
    args.push(OsString::from("--config"));
    args.push(config.as_os_str().to_owned());
    args.extend(options.iter().map(OsString::from));
    args
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_machine_stream(output: &Output) {
    assert!(output.stderr.is_empty(), "{}", output_text(output));
    assert!(output.stdout.ends_with(b"\n"), "{}", output_text(output));
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1,
        "{}",
        output_text(output)
    );
    assert!(
        !contains_bytes(&output.stdout, HASH_MARKER),
        "machine output exposed an Argon2id hash: {}",
        output_text(output)
    );
}

fn parse_success<T: DeserializeOwned>(output: &Output, operation: &str) -> T {
    assert!(output.status.success(), "{}", output_text(output));
    assert_machine_stream(output);
    let envelope: SuccessEnvelope<T> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid success JSON ({error}): {}", output_text(output)));
    assert_eq!(envelope.schema_version, 1);
    assert!(envelope.ok);
    assert_eq!(envelope.operation, operation);
    envelope.result
}

fn parse_error(output: &Output, operation: &str, code: ErrorCode) -> String {
    assert!(!output.status.success(), "{}", output_text(output));
    assert_machine_stream(output);
    let envelope: ErrorEnvelope = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid error JSON ({error}): {}", output_text(output)));
    assert_eq!(envelope.schema_version, 1);
    assert!(!envelope.ok);
    assert_eq!(envelope.operation, operation);
    assert_eq!(envelope.error.code, code);
    assert!(!envelope.error.message.is_empty());
    envelope.error.message
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn assert_output_excludes(output: &Output, secret: &[u8]) {
    assert!(
        !contains_bytes(&output.stdout, secret),
        "stdout exposed secret bytes: {}",
        output_text(output)
    );
    assert!(
        !contains_bytes(&output.stderr, secret),
        "stderr exposed secret bytes: {}",
        output_text(output)
    );
}

fn write_config(path: &Path, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).unwrap();
}

#[test]
fn capabilities_json_reports_the_versioned_machine_contract() {
    let output = invoke(string_args(&["capabilities", "--json"]), b"");
    let result: CapabilitiesResult = parse_success(&output, "capabilities");

    assert_eq!(result.product, "alighieri");
    assert_eq!(result.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(result.target_os, std::env::consts::OS);
    assert_eq!(result.target_arch, std::env::consts::ARCH);
    assert_eq!(result.management_protocol_version, 1);
    assert_eq!(
        result.features,
        [
            "config.check-json",
            "user.add-json",
            "user.delete-json",
            "user.list-json",
            "user.verify-json",
            "user.password-stdin",
            "user.target-userlist",
            "user.target-config",
        ]
    );
}

#[test]
fn capabilities_unknown_options_are_rejected() {
    for args in [
        string_args(&["capabilities", "--unknown"]),
        string_args(&["capabilities", "--json", "--unknown"]),
    ] {
        let output = invoke(args, b"");
        assert!(!output.status.success(), "{}", output_text(&output));
    }
}

#[test]
fn user_add_update_list_and_verify_have_typed_json_and_preserve_password_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let userlist = dir.path().join("users");

    let first_password = b"first-LF-secret";
    let mut first_input = first_password.to_vec();
    first_input.push(b'\n');
    let output = invoke(
        direct_user_args(
            "add",
            Some("alice"),
            &userlist,
            &["--password-stdin", "--json"],
        ),
        &first_input,
    );
    assert_output_excludes(&output, first_password);
    let created: AddResult = parse_success(&output, "user.add");
    assert_eq!(created.username, "alice");
    assert_eq!(created.userlist, userlist.display().to_string());
    assert_eq!(created.config, None);
    assert_eq!(created.action, "created");
    assert!(created.changed);

    let spaced_password = b"  CRLF secret with spaces  ";
    let mut spaced_input = spaced_password.to_vec();
    spaced_input.extend_from_slice(b"\r\n");
    let output = invoke(
        direct_user_args(
            "add",
            Some("alice"),
            &userlist,
            &["--json", "--password-stdin"],
        ),
        &spaced_input,
    );
    assert_output_excludes(&output, spaced_password);
    let updated: AddResult = parse_success(&output, "user.add");
    assert_eq!(updated.username, "alice");
    assert_eq!(updated.userlist, userlist.display().to_string());
    assert_eq!(updated.config, None);
    assert_eq!(updated.action, "updated");
    assert!(updated.changed);

    let stored = fs::read(&userlist).unwrap();
    assert!(contains_bytes(&stored, HASH_MARKER));
    assert!(!contains_bytes(&stored, first_password));
    assert!(!contains_bytes(&stored, spaced_password));

    let output = invoke(direct_user_args("list", None, &userlist, &["--json"]), b"");
    let listed: ListResult = parse_success(&output, "user.list");
    assert_eq!(listed.userlist, userlist.display().to_string());
    assert_eq!(listed.config, None);
    assert_eq!(listed.count, 1);
    assert_eq!(listed.users, ["alice"]);

    let output = invoke(
        direct_user_args(
            "verify",
            Some("alice"),
            &userlist,
            &["--password-stdin", "--json"],
        ),
        &spaced_input,
    );
    assert_output_excludes(&output, spaced_password);
    let verified: VerifyResult = parse_success(&output, "user.verify");
    assert_eq!(verified.username, "alice");
    assert_eq!(verified.userlist, userlist.display().to_string());
    assert_eq!(verified.config, None);
    assert!(verified.verified);

    let trimmed_password = b"CRLF secret with spaces";
    let mut trimmed_input = trimmed_password.to_vec();
    trimmed_input.push(b'\n');
    let output = invoke(
        direct_user_args(
            "verify",
            Some("alice"),
            &userlist,
            &["--json", "--password-stdin"],
        ),
        &trimmed_input,
    );
    assert_output_excludes(&output, trimmed_password);
    let message = parse_error(&output, "user.verify", ErrorCode::CredentialsRejected);
    assert!(!message.contains("CRLF secret"));
}

#[test]
fn user_delete_reports_changed_and_idempotent_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    let userlist = dir.path().join("users");
    fs::write(&userlist, "alice:secret\nbob:other\n").unwrap();

    let output = invoke(
        direct_user_args("delete", Some("alice"), &userlist, &["--json"]),
        b"",
    );
    let deleted: DeleteResult = parse_success(&output, "user.delete");
    assert_eq!(deleted.username, "alice");
    assert_eq!(deleted.userlist, userlist.display().to_string());
    assert_eq!(deleted.config, None);
    assert!(deleted.deleted);
    assert!(deleted.changed);

    let output = invoke(
        direct_user_args("delete", Some("alice"), &userlist, &["--json"]),
        b"",
    );
    parse_error(&output, "user.delete", ErrorCode::UserNotFound);

    let output = invoke(
        direct_user_args(
            "delete",
            Some("alice"),
            &userlist,
            &["--if-present", "--json"],
        ),
        b"",
    );
    let absent: DeleteResult = parse_success(&output, "user.delete");
    assert_eq!(absent.username, "alice");
    assert_eq!(absent.userlist, userlist.display().to_string());
    assert_eq!(absent.config, None);
    assert!(!absent.deleted);
    assert!(!absent.changed);
    assert_eq!(fs::read_to_string(&userlist).unwrap(), "bob:other\n");
}

#[test]
fn password_stdin_rejects_extra_large_long_and_empty_add_records() {
    let dir = tempfile::tempdir().unwrap();

    let additional_secret = b"additional-line-secret";
    let output = invoke(
        direct_user_args(
            "add",
            Some("extra-lines"),
            &dir.path().join("extra-lines-users"),
            &["--password-stdin", "--json"],
        ),
        b"additional-line-secret\nsecond-record\n",
    );
    assert_output_excludes(&output, additional_secret);
    parse_error(&output, "user.add", ErrorCode::InvalidPassword);

    let oversized = vec![b'Z'; 259];
    let output = invoke(
        direct_user_args(
            "add",
            Some("oversized"),
            &dir.path().join("oversized-users"),
            &["--json", "--password-stdin"],
        ),
        &oversized,
    );
    assert_output_excludes(&output, &oversized[..32]);
    parse_error(&output, "user.add", ErrorCode::PasswordInputTooLarge);

    let too_long = vec![b'P'; 256];
    let output = invoke(
        direct_user_args(
            "add",
            Some("too-long"),
            &dir.path().join("too-long-users"),
            &["--password-stdin", "--json"],
        ),
        &too_long,
    );
    assert_output_excludes(&output, &too_long[..32]);
    parse_error(&output, "user.add", ErrorCode::InvalidPassword);

    let output = invoke(
        direct_user_args(
            "add",
            Some("empty"),
            &dir.path().join("empty-users"),
            &["--password-stdin", "--json"],
        ),
        b"\n",
    );
    parse_error(&output, "user.add", ErrorCode::InvalidPassword);
}

#[test]
fn password_stdin_accepts_255_bytes_and_preserves_empty_verify_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let userlist = dir.path().join("max-users");
    let password = vec![b'Q'; 255];
    let output = invoke(
        direct_user_args(
            "add",
            Some("max-password"),
            &userlist,
            &["--password-stdin", "--json"],
        ),
        &password,
    );
    assert_output_excludes(&output, &password[..32]);
    let result: AddResult = parse_success(&output, "user.add");
    assert_eq!(result.username, "max-password");
    assert_eq!(result.userlist, userlist.display().to_string());
    assert_eq!(result.config, None);
    assert_eq!(result.action, "created");
    assert!(result.changed);

    let empty_userlist = dir.path().join("empty-password-users");
    fs::write(&empty_userlist, "empty-user:\n").unwrap();
    let output = invoke(
        direct_user_args(
            "verify",
            Some("empty-user"),
            &empty_userlist,
            &["--password-stdin", "--json"],
        ),
        b"\n",
    );
    let result: VerifyResult = parse_success(&output, "user.verify");
    assert_eq!(result.username, "empty-user");
    assert_eq!(result.userlist, empty_userlist.display().to_string());
    assert_eq!(result.config, None);
    assert!(result.verified);
}

#[test]
fn malformed_user_json_invocations_return_typed_invalid_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("users").display().to_string();
    let config = dir.path().join("config").display().to_string();
    let cases = [
        ("user.add", vec!["user", "add", "alice", "--json"]),
        ("user", vec!["user", "--help", "--json"]),
        ("user", vec!["user", "--json", "--help"]),
        ("user.list", vec!["user", "list", "--json", "--userlist"]),
        ("user.list", vec!["user", "list", "--userlist", "--json"]),
        ("user.list", vec!["user", "list", "--config", "--json"]),
        (
            "user.list",
            vec!["user", "list", "--userlist", "--password-stdin", "--json"],
        ),
        (
            "user.list",
            vec!["user", "list", "--userlist", "--userlist", &path, "--json"],
        ),
        (
            "user.list",
            vec!["user", "list", "--userlist", &path, "--unknown", "--json"],
        ),
        (
            "user.list",
            vec![
                "user",
                "list",
                "--userlist",
                &path,
                "--password-stdin",
                "--json",
            ],
        ),
        (
            "user.delete",
            vec![
                "user",
                "delete",
                "alice",
                "--userlist",
                &path,
                "--password-stdin",
                "--json",
            ],
        ),
        (
            "user.add",
            vec![
                "user",
                "add",
                "alice",
                "--userlist",
                &path,
                "--if-present",
                "--json",
            ],
        ),
        (
            "user.verify",
            vec![
                "user",
                "verify",
                "alice",
                "--userlist",
                &path,
                "--if-present",
                "--json",
            ],
        ),
        (
            "user.add",
            vec![
                "user",
                "add",
                "alice",
                "--userlist",
                &path,
                "--config",
                &config,
                "--json",
            ],
        ),
        (
            "user.add",
            vec![
                "user",
                "add",
                "alice",
                "--userlist",
                &path,
                "--userlist",
                &path,
                "--json",
            ],
        ),
        (
            "user.add",
            vec![
                "user",
                "add",
                "alice",
                "--userlist",
                &path,
                "--password-stdin",
                "--password-stdin",
                "--json",
            ],
        ),
        (
            "user.delete",
            vec![
                "user",
                "delete",
                "alice",
                "--userlist",
                &path,
                "--if-present",
                "--if-present",
                "--json",
            ],
        ),
        (
            "user.list",
            vec!["user", "list", "--userlist", &path, "--json", "--json"],
        ),
        ("user", vec!["user", "unknown-command", "--json"]),
    ];

    for (operation, args) in cases {
        let output = invoke(string_args(&args), b"");
        parse_error(&output, operation, ErrorCode::InvalidArguments);
    }

    let rejected_secret = b"argv-secret-must-not-appear";
    let output = invoke(
        string_args(&[
            "user",
            "add",
            "alice",
            "--userlist",
            &path,
            "--password",
            "argv-secret-must-not-appear",
            "--json",
        ]),
        b"",
    );
    assert_output_excludes(&output, rejected_secret);
    parse_error(&output, "user.add", ErrorCode::InvalidArguments);
}

#[test]
fn user_add_json_option_cannot_be_consumed_as_a_missing_username() {
    let dir = tempfile::tempdir().unwrap();
    let userlist = dir.path().join("users");
    let original = b"keeper:existing-password\n";
    fs::write(&userlist, original).unwrap();
    let secret = b"must-not-create-an-option-named-user";
    let mut input = secret.to_vec();
    input.push(b'\n');

    let output = invoke(
        vec![
            OsString::from("user"),
            OsString::from("add"),
            OsString::from("--json"),
            OsString::from("--userlist"),
            userlist.as_os_str().to_owned(),
            OsString::from("--password-stdin"),
        ],
        &input,
    );

    assert_output_excludes(&output, secret);
    parse_error(&output, "user.add", ErrorCode::InvalidArguments);
    assert_eq!(fs::read(&userlist).unwrap(), original);
    assert!(!userlist.with_extension("bak").exists());
}

#[test]
fn user_json_distinguishes_invalid_usernames_and_userlist_failures() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing-users");
    let output = invoke(direct_user_args("list", None, &missing, &["--json"]), b"");
    parse_error(&output, "user.list", ErrorCode::UserlistReadFailed);

    let malformed = dir.path().join("malformed-users");
    fs::write(&malformed, "entry-without-a-colon\n").unwrap();
    let output = invoke(direct_user_args("list", None, &malformed, &["--json"]), b"");
    parse_error(&output, "user.list", ErrorCode::UserlistParseFailed);

    let output = invoke(
        direct_user_args(
            "add",
            Some("bad:name"),
            &dir.path().join("users"),
            &["--password-stdin", "--json"],
        ),
        b"secret-that-must-not-be-read\n",
    );
    assert_output_excludes(&output, b"secret-that-must-not-be-read");
    parse_error(&output, "user.add", ErrorCode::InvalidUsername);
}

#[test]
fn config_target_honors_includes_last_wins_and_returns_supplied_paths() {
    let dir = tempfile::tempdir().unwrap();
    let fragments = dir.path().join("conf.d");
    fs::create_dir(&fragments).unwrap();
    let first_userlist = dir.path().join("first-users");
    let final_userlist = dir.path().join("final-users");
    fs::write(&final_userlist, "bob:first\nalice:secret\nbob:last\n").unwrap();
    write_config(
        &fragments.join("10-users.conf"),
        format!("userlist: {}\n", first_userlist.display()),
    );
    write_config(
        &fragments.join("20-users.conf"),
        format!("userlist: {}\n", final_userlist.display()),
    );
    let config = dir.path().join("alighieri.conf");
    write_config(
        &config,
        "internal: 127.0.0.1:1080\nsocksmethod: username\ninclude: conf.d/*.conf\n",
    );

    let output = invoke(config_user_args("list", None, &config, &["--json"]), b"");
    let result: ListResult = parse_success(&output, "user.list");
    assert_eq!(result.userlist, final_userlist.display().to_string());
    assert_eq!(
        result.config.as_deref(),
        Some(config.to_string_lossy().as_ref())
    );
    assert_eq!(result.count, 2);
    assert_eq!(result.users, ["alice", "bob"]);
}

#[test]
fn config_target_reports_stable_resolution_errors() {
    let dir = tempfile::tempdir().unwrap();
    let absolute_userlist = dir.path().join("users");
    let cases = [
        (
            "missing-userlist.conf",
            "internal: 127.0.0.1:1080\nsocksmethod: username\n".to_string(),
            ErrorCode::UserlistNotConfigured,
        ),
        (
            "external.conf",
            "internal: 127.0.0.1:1080\nsocksmethod: username\nauth.command: verifier\n".to_string(),
            ErrorCode::ExternalAuthBackend,
        ),
        (
            "inactive.conf",
            format!(
                "internal: 127.0.0.1:1080\nsocksmethod: none\nuserlist: {}\n",
                absolute_userlist.display()
            ),
            ErrorCode::UserlistNotActive,
        ),
        (
            "relative.conf",
            "internal: 127.0.0.1:1080\nsocksmethod: username\nuserlist: users\n".to_string(),
            ErrorCode::RelativeUserlistNotSupported,
        ),
        (
            "malformed.conf",
            "internal: 127.0.0.1:1080\nunknown.setting: value\n".to_string(),
            ErrorCode::ConfigLoadFailed,
        ),
    ];

    for (name, contents, code) in cases {
        let config = dir.path().join(name);
        write_config(&config, contents);
        let output = invoke(config_user_args("list", None, &config, &["--json"]), b"");
        parse_error(&output, "user.list", code);
    }
}

#[test]
fn config_target_can_bootstrap_a_missing_absolute_userlist() {
    let dir = tempfile::tempdir().unwrap();
    let userlist = dir.path().join("new").join("users");
    fs::create_dir(userlist.parent().unwrap()).unwrap();
    let config = dir.path().join("bootstrap.conf");
    write_config(
        &config,
        format!(
            "internal: 127.0.0.1:1080\nsocksmethod: username\nuserlist: {}\n",
            userlist.display()
        ),
    );
    #[cfg(unix)]
    let config_identity = {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        fs::set_permissions(&config, fs::Permissions::from_mode(0o640)).unwrap();
        let metadata = fs::metadata(&config).unwrap();
        (metadata.uid(), metadata.gid())
    };
    let secret = b"bootstrap-stdin-secret";
    let mut input = secret.to_vec();
    input.push(b'\n');

    let output = invoke(
        config_user_args(
            "add",
            Some("bootstrap-user"),
            &config,
            &["--password-stdin", "--json"],
        ),
        &input,
    );
    assert_output_excludes(&output, secret);
    let result: AddResult = parse_success(&output, "user.add");
    assert_eq!(result.username, "bootstrap-user");
    assert_eq!(result.userlist, userlist.display().to_string());
    assert_eq!(
        result.config.as_deref(),
        Some(config.to_string_lossy().as_ref())
    );
    assert_eq!(result.action, "created");
    assert!(result.changed);
    let stored = fs::read(&userlist).unwrap();
    assert!(contains_bytes(&stored, HASH_MARKER));
    assert!(!contains_bytes(&stored, secret));
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let metadata = fs::metadata(&userlist).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
        assert_eq!((metadata.uid(), metadata.gid()), config_identity);
    }
}

#[test]
fn config_target_does_not_create_a_missing_userlist_parent() {
    let dir = tempfile::tempdir().unwrap();
    let missing_parent = dir.path().join("missing");
    let userlist = missing_parent.join("users");
    let config = dir.path().join("missing-parent.conf");
    write_config(
        &config,
        format!(
            "internal: 127.0.0.1:1080\nsocksmethod: username\nuserlist: {}\n",
            userlist.display()
        ),
    );
    let secret = b"missing-parent-secret";
    let mut input = secret.to_vec();
    input.push(b'\n');

    let output = invoke(
        config_user_args(
            "add",
            Some("bootstrap-user"),
            &config,
            &["--password-stdin", "--json"],
        ),
        &input,
    );

    assert_output_excludes(&output, secret);
    parse_error(&output, "user.add", ErrorCode::UserlistUpdateFailed);
    assert!(!missing_parent.exists());
}

#[test]
fn legacy_human_user_list_form_remains_compatible() {
    let dir = tempfile::tempdir().unwrap();
    let userlist = dir.path().join("users");
    fs::write(&userlist, "bob:one\nalice:two\n").unwrap();

    let output = invoke(direct_user_args("list", None, &userlist, &[]), b"");
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(output.stdout, b"alice\nbob\n");
    assert!(output.stderr.is_empty(), "{}", output_text(&output));
}
