//! Linux-only filesystem primitives used by the systemd installer.

use std::ffi::{CStr, CString};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const SYSTEMD_DIRECTORY: &CStr = c"/etc/systemd/system";
const MIGRATION_DIRECTORY: &CStr = c"alighieri.service.migration";
const UNIT_NAME: &str = "alighieri.service";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    HardLink,
    Exchange,
    RenameNoReplace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationEntry {
    Candidate,
    CandidateWitness,
    LinkProbe,
    Previous,
    PreviousStaged,
    RollbackDisplaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    Live,
    Staged(u32),
    Witness(u32),
    Rejected(u32),
    Retained,
    Migration(MigrationEntry),
}

impl Entry {
    fn leaf(self) -> CString {
        let name = match self {
            Self::Live => UNIT_NAME.to_owned(),
            Self::Staged(pid) => format!("{UNIT_NAME}.new.{pid}"),
            Self::Witness(pid) => format!("{UNIT_NAME}.new.{pid}.candidate"),
            Self::Rejected(pid) => format!("{UNIT_NAME}.rejected.{pid}"),
            Self::Retained => format!("{UNIT_NAME}.pre-migration"),
            Self::Migration(entry) => match entry {
                MigrationEntry::Candidate => "candidate".to_owned(),
                MigrationEntry::CandidateWitness => "candidate.witness".to_owned(),
                MigrationEntry::LinkProbe => "link.probe".to_owned(),
                MigrationEntry::Previous => "previous".to_owned(),
                MigrationEntry::PreviousStaged => "previous.staged".to_owned(),
                MigrationEntry::RollbackDisplaced => "rollback.displaced".to_owned(),
            },
        };
        // Every name is constructed from static text and a decimal u32.
        CString::new(name).expect("managed filesystem entry contains no NUL bytes")
    }

    fn is_migration(self) -> bool {
        matches!(self, Self::Migration(_))
    }
}

/// Perform an allowlisted operation relative to pinned systemd directories.
///
/// The caller supplies typed entries rather than paths. This ensures the kernel
/// sees only literal leaf names relative to descriptors opened without following
/// the systemd or migration directory itself.
pub fn perform(operation: Operation, source: Entry, destination: Entry) -> io::Result<()> {
    let directories =
        DirectorySet::open_system(source.is_migration() || destination.is_migration())?;
    directories.perform(operation, source, destination)
}

#[derive(Debug)]
struct DirectorySet {
    systemd: OwnedFd,
    migration: Option<OwnedFd>,
}

impl DirectorySet {
    fn open_system(needs_migration: bool) -> io::Result<Self> {
        Self::open_from_cstr(SYSTEMD_DIRECTORY, needs_migration, 0)
    }

    fn open_from_cstr(
        systemd_path: &CStr,
        needs_migration: bool,
        expected_owner: libc::uid_t,
    ) -> io::Result<Self> {
        let systemd = open_directory(systemd_path, expected_owner)?;
        let migration = needs_migration
            .then(|| open_migration_directory(systemd.as_raw_fd(), expected_owner))
            .transpose()?;
        Ok(Self { systemd, migration })
    }

    #[cfg(test)]
    fn open_from_path(
        systemd_path: &std::path::Path,
        needs_migration: bool,
        migration_owner: libc::uid_t,
    ) -> io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;

        let path = CString::new(systemd_path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "systemd test path contains a NUL byte",
            )
        })?;
        Self::open_from_cstr(&path, needs_migration, migration_owner)
    }

    fn entry_fd(&self, entry: Entry) -> io::Result<RawFd> {
        if entry.is_migration() {
            self.migration
                .as_ref()
                .map(AsRawFd::as_raw_fd)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "migration directory was not opened",
                    )
                })
        } else {
            Ok(self.systemd.as_raw_fd())
        }
    }

    fn perform(&self, operation: Operation, source: Entry, destination: Entry) -> io::Result<()> {
        if source == destination || !operation_is_allowed(operation, source, destination) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "operation is not permitted for these managed entries",
            ));
        }

        let source_fd = self.entry_fd(source)?;
        let destination_fd = self.entry_fd(destination)?;
        let source_leaf = source.leaf();
        let destination_leaf = destination.leaf();

        match operation {
            Operation::HardLink => {
                linkat(source_fd, &source_leaf, destination_fd, &destination_leaf)
            }
            Operation::Exchange => renameat2(
                source_fd,
                &source_leaf,
                destination_fd,
                &destination_leaf,
                libc::RENAME_EXCHANGE,
            ),
            Operation::RenameNoReplace => renameat2(
                source_fd,
                &source_leaf,
                destination_fd,
                &destination_leaf,
                libc::RENAME_NOREPLACE,
            ),
        }
    }
}

fn operation_is_allowed(operation: Operation, source: Entry, destination: Entry) -> bool {
    use Entry::{Live, Migration, Rejected, Retained, Staged, Witness};
    use MigrationEntry::{
        Candidate, CandidateWitness, LinkProbe, Previous, PreviousStaged, RollbackDisplaced,
    };

    match (operation, source, destination) {
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
        | (Operation::RenameNoReplace, Migration(RollbackDisplaced), Live)
        | (Operation::Exchange, Staged(_), Live)
        | (Operation::Exchange, Live, Staged(_))
        | (Operation::Exchange, Migration(Candidate), Live)
        | (Operation::Exchange, Live, Migration(Candidate)) => true,
        _ => false,
    }
}

fn open_directory(path: &CStr, expected_owner: libc::uid_t) -> io::Result<OwnedFd> {
    // SAFETY: `path` is NUL-terminated and remains alive for the call.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let directory = owned_fd(fd)?;
    let metadata = directory_metadata(directory.as_raw_fd())?;
    if metadata.st_uid != expected_owner || metadata.st_mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{path:?} must be owned by uid {expected_owner} and not group- or world-writable"
            ),
        ));
    }
    Ok(directory)
}

fn open_migration_directory(systemd_fd: RawFd, expected_owner: libc::uid_t) -> io::Result<OwnedFd> {
    // SAFETY: `MIGRATION_DIRECTORY` is a static NUL-terminated leaf name and
    // `systemd_fd` remains open for the call.
    let fd = unsafe {
        libc::openat(
            systemd_fd,
            MIGRATION_DIRECTORY.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let directory = owned_fd(fd)?;

    let metadata = directory_metadata(directory.as_raw_fd())?;
    let permissions = metadata.st_mode & 0o7777;
    if metadata.st_uid != expected_owner || permissions != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{MIGRATION_DIRECTORY:?} must be owned by uid {expected_owner} with mode 0700"),
        ));
    }
    Ok(directory)
}

fn directory_metadata(fd: RawFd) -> io::Result<libc::stat> {
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `metadata` points to enough writable storage for `fstat`, and the
    // caller keeps the descriptor open for the duration of the call.
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstat` initialized the complete structure.
    Ok(unsafe { metadata.assume_init() })
}

fn owned_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a successful `open`/`openat` returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn linkat(
    source_fd: RawFd,
    source: &CStr,
    destination_fd: RawFd,
    destination: &CStr,
) -> io::Result<()> {
    // SAFETY: both strings are NUL-terminated leaf names, and both descriptors
    // remain open for the call. A zero flag does not follow a symlink source.
    let result = unsafe {
        libc::linkat(
            source_fd,
            source.as_ptr(),
            destination_fd,
            destination.as_ptr(),
            0,
        )
    };
    syscall_result(result)
}

fn renameat2(
    source_fd: RawFd,
    source: &CStr,
    destination_fd: RawFd,
    destination: &CStr,
    flags: libc::c_uint,
) -> io::Result<()> {
    // SAFETY: both strings are NUL-terminated leaf names, and both descriptors
    // remain open for the call. Calling the kernel directly avoids raising the
    // minimum glibc version merely because old glibc omitted this wrapper.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            source_fd,
            source.as_ptr(),
            destination_fd,
            destination.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn syscall_result(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::Path;

    fn directories(root: &Path, needs_migration: bool) -> DirectorySet {
        // SAFETY: reading the effective uid has no preconditions.
        let owner = unsafe { libc::geteuid() };
        DirectorySet::open_from_path(root, needs_migration, owner).unwrap()
    }

    fn create_migration(root: &Path) {
        let path = root.join("alighieri.service.migration");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn hard_link_uses_exact_leaf_and_no_replace() {
        let root = tempfile::tempdir().unwrap();
        create_migration(root.path());
        let source = root.path().join("alighieri.service.migration/candidate");
        let destination = root.path().join("alighieri.service.pre-migration");
        std::fs::write(&source, b"legacy").unwrap();
        let directories = directories(root.path(), true);

        directories
            .perform(
                Operation::HardLink,
                Entry::Migration(MigrationEntry::Candidate),
                Entry::Retained,
            )
            .unwrap();
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&destination).unwrap().ino()
        );
        assert!(directories
            .perform(
                Operation::HardLink,
                Entry::Migration(MigrationEntry::Candidate),
                Entry::Retained,
            )
            .is_err());
    }

    #[test]
    fn platform_layer_rejects_unapproved_typed_pairs() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("alighieri.service"), b"live").unwrap();
        assert_eq!(
            directories(root.path(), false)
                .perform(Operation::HardLink, Entry::Live, Entry::Retained)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!root.path().join("alighieri.service.pre-migration").exists());
    }

    #[test]
    fn exchange_crosses_pinned_root_and_migration_directories() {
        let root = tempfile::tempdir().unwrap();
        create_migration(root.path());
        let live = root.path().join("alighieri.service");
        let candidate = root.path().join("alighieri.service.migration/candidate");
        std::fs::write(&live, b"old").unwrap();
        std::fs::write(&candidate, b"new").unwrap();

        directories(root.path(), true)
            .perform(
                Operation::Exchange,
                Entry::Migration(MigrationEntry::Candidate),
                Entry::Live,
            )
            .unwrap();

        assert_eq!(std::fs::read(live).unwrap(), b"new");
        assert_eq!(std::fs::read(candidate).unwrap(), b"old");
    }

    #[test]
    fn rename_no_replace_preserves_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        create_migration(root.path());
        let source = root.path().join("alighieri.service");
        let destination = root
            .path()
            .join("alighieri.service.migration/rollback.displaced");
        std::fs::write(&source, b"source").unwrap();
        std::fs::write(&destination, b"destination").unwrap();
        let directories = directories(root.path(), true);

        assert!(directories
            .perform(
                Operation::RenameNoReplace,
                Entry::Live,
                Entry::Migration(MigrationEntry::RollbackDisplaced),
            )
            .is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"source");
        assert_eq!(std::fs::read(&destination).unwrap(), b"destination");

        std::fs::remove_file(&destination).unwrap();
        directories
            .perform(
                Operation::RenameNoReplace,
                Entry::Live,
                Entry::Migration(MigrationEntry::RollbackDisplaced),
            )
            .unwrap();
        assert!(!source.exists());
        assert_eq!(std::fs::read(destination).unwrap(), b"source");
    }

    #[test]
    fn previous_snapshot_publication_is_atomic_and_no_replace() {
        let root = tempfile::tempdir().unwrap();
        create_migration(root.path());
        let staged = root
            .path()
            .join("alighieri.service.migration/previous.staged");
        let previous = root.path().join("alighieri.service.migration/previous");
        std::fs::write(&staged, b"complete snapshot").unwrap();
        let directories = directories(root.path(), true);

        directories
            .perform(
                Operation::RenameNoReplace,
                Entry::Migration(MigrationEntry::PreviousStaged),
                Entry::Migration(MigrationEntry::Previous),
            )
            .unwrap();
        assert!(!staged.exists());
        assert_eq!(std::fs::read(&previous).unwrap(), b"complete snapshot");

        std::fs::write(&staged, b"replacement").unwrap();
        assert!(directories
            .perform(
                Operation::RenameNoReplace,
                Entry::Migration(MigrationEntry::PreviousStaged),
                Entry::Migration(MigrationEntry::Previous),
            )
            .is_err());
        assert_eq!(std::fs::read(staged).unwrap(), b"replacement");
        assert_eq!(std::fs::read(previous).unwrap(), b"complete snapshot");
    }

    #[test]
    fn rejects_symlinked_migration_directory() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(
            outside.path(),
            root.path().join("alighieri.service.migration"),
        )
        .unwrap();

        let error = DirectorySet::open_from_path(
            root.path(),
            true,
            // SAFETY: reading the effective uid has no preconditions.
            unsafe { libc::geteuid() },
        )
        .unwrap_err();
        assert!(matches!(
            error.raw_os_error(),
            Some(libc::ELOOP | libc::ENOTDIR)
        ));
    }

    #[test]
    fn rejects_migration_directory_with_wrong_owner_or_mode() {
        let root = tempfile::tempdir().unwrap();
        create_migration(root.path());
        let migration = root.path().join("alighieri.service.migration");
        std::fs::set_permissions(&migration, std::fs::Permissions::from_mode(0o755)).unwrap();
        // SAFETY: reading the effective uid has no preconditions.
        let owner = unsafe { libc::geteuid() };
        assert_eq!(
            DirectorySet::open_from_path(root.path(), true, owner)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        std::fs::set_permissions(&migration, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            DirectorySet::open_from_path(root.path(), true, owner.wrapping_add(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn rejects_symlinked_systemd_directory() {
        let parent = tempfile::tempdir().unwrap();
        let actual = tempfile::tempdir().unwrap();
        let link = parent.path().join("system");
        symlink(actual.path(), &link).unwrap();

        let error = DirectorySet::open_from_path(
            &link,
            false,
            // SAFETY: reading the effective uid has no preconditions.
            unsafe { libc::geteuid() },
        )
        .unwrap_err();
        assert!(matches!(
            error.raw_os_error(),
            Some(libc::ELOOP | libc::ENOTDIR)
        ));
    }

    #[test]
    fn rejects_untrusted_systemd_directory_owner_or_mode() {
        let root = tempfile::tempdir().unwrap();
        // SAFETY: reading the effective uid has no preconditions.
        let owner = unsafe { libc::geteuid() };

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            DirectorySet::open_from_path(root.path(), false, owner)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            DirectorySet::open_from_path(root.path(), false, owner.wrapping_add(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
