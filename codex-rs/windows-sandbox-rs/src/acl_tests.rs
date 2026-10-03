use super::acl_api_result;
use super::deny_ace_already_present;
use super::ensure_allow_mask_aces_with_inheritance;
use super::ensure_handle_is_not_filesystem_root;
use super::fetch_dacl_handle;
use crate::token::LocalSid;
use crate::winutil::to_wide;
use pretty_assertions::assert_eq;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACL_SIZE_INFORMATION;
use windows_sys::Win32::Security::AclSizeInformation;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::SDDL_REVISION_1;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::GetAclInformation;
use windows_sys::Win32::Security::GetSecurityDescriptorControl;
use windows_sys::Win32::Security::SE_DACL_PROTECTED;
use windows_sys::Win32::Security::SetFileSecurityW;
use windows_sys::Win32::Security::UNPROTECTED_DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;

#[test]
fn deny_ace_update_failure_is_an_error() {
    let path = std::path::Path::new(r"C:\world-writable");
    let error = acl_api_result(path, "SetNamedSecurityInfoW", ERROR_ACCESS_DENIED)
        .expect_err("access denied must not look like an already-present ACE");

    assert_eq!(
        error.to_string(),
        r"SetNamedSecurityInfoW failed for C:\world-writable: 5"
    );
}

#[test]
fn deny_read_root_check_uses_the_open_handle() {
    let cwd = std::env::current_dir().expect("current directory");
    let root = cwd.ancestors().last().expect("filesystem root");
    let root_directory = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
        .expect("open filesystem root");
    let diagnostic_path = std::path::Path::new(r"C:\not-a-root");

    let error = ensure_handle_is_not_filesystem_root(&root_directory, diagnostic_path)
        .expect_err("classification must follow the root handle, not the diagnostic path");

    assert_eq!(
        error.to_string(),
        r"refusing to apply a deny-read ACE to filesystem root C:\not-a-root"
    );
}

#[test]
fn existing_deny_ace_is_visible_without_write_dac() {
    let target = tempfile::NamedTempFile::new().expect("temporary file");
    let sid = LocalSid::from_string("S-1-5-21-10-20-30-40").expect("test SID");
    let path = target.path();
    let psid = sid.as_ptr();
    assert!(unsafe { super::add_deny_read_ace(path, psid) }.expect("add deny ACE"));
    let already_present = unsafe {
        deny_ace_already_present(target.as_file(), path, &[psid], super::DenyAceKind::Read)
    }
    .expect("read existing deny ACE");
    assert!(already_present);
}

#[test]
fn revoking_absent_sid_preserves_child_null_dacl() {
    let parent = tempfile::tempdir().expect("parent directory");
    let child = parent.path().join("child");
    std::fs::create_dir(&child).expect("child directory");
    let sid = LocalSid::from_string("S-1-5-21-10-20-30-40").expect("absent SID");
    let other_sid = LocalSid::from_string("S-1-5-21-10-20-30-41").expect("inherited SID");

    unsafe {
        super::add_allow_ace(parent.path(), other_sid.as_ptr()).expect("inheritable parent ACE");
        let mut descriptor = std::ptr::null_mut();
        assert_ne!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                crate::winutil::to_wide("D:NO_ACCESS_CONTROL").as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            ),
            0,
        );
        // The legacy setter preserves a null DACL without applying automatic inheritance.
        let set = SetFileSecurityW(
            crate::winutil::to_wide(&child).as_ptr(),
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        LocalFree(descriptor as HLOCAL);
        assert_ne!(set, 0, "set an unprotected null DACL");
        for revoke in [false, true] {
            if revoke {
                super::revoke_ace(parent.path(), sid.as_ptr()).expect("revoke absent SID");
            }
            let (dacl, descriptor) = super::fetch_dacl_handle(&child).expect("child permissions");
            let mut control = 0;
            let mut revision = 0;
            let valid = GetSecurityDescriptorControl(descriptor, &mut control, &mut revision);
            LocalFree(descriptor as HLOCAL);

            assert_ne!(valid, 0, "read child inheritance flags");
            assert_eq!(control & SE_DACL_PROTECTED, 0, "child permits inheritance");
            assert!(
                dacl.is_null(),
                "revocation must preserve the child's null DACL"
            );
        }
    }
}

fn acl_snapshot(path: &Path) -> (u16, Vec<u8>) {
    unsafe {
        let (acl, descriptor) = fetch_dacl_handle(path).expect("read directory ACL");
        let mut control = 0;
        let mut revision = 0;
        assert_ne!(
            GetSecurityDescriptorControl(descriptor, &mut control, &mut revision),
            0
        );
        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        assert_ne!(
            GetAclInformation(
                acl,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ),
            0
        );
        let dacl =
            std::slice::from_raw_parts(acl.cast::<u8>(), info.AclBytesInUse as usize).to_vec();
        LocalFree(descriptor as HLOCAL);
        (control, dacl)
    }
}

#[test]
fn noninheriting_read_attributes_preserve_unprotected_child_dacl() {
    let parent = tempfile::tempdir().expect("create parent");
    let child = parent.path().join("child");
    let marker = LocalSid::from_string("S-1-5-21-915763429-1123581321-271828182-4243").unwrap();
    let target = LocalSid::from_string("S-1-5-21-915763429-1123581321-271828182-4244").unwrap();
    std::fs::create_dir(&child).unwrap();
    let original = acl_snapshot(&child).1;

    // Restore the original child DACL after adding an inheritable parent ACE.
    // An ordinary parent update would re-propagate this missing permission.
    unsafe {
        let (_, descriptor) = fetch_dacl_handle(&child).unwrap();
        ensure_allow_mask_aces_with_inheritance(
            parent.path(),
            &[marker.as_ptr()],
            FILE_READ_ATTRIBUTES,
            super::CONTAINER_INHERIT_ACE | super::OBJECT_INHERIT_ACE,
        )
        .unwrap();
        assert_ne!(
            acl_snapshot(&child).1,
            original,
            "child should inherit the ACE"
        );
        assert_ne!(
            SetFileSecurityW(
                to_wide(&child).as_ptr(),
                DACL_SECURITY_INFORMATION,
                descriptor
            ),
            0
        );
        LocalFree(descriptor as HLOCAL);
    }
    let before = acl_snapshot(&child);
    assert_eq!(before.0 & SE_DACL_PROTECTED, 0);

    assert!(unsafe {
        ensure_allow_mask_aces_with_inheritance(
            parent.path(),
            &[target.as_ptr()],
            FILE_READ_ATTRIBUTES,
            /*inheritance*/ 0,
        )
        .unwrap()
    });
    assert_eq!(acl_snapshot(&child), before);
}

// Use a synthetic restricting SID, never the real user's SID, so deny tests
// cannot lock the test process out of its temporary files.
fn restricted_access_allowed(path: &Path, psid: *mut c_void, desired: u32) -> bool {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::Security::AccessCheck;
    use windows_sys::Win32::Security::CreateRestrictedToken;
    use windows_sys::Win32::Security::DISABLE_MAX_PRIVILEGE;
    use windows_sys::Win32::Security::DuplicateToken;
    use windows_sys::Win32::Security::GENERIC_MAPPING;
    use windows_sys::Win32::Security::MapGenericMask;
    use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
    use windows_sys::Win32::Security::SecurityImpersonation;

    unsafe {
        let base = OwnedHandle::from_raw_handle(
            crate::token::get_current_token_for_restriction().expect("current token") as _,
        );
        let restricting = SID_AND_ATTRIBUTES {
            Sid: psid,
            Attributes: 0,
        };
        let mut restricted = std::ptr::null_mut();
        assert_ne!(
            CreateRestrictedToken(
                base.as_raw_handle() as _,
                DISABLE_MAX_PRIVILEGE,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                1,
                &restricting,
                &mut restricted,
            ),
            0,
            "create restricting token: {}",
            std::io::Error::last_os_error()
        );
        let restricted = OwnedHandle::from_raw_handle(restricted as _);
        let mut impersonation = std::ptr::null_mut();
        assert_ne!(
            DuplicateToken(
                restricted.as_raw_handle() as _,
                SecurityImpersonation,
                &mut impersonation
            ),
            0
        );
        let impersonation = OwnedHandle::from_raw_handle(impersonation as _);
        let mapping = GENERIC_MAPPING {
            GenericRead: super::FILE_GENERIC_READ,
            GenericWrite: super::FILE_GENERIC_WRITE,
            GenericExecute: super::FILE_GENERIC_EXECUTE,
            GenericAll: super::FILE_ALL_ACCESS,
        };
        let mut desired = desired;
        MapGenericMask(&mut desired, &mapping);
        let mut descriptor = std::ptr::null_mut();
        assert_eq!(
            windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW(
                to_wide(path).as_ptr(),
                1,
                DACL_SECURITY_INFORMATION
                    | windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION
                    | windows_sys::Win32::Security::GROUP_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            ),
            0,
            "AccessCheck requires the owner and group as well as the DACL"
        );
        let mut privileges = [0u64; 128];
        let mut privilege_bytes = std::mem::size_of_val(&privileges) as u32;
        let mut granted = 0;
        let mut allowed = 0;
        let checked = AccessCheck(
            descriptor,
            impersonation.as_raw_handle() as _,
            desired,
            &mapping,
            privileges.as_mut_ptr().cast(),
            &mut privilege_bytes,
            &mut granted,
            &mut allowed,
        );
        LocalFree(descriptor as HLOCAL);
        assert_ne!(
            checked,
            0,
            "AccessCheck: {}",
            std::io::Error::last_os_error()
        );
        allowed != 0
    }
}

fn install_legacy_deny(path: &Path, psid: *mut c_void, mask: u32) {
    use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
    use windows_sys::Win32::Security::Authorization::SetEntriesInAclW;
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::Authorization::TRUSTEE_W;
    unsafe {
        let (dacl, descriptor) = fetch_dacl_handle(path).unwrap();
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: super::DENY_ACCESS,
            grfInheritance: super::CONTAINER_INHERIT_ACE | super::OBJECT_INHERIT_ACE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: super::TRUSTEE_IS_SID,
                TrusteeType: super::TRUSTEE_IS_UNKNOWN,
                ptstrName: psid.cast(),
            },
        };
        let mut updated = std::ptr::null_mut();
        assert_eq!(SetEntriesInAclW(1, &entry, dacl, &mut updated), 0);
        let result = SetNamedSecurityInfoW(
            to_wide(path).as_ptr() as *mut u16,
            1,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            updated,
            std::ptr::null_mut(),
        );
        LocalFree(updated as HLOCAL);
        LocalFree(descriptor as HLOCAL);
        assert_eq!(result, 0);
    }
}

fn assert_single_deny(path: &Path, psid: *mut c_void, mask: u32, flags: u8) {
    use windows_sys::Win32::Security::ACCESS_DENIED_ACE;
    use windows_sys::Win32::Security::EqualSid;
    use windows_sys::Win32::Security::GetAce;
    unsafe {
        let (acl, descriptor) = fetch_dacl_handle(path).unwrap();
        let mut denies = Vec::new();
        for index in 0..u32::from((*acl).AceCount) {
            let mut ace = std::ptr::null_mut();
            assert_ne!(GetAce(acl, index, &mut ace), 0);
            let ace = &*ace.cast::<ACCESS_DENIED_ACE>();
            if ace.Header.AceType == super::ACCESS_DENIED_ACE_TYPE
                && EqualSid(std::ptr::addr_of!(ace.SidStart) as *mut c_void, psid) != 0
            {
                denies.push((ace.Mask, ace.Header.AceFlags));
            }
        }
        LocalFree(descriptor as HLOCAL);
        assert_eq!(denies, vec![(mask, flags)], "{}", path.display());
    }
}

#[test]
fn specific_denies_preserve_access_and_do_not_split_or_grow() {
    for (kind, generic) in [
        (super::DenyAceKind::Read, super::GENERIC_READ_MASK),
        (super::DenyAceKind::Write, super::GENERIC_WRITE_MASK),
    ] {
        let legacy = tempfile::tempdir().unwrap();
        let compact = tempfile::tempdir().unwrap();
        let sid = LocalSid::from_string("S-1-5-21-915763429-1123581321-271828182-4245").unwrap();
        let mask = kind.mask();
        // A real allow establishes that AccessCheck fails because of the deny,
        // rather than because the synthetic restricting SID lacks a grant.
        for root in [legacy.path(), compact.path()] {
            unsafe {
                super::ensure_allow_mask_aces(root, &[sid.as_ptr()], super::FILE_ALL_ACCESS)
                    .unwrap();
            }
            assert!(restricted_access_allowed(root, sid.as_ptr(), generic));
            std::fs::create_dir(root.join("existing")).unwrap();
            std::fs::write(root.join("existing/file"), b"test").unwrap();
        }
        install_legacy_deny(legacy.path(), sid.as_ptr(), mask | generic);
        assert!(unsafe { super::add_deny_ace(compact.path(), sid.as_ptr(), kind) }.unwrap());
        for root in [legacy.path(), compact.path()] {
            std::fs::create_dir(root.join("later")).unwrap();
            std::fs::create_dir(root.join("later/nested")).unwrap();
            std::fs::write(root.join("later/nested/file"), b"test").unwrap();
        }
        let paths = [
            "",
            "existing",
            "existing/file",
            "later",
            "later/nested",
            "later/nested/file",
        ];
        for relative in paths {
            let old = legacy.path().join(relative);
            let new = compact.path().join(relative);
            let flags = if relative.is_empty() {
                3
            } else if new.is_dir() {
                0x13
            } else {
                0x10
            };
            assert_single_deny(&new, sid.as_ptr(), mask, flags);
            assert!(!restricted_access_allowed(&new, sid.as_ptr(), generic));
            // Check every specific right, including unrelated rights, against
            // the legacy behavior on self, existing children and later descendants.
            for bit in 0..32 {
                let access = 1u32 << bit;
                if access & super::FILE_ALL_ACCESS != 0 {
                    assert_eq!(
                        restricted_access_allowed(&new, sid.as_ptr(), access),
                        restricted_access_allowed(&old, sid.as_ptr(), access),
                        "{relative}: access {access:#x}"
                    );
                }
            }
        }
        let before: Vec<_> = paths
            .iter()
            .map(|p| acl_snapshot(&compact.path().join(p)))
            .collect();
        // A second SID forces another native DACL update, which must not split
        // the first SID's ACE during automatic inheritance.
        let other = LocalSid::from_string("S-1-5-21-915763429-1123581321-271828182-4246").unwrap();
        assert!(unsafe { super::add_deny_ace(compact.path(), other.as_ptr(), kind) }.unwrap());
        for relative in paths {
            let path = compact.path().join(relative);
            let flags = if relative.is_empty() {
                3
            } else if path.is_dir() {
                0x13
            } else {
                0x10
            };
            assert_single_deny(&path, sid.as_ptr(), mask, flags);
            assert_single_deny(&path, other.as_ptr(), mask, flags);
        }
        let stable: Vec<_> = paths
            .iter()
            .map(|p| acl_snapshot(&compact.path().join(p)))
            .collect();
        for _ in 0..8 {
            for root in paths.map(|p| compact.path().join(p)) {
                assert!(!unsafe { super::add_deny_ace(&root, sid.as_ptr(), kind) }.unwrap());
                assert!(!unsafe { super::add_deny_ace(&root, other.as_ptr(), kind) }.unwrap());
            }
        }
        assert_eq!(
            paths
                .iter()
                .map(|p| acl_snapshot(&compact.path().join(p)))
                .collect::<Vec<_>>(),
            stable
        );
        assert!(
            stable
                .iter()
                .zip(before)
                .all(|(after, before)| after.1.len() == before.1.len() + 36)
        );
    }
}

fn ace_snapshot(path: &Path) -> Vec<Vec<u8>> {
    unsafe {
        let (acl, descriptor) = fetch_dacl_handle(path).unwrap();
        let mut entries = Vec::new();
        for index in 0..u32::from((*acl).AceCount) {
            let mut ace = std::ptr::null_mut();
            assert_ne!(super::GetAce(acl, index, &mut ace), 0);
            let header = &*ace.cast::<super::ACE_HEADER>();
            entries.push(
                std::slice::from_raw_parts(ace.cast::<u8>(), usize::from(header.AceSize)).to_vec(),
            );
        }
        LocalFree(descriptor as HLOCAL);
        entries
    }
}

#[test]
fn batch_write_denies_preserve_existing_aces_and_are_idempotent() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("protected");
    let existing = LocalSid::from_string("S-1-5-21-915763429-1123581321-271828182-4250").unwrap();
    let first = LocalSid::from_string("S-1-5-21-915763429-1123581321-271828182-4251").unwrap();
    let second = LocalSid::from_string("S-1-5-21-915763429-1123581321-271828182-4252").unwrap();
    let duplicate = LocalSid::from_string("S-1-5-21-915763429-1123581321-271828182-4251").unwrap();
    let marker = LocalSid::from_string("S-1-5-21-915763429-1123581321-271828182-4253").unwrap();
    unsafe {
        super::ensure_allow_mask_aces(parent.path(), &[marker.as_ptr()], super::FILE_GENERIC_READ)
            .unwrap();
    }
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("existing")).unwrap();
    std::fs::write(root.join("existing/file"), b"test").unwrap();
    let sids = [
        existing.as_ptr(),
        first.as_ptr(),
        second.as_ptr(),
        duplicate.as_ptr(),
    ];
    unsafe {
        super::ensure_allow_mask_aces(&root, &sids[..3], super::FILE_ALL_ACCESS).unwrap();
        assert!(super::add_deny_write_ace(&root, existing.as_ptr()).unwrap());
        assert!(super::add_deny_read_ace(&root, marker.as_ptr()).unwrap());
    }
    assert!(restricted_access_allowed(
        &root,
        first.as_ptr(),
        super::FILE_WRITE_DATA
    ));
    assert!(restricted_access_allowed(
        &root,
        second.as_ptr(),
        super::FILE_WRITE_DATA
    ));
    let before = ace_snapshot(&root);
    let control = acl_snapshot(&root).0;
    assert!(unsafe { super::add_deny_write_aces(&root, &sids) }.unwrap());
    let after = ace_snapshot(&root);
    assert_eq!(
        acl_snapshot(&root).0,
        control,
        "preserve inheritance control"
    );
    assert_eq!(after.len(), before.len() + 2, "only the two missing SIDs");
    for ace in &before {
        assert_eq!(
            after.iter().filter(|entry| *entry == ace).count(),
            before.iter().filter(|entry| *entry == ace).count(),
            "preserve every existing explicit and inherited ACE"
        );
    }
    std::fs::create_dir(root.join("later")).unwrap();
    std::fs::write(root.join("later/file"), b"test").unwrap();
    let paths = ["", "existing", "existing/file", "later", "later/file"];
    for relative in paths {
        let path = root.join(relative);
        let flags = if relative.is_empty() {
            3
        } else if path.is_dir() {
            0x13
        } else {
            0x10
        };
        for &sid in &sids[..3] {
            assert_single_deny(&path, sid, super::DenyAceKind::Write.mask(), flags);
            assert!(!restricted_access_allowed(
                &path,
                sid,
                super::FILE_WRITE_DATA
            ));
        }
    }
    // The READ_CONTROL-only fallback must recognize the entire batch, not just one SID.
    let read_handle = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&root)
        .unwrap();
    assert!(unsafe {
        deny_ace_already_present(&read_handle, &root, &sids, super::DenyAceKind::Write).unwrap()
    });
    assert!(!unsafe {
        deny_ace_already_present(
            &read_handle,
            &root,
            &[existing.as_ptr(), marker.as_ptr()],
            super::DenyAceKind::Write,
        )
        .unwrap()
    });
    let stable: Vec<_> = paths.iter().map(|p| acl_snapshot(&root.join(p))).collect();
    for _ in 0..3 {
        assert!(!unsafe { super::add_deny_write_aces(&root, &sids) }.unwrap());
        assert!(!unsafe { super::add_deny_write_ace(&root, first.as_ptr()) }.unwrap());
    }
    assert_eq!(
        paths
            .iter()
            .map(|p| acl_snapshot(&root.join(p)))
            .collect::<Vec<_>>(),
        stable
    );
}

#[test]
fn empty_write_deny_batch_does_not_open_the_path() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("absent");
    assert!(!unsafe { super::add_deny_write_aces(&missing, &[]) }.unwrap());
    assert!(!missing.exists());
}
