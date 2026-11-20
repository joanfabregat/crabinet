//! Startup-only account labels. IDs remain authoritative; labels are display-only.
use std::{collections::HashMap, fs::File, io::Read as _};

const MAX_ACCOUNT_FILE_BYTES: u64 = 1_048_576;
const MAX_ACCOUNTS: usize = 8192;

#[derive(Clone, Debug, Default)]
pub struct OwnerNames {
    pub(crate) users: HashMap<u32, String>,
    pub(crate) groups: HashMap<u32, String>,
}

impl OwnerNames {
    /// Read only the runtime's account files, never a user's requested path.
    pub(crate) fn load(users: HashMap<u32, String>, groups: HashMap<u32, String>) -> Self {
        let mut result = Self {
            users: read_accounts("/etc/passwd"),
            groups: read_accounts("/etc/group"),
        };
        result.users.extend(users);
        result.groups.extend(groups);
        result
    }

    pub(crate) fn user(&self, uid: u32) -> Option<&str> {
        self.users.get(&uid).map(String::as_str)
    }

    pub(crate) fn group(&self, gid: u32) -> Option<&str> {
        self.groups.get(&gid).map(String::as_str)
    }
}

pub(crate) fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.trim() == name
        && !name.chars().any(|c| c.is_control() || c == ':')
}

#[expect(
    clippy::disallowed_methods,
    reason = "startup-only: bounded reads of fixed runtime account files, without NSS plugins or network lookups"
)]
fn read_accounts(path: &str) -> HashMap<u32, String> {
    let mut bytes = Vec::new();
    // Startup only: callers supply exactly /etc/passwd or /etc/group above.
    // nosemgrep: crabinet-ambient-filesystem-path
    let Ok(file) = File::open(path) else {
        return HashMap::new();
    };
    if file
        .take(MAX_ACCOUNT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_ACCOUNT_FILE_BYTES
    {
        return HashMap::new();
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return HashMap::new();
    };
    parse_accounts(text)
}

fn parse_accounts(text: &str) -> HashMap<u32, String> {
    let mut result = HashMap::new();
    for line in text.lines().take(MAX_ACCOUNTS) {
        let mut fields = line.split(':');
        let Some(name) = fields.next().filter(|name| valid_account_name(name)) else {
            continue;
        };
        let Some(id) = fields.nth(1).and_then(|id| id.parse::<u32>().ok()) else {
            continue;
        };
        result.entry(id).or_insert_with(|| name.to_owned());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_files_are_bounded_labels_not_authorization_or_password_data() {
        let users = parse_accounts(
            "alice:x:1000:100:Alice:/home/alice:/bin/sh\nbob:secret:1001:100::/:/bin/sh\nother:x:1000:100::/:/bin/sh\nbad\n invalid:x:12\nroot:x:0:0",
        );
        assert_eq!(users.get(&1000).unwrap(), "alice");
        assert_eq!(users.get(&1001).unwrap(), "bob");
        assert_eq!(users.get(&0).unwrap(), "root");
        assert!(!users.contains_key(&12));
        let groups = parse_accounts("staff:x:100:alice,bob\nmissing:x:bad:\n");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups.get(&100).unwrap(), "staff");
        let bounded = parse_accounts(&format!("{}late:x:2\n", "a:x:1\n".repeat(MAX_ACCOUNTS)));
        assert_eq!(bounded.len(), 1);
        assert!(!bounded.contains_key(&2));
        assert!(!valid_account_name("bad\nname"));
        assert!(!valid_account_name(&"a".repeat(129)));
    }
}
