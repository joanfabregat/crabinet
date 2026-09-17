use argon2::{Algorithm, Argon2, Params, Version, password_hash::PasswordHasher};
use thiserror::Error;

pub const PASSWORD_MEMORY_KIB: u32 = 65_536;
pub const PASSWORD_ITERATIONS: u32 = 3;
pub const PASSWORD_PARALLELISM: u32 = 1;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password must not be empty")]
    Empty,
    #[error("passwords do not match")]
    Mismatch,
    #[error("password hashing failed")]
    Hash,
}

/// Hashes a confirmed password with Argon2id v19 and a fresh random salt.
pub fn hash_confirmed(password: &str, confirmation: &str) -> Result<String, PasswordError> {
    if password.is_empty() {
        return Err(PasswordError::Empty);
    }
    if password != confirmation {
        return Err(PasswordError::Mismatch);
    }
    let parameters = Params::new(
        PASSWORD_MEMORY_KIB,
        PASSWORD_ITERATIONS,
        PASSWORD_PARALLELISM,
        None,
    )
    .map_err(|_| PasswordError::Hash)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters)
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|_| PasswordError::Hash)
}

#[cfg(test)]
mod tests {
    use argon2::{Argon2, PasswordHash, password_hash::PasswordVerifier};

    use super::*;

    #[test]
    fn produces_verifiable_argon2id_hash_with_random_salt() {
        let first = hash_confirmed(
            "correct horse battery staple",
            "correct horse battery staple",
        )
        .unwrap();
        let second = hash_confirmed(
            "correct horse battery staple",
            "correct horse battery staple",
        )
        .unwrap();
        assert!(first.starts_with("$argon2id$v=19$"));
        let parsed = PasswordHash::new(&first).unwrap();
        assert_eq!(parsed.params.get_decimal("m"), Some(PASSWORD_MEMORY_KIB));
        assert_eq!(parsed.params.get_decimal("t"), Some(PASSWORD_ITERATIONS));
        assert_eq!(parsed.params.get_decimal("p"), Some(PASSWORD_PARALLELISM));
        assert_ne!(first, second);
        assert!(
            Argon2::default()
                .verify_password(b"correct horse battery staple", &parsed)
                .is_ok()
        );
    }

    #[test]
    fn rejects_empty_and_mismatched_passwords() {
        assert!(matches!(hash_confirmed("", ""), Err(PasswordError::Empty)));
        assert!(matches!(
            hash_confirmed("one", "two"),
            Err(PasswordError::Mismatch)
        ));
    }
}
