//! Structured security audit events.
//!
//! Every event carries `audit = true`, an `operation`, and an `outcome`, the
//! same shape as the mutation events in [`crate::mutations`]. Events are
//! emitted inside the request span, so the JSON log line also carries the
//! server-generated request ID. Passwords, hashes, cookies, session IDs,
//! CSRF tokens, OIDC codes and tokens, and file contents are never fields.

use std::net::IpAddr;

/// A successful sign-in. `client` is the resolved client address, the same
/// one the login limiters are keyed on.
pub(crate) fn sign_in_succeeded(operation: &'static str, subject: &str, client: Option<IpAddr>) {
    tracing::info!(
        audit = true,
        subject,
        operation,
        client_address = client.map(tracing::field::display),
        outcome = "success"
    );
}

/// A refused sign-in. `subject` is set only for a configured account;
/// `identifier` is a keyed digest of an attempted name that matched none,
/// so the log never stores what a user typed.
pub(crate) fn sign_in_rejected(
    operation: &'static str,
    reason: &'static str,
    subject: Option<&str>,
    identifier: Option<&str>,
    client: Option<IpAddr>,
) {
    tracing::warn!(
        audit = true,
        subject,
        identifier,
        operation,
        client_address = client.map(tracing::field::display),
        outcome = "rejected",
        reason
    );
}

/// An explicit sign-out of an authenticated session.
pub(crate) fn signed_out(subject: &str, client: Option<IpAddr>) {
    tracing::info!(
        audit = true,
        subject,
        operation = "logout",
        client_address = client.map(tracing::field::display),
        outcome = "success"
    );
}

/// A stored session refused and deleted on lookup: `expired` for an idle or
/// absolute timeout, `revoked` for a removed or disabled user.
pub(crate) fn session_ended(subject: &str, reason: &'static str) {
    tracing::info!(
        audit = true,
        subject,
        operation = "session",
        outcome = "ended",
        reason
    );
}

/// A request naming a share the subject has no grant for. The client still
/// receives the ordinary non-disclosing `404`.
pub(crate) fn access_denied(subject: &str, share_id: &str, operation: &str) {
    tracing::warn!(
        audit = true,
        subject,
        share_id,
        operation,
        outcome = "rejected",
        reason = "no_grant"
    );
}

#[cfg(test)]
pub(crate) mod capture {
    //! Log capture for tests.
    //!
    //! One process-wide subscriber is installed once and never replaced, so
    //! callsite interest is never cached against a short-lived scoped
    //! subscriber that another test thread raced with. Its writer appends to
    //! a buffer bound to the calling thread only; `#[tokio::test]` runs its
    //! current-thread runtime on that thread, so every handler event lands
    //! in the right test's buffer while events from parallel tests are
    //! dropped.

    use std::{
        cell::RefCell,
        io::Write,
        sync::{Arc, Mutex, Once},
    };

    type Buffer = Arc<Mutex<Vec<u8>>>;

    thread_local! {
        static CURRENT: RefCell<Option<Buffer>> = const { RefCell::new(None) };
    }

    struct ThreadWriter(Option<Buffer>);

    impl Write for ThreadWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if let Some(buffer) = &self.0 {
                buffer.lock().expect("log buffer").extend_from_slice(bytes);
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct ThreadMakeWriter;

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for ThreadMakeWriter {
        type Writer = ThreadWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            ThreadWriter(CURRENT.with(|current| current.borrow().clone()))
        }
    }

    /// Captured log output of the current thread until dropped.
    pub(crate) struct Capture {
        buffer: Buffer,
    }

    impl Capture {
        /// Returns and clears everything captured so far.
        pub(crate) fn take(&self) -> String {
            let bytes = std::mem::take(&mut *self.buffer.lock().expect("log buffer"));
            String::from_utf8(bytes).expect("UTF-8 logs")
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            CURRENT.with(|current| current.borrow_mut().take());
        }
    }

    /// Starts capturing events emitted on the current thread.
    pub(crate) fn start() -> Capture {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(ThreadMakeWriter)
                .with_ansi(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no other test installs a global subscriber");
        });
        // A callsite first reached by another thread while the subscriber
        // was being installed may hold stale interest; recompute it.
        tracing::callsite::rebuild_interest_cache();
        let buffer = Buffer::default();
        CURRENT.with(|current| *current.borrow_mut() = Some(Arc::clone(&buffer)));
        Capture { buffer }
    }
}
