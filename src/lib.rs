#![forbid(unsafe_code)]

pub mod app;
pub mod assets;
mod audit;
pub mod auth;
pub mod browse;
pub mod client_address;
pub mod config;
pub mod error;
mod extract;
pub mod filesystem;
pub(crate) mod folder_sizes;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
pub mod mutations;
pub mod oidc;
pub mod password;
pub mod preview;
pub mod server;
#[cfg(test)]
mod test_pki;
pub mod thumbnail;
mod zip;

pub const APP_NAME: &str = "crabinet";
