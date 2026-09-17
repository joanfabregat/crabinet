#![forbid(unsafe_code)]

pub mod app;
pub mod assets;
pub mod auth;
pub mod browse;
pub mod config;
pub mod error;
pub mod filesystem;
pub mod mutations;
pub mod password;
pub mod preview;

pub const APP_NAME: &str = "index";
