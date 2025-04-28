use indicatif;
use serde_json;
use std::io;
use thiserror::Error;
use zip;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Zip error: {0}")]
    ZipError(#[from] zip::result::ZipError),
    #[error("Class parse error in '{path}': {msg}")]
    ClassParseError { path: String, msg: String },
    #[error("Unsupported file type: {0:?}")]
    UnsupportedFileType(Option<std::ffi::OsString>),
    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Template error: {0}")]
    TemplateError(#[from] indicatif::style::TemplateError),
}
