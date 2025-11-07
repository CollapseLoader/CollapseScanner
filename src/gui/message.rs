use std::path::PathBuf;

use crate::types::{DetectionMode, ScanResult};

#[derive(Debug, Clone)]
pub enum Message {
    SelectPath,
    PathSelected(Option<PathBuf>),
    PathInputChanged(String),

    ModeChanged(DetectionMode),
    VerboseToggled(bool),
    ExtractStringsToggled(bool),
    ExtractResourcesToggled(bool),
    ExportJsonToggled(bool),
    ThreadsChanged(String),

    ExcludePatternChanged(String),
    AddExcludePattern,
    RemoveExcludePattern(usize),
    FindPatternChanged(String),
    AddFindPattern,
    RemoveFindPattern(usize),

    StartScan,
    CancelScan,
    ScanCompleted(Result<Vec<ScanResult>, String>),
    Tick,

    TabSelected(usize),
    ClearResults,
    ExpandFinding(usize),
    ResultsSearchChanged(String),
    ResultsSeverityChanged(&'static str),
}
