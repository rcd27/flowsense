#[derive(Debug, thiserror::Error)]
pub enum FlowsenseError {
    #[error("capture on {iface}: {reason}")]
    CaptureOpen { iface: String, reason: String },

    #[error("config load {path}: {reason}")]
    ConfigLoad { path: String, reason: String },

    #[error("config: {0}")]
    Config(String),
}
