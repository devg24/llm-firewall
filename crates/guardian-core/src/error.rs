use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    ModelLoad(String),
    Tokenization(String),
    InferenceTimeout,
    TooManyRequests,
    TaskPanicked(String),
    PayloadValidation(String),
    Serialization(String),
    Internal(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::ModelLoad(msg) => write!(f, "Model load error: {}", msg),
            CoreError::Tokenization(msg) => write!(f, "Tokenization error: {}", msg),
            CoreError::InferenceTimeout => write!(f, "Inference timeout"),
            CoreError::TooManyRequests => write!(f, "Too many requests"),
            CoreError::TaskPanicked(msg) => write!(f, "Inference task panicked: {}", msg),
            CoreError::PayloadValidation(msg) => write!(f, "Payload validation error: {}", msg),
            CoreError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            CoreError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<serde_json::Error> for CoreError {
    fn from(err: serde_json::Error) -> Self {
        CoreError::Serialization(err.to_string())
    }
}

impl From<std::io::Error> for CoreError {
    fn from(err: std::io::Error) -> Self {
        CoreError::ModelLoad(err.to_string())
    }
}
