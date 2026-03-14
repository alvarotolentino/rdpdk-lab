use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetShieldError {
    #[error("packet parse error: {0}")]
    PacketParse(&'static str),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },
}
