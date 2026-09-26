use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PaymentError {
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("derivation error: {0}")]
    Derivation(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for PaymentError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let rpc_err = PaymentError::Rpc("connection refused".into());
        assert_eq!(rpc_err.to_string(), "rpc error: connection refused");

        let deriv_err = PaymentError::Derivation("invalid key".into());
        assert_eq!(deriv_err.to_string(), "derivation error: invalid key");

        let store_err = PaymentError::Store("duplicate key".into());
        assert_eq!(store_err.to_string(), "store error: duplicate key");

        let io_err = PaymentError::Io("file not found".into());
        assert_eq!(io_err.to_string(), "io error: file not found");
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "disk missing");
        let pay_err: PaymentError = io_err.into();
        assert!(matches!(pay_err, PaymentError::Io(ref s) if s.contains("disk missing")));
    }
}
