use connectrpc::ConnectError;

use crate::ValidationError;

impl ValidationError {
    #[must_use]
    pub fn into_connect_error(self) -> ConnectError {
        ConnectError::invalid_argument(self.to_string())
    }
}
