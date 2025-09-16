use serde::Deserialize;

#[derive(Deserialize)]
pub struct TransactionReceiptResponse<T> {
    result: T,
}

impl<T> TransactionReceiptResponse<T> {
    pub fn result(self) -> T {
        self.result
    }
}
