pub mod models;
pub mod canonical;
pub mod crypto;
pub mod trust;

#[cfg(test)]
mod models_test;

#[cfg(test)]
mod trust_test;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(version(), "0.1.0");
    }
}
