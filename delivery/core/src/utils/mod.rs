//! Delivery specific utils

#[cfg(any(test, feature = "mock-tls"))]
#[cfg_attr(docsrs, doc(cfg(feature = "mock-tls")))]
pub mod mock_tls;
