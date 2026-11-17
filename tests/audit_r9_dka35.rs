//! Audit Round 9 pin for finding DK-A35: the library's Error
//! answers its carried filesystem error through the standard
//! error chain. Before the repair the Error implementation
//! carried no source override, so a caller walking source()
//! from an Io error arrived at None and the filesystem failure
//! that explained the refusal stayed sealed inside the variant.
//! The second half of the pin fences the repair's shape: the
//! variants whose payloads are text, and the redemption refusal
//! variant, answer no source, because nothing stands beneath
//! them to source.

use std::error::Error as _;

use deadbolt::{Error, RedeemRefusal};

#[test]
fn the_io_variant_answers_its_carried_error_as_its_source() {
    let err: Error = std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "SYNTHETIC-TEST-VALUE-io-probe",
    )
    .into();
    let source = err
        .source()
        .expect("the carried filesystem error stands in the chain");
    let io = source
        .downcast_ref::<std::io::Error>()
        .expect("the source is the carried io error");
    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        io.to_string()
            .contains("the filesystem refused an operation"),
        "{io}"
    );
}

#[test]
fn the_text_and_refusal_variants_answer_no_source() {
    for err in [
        Error::Caller("probe".to_string()),
        Error::Refusal("probe".to_string()),
        Error::Corrupt("probe".to_string()),
        Error::Permission("probe".to_string()),
        Error::Redeem(RedeemRefusal::Expired),
    ] {
        assert!(err.source().is_none(), "{err}");
    }
}
