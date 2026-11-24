// SPDX-License-Identifier: MIT OR Apache-2.0
//! Item 1: the approval subject `NAME -> path`, parsed strictly. The person
//! sees the path whole: a path over the cap is refused, never clipped.
use secretant_mcp::subject::{MAX_PATH_CHARS, SubjectError, format, parse};
use std::path::Path;

#[test]
fn round_trips() {
    let s = format("proj_db", Path::new("/safe/db.secret")).unwrap();
    assert_eq!(s, "proj_db -> /safe/db.secret");
    let (n, p) = parse(&s).unwrap();
    assert_eq!(
        (n.as_str(), p.as_path()),
        ("proj_db", Path::new("/safe/db.secret"))
    );
}

#[test]
fn ambiguity_and_forgery_are_refused() {
    // A path that itself contains the separator could forge a second subject.
    assert_eq!(
        format("a", Path::new("/x -> /etc/passwd")),
        Err(SubjectError::Ambiguous)
    );
    // Controls, newlines, bidi overrides and zero-width marks.
    for bad in ["/x\ny", "/x\u{202e}y", "/x\u{200b}y", "/x\0y", "/x\ty"] {
        assert_eq!(
            format("a", Path::new(bad)),
            Err(SubjectError::Forbidden),
            "{bad:?}"
        );
    }
    assert_eq!(
        format("bad name", Path::new("/x")),
        Err(SubjectError::Forbidden)
    );
    assert_eq!(format("", Path::new("/x")), Err(SubjectError::Forbidden));
    // Parse is exact: one separator, no padding, no empty halves.
    for bad in [
        "a->/x",
        "a  -> /x",
        " a -> /x",
        "a -> ",
        " -> /x",
        "a -> /x -> /y",
        "a -> /x\n",
    ] {
        assert!(parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn over_the_cap_is_refused_whole() {
    let ok = format!("/{}", "a".repeat(MAX_PATH_CHARS - 1));
    assert!(format("n", Path::new(&ok)).is_ok());
    let long = format!("/{}", "a".repeat(MAX_PATH_CHARS));
    assert_eq!(format("n", Path::new(&long)), Err(SubjectError::TooLong));
    assert_eq!(parse(&format!("n -> {long}")), Err(SubjectError::TooLong));
}
