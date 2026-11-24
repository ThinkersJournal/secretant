// SPDX-License-Identifier: MIT OR Apache-2.0
//! Item 1: the approval subject `NAME -> path`, parsed strictly. The person
//! sees the path whole: a path over the cap is refused, never clipped.
use secretant_mcp::subject::{MAX_SUBJECT_CHARS, SubjectError, format, parse};
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
    // user-request 0.17's strict rule: the WHOLE subject is at most 200.
    assert_eq!(MAX_SUBJECT_CHARS, 200);
    let room = MAX_SUBJECT_CHARS - "n -> ".len();
    let ok = format!("/{}", "a".repeat(room - 1));
    let s = format("n", Path::new(&ok)).unwrap();
    assert_eq!(s.chars().count(), 200);
    assert!(parse(&s).is_ok());
    let long = format!("/{}", "a".repeat(room));
    assert_eq!(format("n", Path::new(&long)), Err(SubjectError::TooLong));
    assert_eq!(parse(&format!("n -> {long}")), Err(SubjectError::TooLong));
    // a long name leaves less room for the path, never more.
    let name = "N".repeat(64);
    let path = format!("/{}", "a".repeat(200 - 64 - 4));
    assert_eq!(format(&name, Path::new(&path)), Err(SubjectError::TooLong));
}
