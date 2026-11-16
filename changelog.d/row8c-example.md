kind: installer worked example and plain-words constant
---
`secretant::installer::PLAIN_WORDS` and `plain_words(protection)`: the text of DESIGN 8.2 the installer shows before first use. `docs/INSTALLER-EXAMPLE.md` is the worked example; `tests/installer_example.rs` runs it end to end (store, recovery confirmation, secrets, place; a second run changes no file; no secret in anything shown, with a control) and checks the plain words against DESIGN 8.2 word for word and the document against the calls it names.
