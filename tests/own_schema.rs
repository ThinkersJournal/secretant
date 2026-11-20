// SPDX-License-Identifier: MIT OR Apache-2.0
//! SecretAnt's own ConfigurAnt schema (`configurant.toml`, ROADMAP row 10).
//!
//! Three rules, each with a negative control so a check that never ran cannot pass:
//! the file parses; no value takes `source = "secretant:..."` (the cycle check,
//! DESIGN section 6.3); and a canary placed in the secret setting's environment
//! variable appears nowhere in what the schema prints.

use configurant::{Loader, Schema};

const OWN: &str = include_str!("../configurant.toml");

/// The cycle check: the keys of every value that asks SecretAnt for its own start-up input.
fn cyclic_keys(schema: &Schema) -> Vec<String> {
    schema
        .values()
        .iter()
        .filter(|v| {
            v.source.as_deref().is_some_and(|s| {
                s.trim_start()
                    .to_ascii_lowercase()
                    .starts_with("secretant:")
            })
        })
        .map(|v| v.key.clone())
        .collect()
}

#[test]
fn own_schema_parses_and_declares_the_settings_that_exist() {
    let schema = Schema::parse(OWN).expect("configurant.toml must parse");
    assert!(schema.get("store.path").is_some());
    let pass = schema.get("unlock.passphrase").expect("unlock.passphrase");
    assert!(pass.secret, "the passphrase must be marked secret");
    assert_eq!(pass.env.as_deref(), Some("SECRETANT_PASSPHRASE"));
}

#[test]
fn own_schema_has_no_secretant_source() {
    let schema = Schema::parse(OWN).unwrap();
    assert_eq!(cyclic_keys(&schema), Vec::<String>::new());
}

#[test]
fn cycle_check_catches_a_secretant_source() {
    // Negative control: the same schema with one forbidden source must be reported.
    let bad = format!(
        "{OWN}\n[[value]]\nkey = \"web.token\"\ntype = \"string\"\nsecret = true\n\
         description = \"x\"\nsource = \"secretant:WEB_TOKEN\"\n"
    );
    // ConfigurAnt 0.7.2 accepts the `secretant:` scheme, so only this check stops it.
    let schema = Schema::parse(&bad).expect("parses");
    assert_eq!(cyclic_keys(&schema), vec!["web.token".to_string()]);
}

#[test]
fn a_canary_in_the_secret_setting_is_not_printed() {
    const CANARY: &str = "CANARY-9f3a1c77-own-schema";
    let schema = Schema::parse(OWN).unwrap();
    let help = schema.help();
    assert!(!help.contains(CANARY));
    let config = Loader::new(&schema)
        .env(std::collections::BTreeMap::from([(
            "SECRETANT_PASSPHRASE".to_string(),
            CANARY.to_string(),
        )]))
        .build()
        .expect("loads with the canary set");
    let shown = format!("{config:?}");
    assert!(!shown.contains(CANARY), "the secret leaked through Debug");
    // Positive control: the canary really was supplied (it is the ONLY way the check above can fail).
    assert_eq!(config.get::<String>("unlock.passphrase").unwrap(), CANARY);
}
