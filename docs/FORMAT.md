# The store and export-bundle file format (format 1)

`docs/DESIGN.md` section 9.5 promises the bundle format is documented so a person is never locked in. This is that document, written from `src/store.rs`
at the commit that adds it. An export bundle is **a store file** with one passphrase wrap: there is one format.

## Container

A UTF-8 JSON object:

```
{
  "format": 1,
  "wraps": [ { "kind": ..., "salt": ..., "kdf": ..., "nonce": ..., "wrapped": ... }, ... ],
  "nonce": "<48 hex digits>",
  "ciphertext": "<hex>"
}
```

All binary values are lowercase hexadecimal. A reader refuses a `format` it does not know.

## Payload

`ciphertext` is the XChaCha20-Poly1305 encryption (24-byte `nonce`, 16-byte tag at the end, associated data the ASCII bytes `secretant-1-data`) of a JSON
object under a random 256-bit **data key**:

```
{ "entries": { "<name>": [ { "v": 1, "at": <unix seconds>, "value": "<hex>", "meta": { "<k>": "<v>" } }, ... ] } }
```

Versions of one name are in order, `v` counts from 1, `value` is the secret's bytes in hex, `meta` is non-secret text that callers must not use for secrets.

## Wraps (what unlocks the data key)

Each wrap independently encrypts the same data key (XChaCha20-Poly1305, associated data `secretant-1-wrap`); any one opens the store.

| `kind` | key that seals the data key | fields |
|---|---|---|
| `passphrase` | Argon2id (version 0x13) over the passphrase bytes, 16-byte `salt`, cost `kdf` = `{ "m_kib", "t", "p" }`, 32-byte output | `salt`, `kdf`, `nonce`, `wrapped` |
| `recovery` | a random 256-bit key, shown to the owner once as 64 hex digits in groups of 8 joined by `-`, never stored | `nonce`, `wrapped` |
| `os-dpapi` | Windows DPAPI (current user) protects the data key; `wrapped` is the DPAPI blob | `wrapped` |

A reader refuses `kdf` values outside its bounds (so a hostile file cannot demand absurd cost): 1 to 16 lanes, 1 to 20 passes, memory from 8 KiB per lane to 1 GiB.

## Export bundle

`FileStore::export_to` writes every entry, version, time and metadata into a store file created with the bundle's **own passphrase** (one `passphrase`
wrap, no recovery or OS wrap). To read a bundle by hand: parse the container, derive the key from the bundle passphrase with the `kdf` and `salt`, decrypt
`wrapped` to the data key, decrypt `ciphertext`.

## Previous generation

Every write keeps the previous file beside it as `<path>.prev`, and a temporary `<path>.tmp` exists only while a write is in progress (a leftover
`.tmp` means an interrupted write; the store itself is intact).

## What is not in the file

No key, passphrase or recovery text appears in it in any encoding (asserted by the canary tests in `src/store.rs`).
