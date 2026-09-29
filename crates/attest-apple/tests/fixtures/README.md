# App Attest fixtures

Real, device-captured App Attest objects. `tests/fixtures.rs` verifies every `*.json` file in
this directory against the embedded Apple App Attestation Root CA.

## Format

```json
{
  "description": "free text",
  "source": "where it came from (optional)",
  "license": "license of the source (optional)",
  "app_id": "TEAMID1234.com.example.app",
  "environment": "production | development",
  "verify_at": 1601240898,
  "attestation": "<standard base64 attestation object>",
  "key_id": "<standard base64 key id>",
  "client_data": "<standard base64 of the bytes hashed into clientDataHash>",
  "assertion": {
    "assertion": "<standard base64 assertion made with the attested key>",
    "client_data": "<standard base64 of the bytes hashed into clientDataHash>",
    "counter": 1
  }
}
```

- `client_data` is what the app passed through SHA-256 to produce `clientDataHash`. For
  Attestra this is the raw 32 challenge bytes (`/challenge` returns them as base64url).
- `verify_at` must fall inside the leaf certificate's validity window. Leaf certificates are
  short-lived, so captured fixtures are always verified at a fixed time.
- `assertion` is optional.

## Capturing your own

In a debug build of the app, log the base64 `keyId`, the attestation object, and the challenge
bytes, then write them into a new file here with `verify_at` set to the capture time. Never
commit fixtures from production users.

## Provenance

The vectors were copied verbatim from the test suites of these open-source projects. Each file
records its exact source URL and license.

| Files | Project | License |
| --- | --- | --- |
| `webauthn4j_kayak.json` | [webauthn4j](https://github.com/webauthn4j/webauthn4j) | Apache-2.0 |
| `bas_d_appattest_go.json` | [bas-d/appattest](https://github.com/bas-d/appattest) | BSD-3-Clause |
| `veehaitch_ios_14_*.json` | [veehaitch/devicecheck-appattest](https://github.com/veehaitch/devicecheck-appattest) | Apache-2.0 |
| `srinivas1729_appattest_checker_node.json` | [appattest-checker-node](https://github.com/srinivas1729/appattest-checker-node) | Apache-2.0 |
| `node_app_attest_*.json` | [uebelack/node-app-attest](https://github.com/uebelack/node-app-attest) | MIT |
