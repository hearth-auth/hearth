## 0. Precondition

- [ ] 0.1 Archive `scope-trim-trusted-core` first, so the `sdk-support-contract` capability exists in `openspec/specs/` (this change only adds requirements to it)

## 1. Spikes

- [ ] 1.1 Generator spike per SDK (design decision 2): generate the admin client for `/admin/users`, `/admin/clients` and `/admin/roles`; record the chosen generator, and each gap in `docs/api/openapi.json` it hit
- [ ] 1.2 Fix the gaps from 1.1 in the server's OpenAPI derivation (`scripts/merge_openapi.py` or the proto annotations), with `make openapi-check` green

## 2. JOSE-library verification (one PR per SDK is fine)

- [ ] 2.1 TypeScript: red tests (Ed25519 token validates; tampered payload, `alg:none`, wrong `kid` fail); remove any handwritten claim check that `jwtVerify` options already cover
- [ ] 2.2 Go: red tests first; add `github.com/go-jose/go-jose/v4`; replace `hearth/verify.go`'s `ed25519.Verify` path; keep the error taxonomy
- [ ] 2.3 Python: red tests first; verify with `jwt.decode(..., algorithms=["EdDSA"])` and `PyJWK`; delete the `Ed25519PublicKey.verify` path in `client.py` and the key cache in `jwks.py` it fed
- [ ] 2.4 PHP: red tests first; verify with `lcobucci/jwt` `Signer\Eddsa` and the validation constraints; delete the `sodium_crypto_sign_verify_detached` path in `TokenVerifier.php`
- [ ] 2.5 Add a CI grep that fails on a direct Ed25519 verify call in `sdks/` (the "No handwritten signature check remains" scenario)

## 3. Generated admin clients

- [ ] 3.1 Add `make sdk-admin-gen` (all four generators) and commit each generated client under `sdks/<sdk>/generated/admin/`
- [ ] 3.2 Rewrite each handwritten `AdminClient` as a wrapper over its generated client, keeping its tests green
- [ ] 3.3 Add `make sdk-admin-check` and a CI step that fails on a stale generated client

## 4. Conformance harness

- [ ] 4.1 Write `sdks/conformance/scenarios.yaml` (token validation set plus client credentials; design Open Question 2)
- [ ] 4.2 Write a runner per SDK (`sdks/<sdk>/conformance/`) that prints one JSON result per scenario
- [ ] 4.3 Write the driver (extend `scripts/sdk-smoke-local.sh`): boot `--dev`, bootstrap, mint tokens, run the runners, diff; a difference names the SDK and the scenario
- [ ] 4.4 Add the harness as a CI job, required in the summary

## 5. Docs and release

- [ ] 5.1 Update `docs/specs/SDK.md`, `docs/specs/SDK_SURFACE.md` and the four SDK guides: the libraries, the generated clients, the harness
- [ ] 5.2 CHANGELOG `### Changed` entries per SDK (verification library, admin client method names)
