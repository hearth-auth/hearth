## Why

Passkeys are the strongest sign-in method that Hearth offers. Hearth never stores a secret for them, a captured sign-in cannot be replayed, and a passkey sign-in costs no Argon2id work. The `login-overload-resilience` change keeps passkey sign-in outside the KDF admission gate, so passkey users are not affected by a password flood. Today, Hearth only offers passkey enrolment on the account page, and few users find that page. Passkeys must become the standard way to sign in, so Hearth must ask password users to create one.

## What Changes

- **A passkey prompt after sign-in.** When a user completes a sign-in without a passkey and has no passkey, Hearth shows a prompt page before it returns the user to the application. The page offers "Create a passkey" and "Not now".
- **A per-realm policy** `passkey_prompt`:
  - `every_login` (the default) shows the prompt at every qualifying sign-in.
  - `interval` shows it again only `passkey_prompt_interval_days` days after the user chose "Not now".
  - `off` never shows it.
- **No second password entry.** Passkey enrolment needs a step-up proof today. A sign-in that just completed gives the prompt a single-use, short-lived enrolment ticket, and that ticket is accepted as the proof for one enrolment from the prompt.
- **Adoption metrics.** A counter records each prompt outcome, so an operator can see passkey adoption.

No breaking change.

## Capabilities

### New Capabilities

- `passkey-first-login`: when the post-sign-in passkey prompt is shown, what it offers, the realm policy that controls it, the enrolment ticket that replaces a second step-up proof, and the prompt metrics.

### Modified Capabilities

None. Passkey enrolment from the account page and the REST API keeps its current step-up rule.

## Impact

- **Code:** the post-sign-in pipeline in `src/protocol/web/` (a prompt step after required actions and before the authorization code or the `return_to` redirect); a new prompt template under `templates/ui/`; the passkey registration handlers (accept the enrolment ticket); realm configuration in `src/identity/types/realm.rs` and its admin API and console fields; a per-account "Not now" timestamp for the `interval` policy.
- **UI:** one new page that must follow `docs/dev/THEME.md`; `make ui-test-smoke` and `make ui-test-accessibility` cover it.
- **API:** two new realm fields on the admin API (`passkey_prompt`, `passkey_prompt_interval_days`) and in `hearth.yaml` realm configuration.
- **Metrics:** `hearth_passkey_prompt_total{outcome}`.
- **Docs:** `CHANGELOG.md` (Added), the configuration reference, and the passkey guide.
