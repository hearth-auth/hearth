## Context

Hearth supports passkey sign-in on the hosted login page, and passkey enrolment on the account page (`/ui/account/passkeys/register-begin` and `register-complete`) and the REST API (`/webauthn/register/begin`). Enrolment needs a step-up proof: `password`, `totp_code` or `assertion` (`src/protocol/step_up.rs`). A realm can force passkeys with `webauthn_required`, and it can limit sign-in methods with `allowed_auth_methods`.

Required actions (`VERIFY_EMAIL`, `UPDATE_PASSWORD`, `ENROLL_MFA`, `ENROLL_EMAIL_OTP`) already run at `/required-action/{ACTION}` during `/authorize`, before the authorization code is issued. They are mandatory. The passkey prompt is optional, so it is not a required action.

The owner wants passkeys to be the standard, and accepts a prompt at every sign-in. Google and Microsoft use a post-sign-in page with a clear "Not now" control. Large identity providers vary on how often they ask again.

## Goals / Non-Goals

**Goals:**

- Every password user sees a passkey offer at the moment they are most likely to accept it: right after a sign-in.
- Enrolment from the prompt needs no second password entry.
- Each realm controls how often the prompt appears.
- Operators can measure adoption.

**Non-Goals:**

- Removing passwords, or making passkeys mandatory. `webauthn_required` already does that.
- Prompts inside client applications. The prompt runs on Hearth's hosted pages only.
- A prompt in the SDKs or the REST API.
- Conditional mediation (passkey autofill) on the login form. It is a separate improvement.

## Decisions

### D1. The prompt is a step after required actions, not a required action

The sign-in pipeline runs: credentials → second factor → required actions → **passkey prompt** → authorization code (or the `return_to` redirect). The prompt runs last, so it never blocks a mandatory step. A user who completes a required action in the same sign-in still sees the prompt after it.

*Alternative considered:* a skippable required action. Required actions are mandatory by definition. A skippable one would weaken that rule, and SDK `RequiredActionError` would have to learn a new kind of action.

### D2. When the prompt is shown

All of these conditions must be true:

1. The realm's `passkey_prompt` is not `off`.
2. The realm allows passkey sign-in: `allowed_auth_methods` is absent, or it contains `passkey`.
3. The realm does not set `webauthn_required: true`. Those users are already forced to enrol.
4. The sign-in did not use a passkey.
5. The account has no passkey.
6. For `interval`: the account has no "Not now" inside the last `passkey_prompt_interval_days` days.

The prompt applies to every hosted sign-in that ends in a session, including the admin console. The system realm uses the same policy field.

### D3. A single-use enrolment ticket replaces the second step-up proof

When the pipeline shows the prompt, it creates an enrolment ticket. The ticket has these properties:

- It is a 256-bit random value, stored server-side, bound to the new session.
- It expires 300 s after the sign-in.
- It is used once, then deleted.
- It is placed in the prompt page only, not in a cookie.

The prompt's registration request sends the ticket in place of a step-up proof. The registration handlers accept a ticket only when it matches the request's session. All other enrolment requests keep the current rule.

*Alternatives considered:*

- Ask for the password again. This adds friction exactly where the goal is adoption.
- Accept any session younger than N minutes. Then any request with a stolen fresh session could enrol a passkey. The ticket also requires the prompt page.

### D4. "Not now" is stored per account, only for the `interval` policy

For `interval`, "Not now" records a timestamp on the account. Thus the interval holds across browsers and devices. For `every_login`, "Not now" records nothing. Thus that policy causes no storage write at sign-in.

### D5. A browser without WebAuthn sees a "Continue" page

The server cannot know before it renders whether the browser supports WebAuthn. The page checks `PublicKeyCredential` in the browser. Without support, it hides "Create a passkey" and shows "Continue" with a short explanation. That outcome is counted as `unsupported`, and it is not recorded as "Not now".

### D6. The page follows the theme

There is one `btn-ember` ("Create a passkey"). "Not now" is a secondary control with the same visual weight as other secondary actions. The page has no light-mode styles. A user who chooses "Not now" must not need more clicks than one.

## Risks / Trade-offs

- [Prompt fatigue at `every_login`] → "Not now" is one click. Operators can choose `interval`. The outcome counter shows when users only dismiss.
- [An extra page in every password sign-in adds latency for the application] → The page is rendered from data that the pipeline already has, and it needs one request to continue.
- [The enrolment ticket is a new step-up path] → It is single-use, it expires in 300 s, it is bound to the session, and it exists only in the prompt page. It allows enrolment only, never removal.
- [A client application expects an immediate redirect after sign-in] → The OIDC contract allows interaction pages before the code is issued. Clients that use `prompt=none` never reach the prompt, because they get no interactive sign-in.

## Migration Plan

Hearth has no deployed users. The default policy is `every_login`. To roll back, set `passkey_prompt: off` on each realm.

## Open Questions

1. **The default policy.** The draft uses `every_login`, as the owner asked. `interval` with 7 days is the gentler alternative.
2. **The account page.** Should it also show a passkey banner to users without a passkey? It is not in this change.
