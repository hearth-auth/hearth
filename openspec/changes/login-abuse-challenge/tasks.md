## 0. Before you start

- [ ] 0.1 Read the draft advisory `GHSA-hxcr-696v-vqw3` (maintainers only)
- [ ] 0.2 Write `design.md`: the no-op provider rule, the API sign-in endpoints in scope, and one status code for a challenged API caller (reconcile A-3 and A-16 in the spec)
- [ ] 0.3 For every task: write the scenario as a failing test first (red), then fix (green). Each fix needs a `### Security` entry in `CHANGELOG.md`

## 1. Challenge

- [ ] 1.1 Enforce: A challenged login is audited and challenged. Test: scenario "A challenged login is audited and challenged" (`tests/abuse_detector.rs`)
- [ ] 1.2 Enforce: A challenged caller is told to solve a challenge. Test: scenario "A challenged caller is told to solve a challenge" (`tests/abuse_captcha.rs`)
- [ ] 1.3 Run `make ui-test-smoke` and `make ui-test-accessibility` against `make dev`
