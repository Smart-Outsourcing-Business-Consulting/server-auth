# Bound OIDC login attempts

Status: Accepted. The user accepted the Cloudflare-independent design and explicitly
requested implementation with disposable Odoo database testing.

## Purpose

Prevent anonymous login-page traffic from creating unbounded persistent OIDC attempt
state while preserving Odoo's native provider buttons, redirect state, one-time callback
correlation, nonce, and PKCE behavior.

Completion means rendering a login, signup, or reset page creates no attempt; clicking
an enabled authorization-code provider creates at most one pending attempt for the
browser session, provider, and website; and total unexpired pending attempts remain
bounded per provider and website without Cloudflare or another external challenge
service.

## Non-goals

- Do not add Cloudflare Turnstile, CAPTCHA, JavaScript, or an external service.
- Do not change token validation, callback claiming, native session authentication,
  provider configuration, or downstream provisioning hooks.
- Do not add source-IP identity or rate limiting; proxy-derived client IP is not an
  authoritative application identity.
- Do not update the OLB gitlink, publish, deploy, or contact an identity provider in
  this pass.
- Do not change `miniorange_oauth_20` production code.

## Domain language and business rules

An **initiation intent** is a high-entropy, single-use local handle for Odoo's native
OAuth state for one provider button, staged in the existing browser session while the
page is rendered. The staged state may contain Odoo's native redirect or invitation
token state; none of those values is placed in the local initiation URL. The session
retains at most 16 prior/current handles, or all providers from the current render when
more than 16 are configured.

A **pending attempt** is the server-side record containing the opaque-state digest,
nonce, and PKCE verifier after the initiation link is followed. A later start for the
same database, session fingerprint, provider, and website supersedes and deletes the
earlier pending attempt so its callback fails generically.

The adapter enforces a fixed ceiling of 1,000 unexpired pending attempts for one
provider and website. Before measuring capacity it deletes expired pending attempts and
supersedes the current session's pending attempt. Capacity checks and creation serialize
on the provider row so concurrent requests cannot race past the ceiling. At capacity,
initiation fails closed through the existing generic local authentication-failure path
and creates no new row.

Terminal rows do not consume pending capacity. The cron deletes a pending row as soon as
it is expired when cleanup runs; it retains consumed and failed rows for the existing
24-hour diagnostic window.

## Accepted scope

- `auth_oidc/controllers/main.py`: render local initiation links, stage native state in
  the session, validate initiation input, create the bounded attempt, and redirect to
  the configured provider.
- `auth_oidc/models/auth_oidc_login_attempt.py`: private creation seam, supersession,
  prompt expired-row cleanup, serialized provider/website limit, and cleanup retention
  behavior.
- `auth_oidc/tests/test_auth_oidc_auth_code.py`: public controller and explicit
  storage-contract coverage.
- `auth_oidc/__manifest__.py` and readme fragments: addon version and behavior
  documentation.

## Out of scope

- OLB composition pin updates and deployment.
- Production or shared database verification.
- Browser automation and live identity-provider verification.
- A configurable or per-IP limiter.

## Acceptance criteria

1. Calling `OpenIDLogin.list_providers()` for an authorization-code provider creates
   zero `auth.oidc.login.attempt` records and returns a same-origin initiation link
   containing only a high-entropy handle, without redirect, invitation, or provider
   state in its query string.
2. Following a staged initiation link validates an enabled `id_token_code` provider,
   creates one fresh attempt, and redirects with the expected state, nonce, S256 PKCE,
   scope, client, and callback parameters.
3. A direct or malformed initiation without matching session-staged intent fails locally
   and creates no attempt.
4. Repeated initiation for the same session, provider, and website replaces the pending
   attempt; the superseded opaque state cannot be claimed.
5. Expired pending rows are removed before capacity is evaluated and by cron without an
   additional 24-hour delay.
6. Distinct sessions cannot create more than 1,000 unexpired pending rows for one
   provider and website. The over-capacity request fails closed without a row. Tests may
   patch the fixed limit to a small value.
7. Existing one-time, session-bound callback, token-validation, failure, and
   finalization tests remain green.

## Implementation strategy

Implement one vertical slice through the rendered provider link, local start route,
bounded model operation, and callback-compatible authorization URL. Replace the existing
public `create_for_authorization` helper with a private `_create_for_authorization`
seam, migrate all repository callers, and retain no compatibility alias because no
external caller exists in the repository-wide inventory.

Use the browser session as the owner of bounded pre-click native state. The HTTP
controller consumes an opaque handle, parses the staged provider identifier, and
validates enabled code-flow configuration; the private model method trusts the validated
provider record. Use a provider-row lock for the supersession/count/create critical
section.

## Expected file and code changes

- Add the local `/auth_oidc/start` route in the existing controller.
- Stage one native-state value per provider in the browser session while rendering and
  consume it at initiation.
- Make attempt creation private and enforce the fixed storage invariant.
- Change pending cleanup from `expires_at < now - 24 hours` to `expires_at < now` while
  preserving terminal retention.
- Bump `auth_oidc` to `18.0.1.5.0` and document the bounded initiation change.
- Migrate tests from render-time creation to initiation-time creation.

## Verification policy

The user explicitly authorized the Odoo test suite and disposable databases. Use Odoo 18
Community plus the configured local Enterprise checkout and this repository on the
addons path. First run the focused `auth_oidc` test class on a uniquely named disposable
local database, then run the complete `auth_oidc` module tests. Static Ruff, Ruff
format, mandatory pylint, XML parsing, and `git diff --check` are allowed.

Never run against the configured shared `odoo_18` database, staging, production, or
Microsoft Entra. Remove the disposable database, temporary configuration,
filestore/session artifacts, and test logs after recording the result.

## Documentation alignment

Update the addon usage and history fragments. Generated OCA README artifacts may be
refreshed by the repository's existing generator if available; do not hand-edit
generated HTML. The application security report remains open until OLB pins the eventual
adapter commit and a separate source-grounded review revalidates the finding.

## Ownership and parallelization

This repository owns the complete change. Do not modify the OLB parent gitlink or
`miniorange_oauth_20`. The controller, model, and test edits are one coupled slice and
must not be parallelized.

## Drift rules

Stop if Odoo's native state cannot be preserved without exposing invitation or redirect
state in the local initiation URL, if another repository caller needs the public
creation method, if the provider-row lock cannot serialize the capacity invariant, or if
the focused test requires a production/shared database or live provider.

## Open questions

None.
