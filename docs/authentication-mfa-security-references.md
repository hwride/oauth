# Authentication and MFA Security References

> [!WARNING]
> This document was AI-generated and requires further review.

References for the authorization server's multi-step authentication flow, including the pending state between password authentication and MFA verification.

## OAuth and federation protocol guidance

### OAuth 2.0 Security BCP — RFC 9700

https://www.rfc-editor.org/rfc/rfc9700.html

The current OAuth security baseline. Covers authorization-code protection, PKCE, redirect URI validation, mix-up attacks, and other protocol-level threats. It does not prescribe the authorization server's internal login or MFA page flow.

## Practical web application security guidance

### OWASP Application Security Verification Standard (ASVS) 5.0

https://asvs.owasp.org/

Use ASVS as the overall security checklist for authentication, session management, access control, and input validation.

### OWASP Session Management Cheat Sheet

https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

Relevant topics include:

- Meaningless, unpredictable session or transaction identifiers.
- Server-side storage of the state associated with an identifier.
- At least 128 bits of entropy when generating identifiers.
- Expiration, invalidation, and one-time use.
- URL leakage through browser history, logs, bookmarks, and `Referer` headers.
- Cookie protections such as `Secure`, `HttpOnly`, and `SameSite`.
- Session renewal after authentication or privilege changes.

### OWASP Business Logic Security Cheat Sheet

https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html

Particularly relevant guidance:

- Represent multi-step workflows as explicit server-side state machines.
- Validate every state transition and prevent skipped steps.
- Derive security-relevant identity and authorization data on the server.
- Make check-and-consume operations atomic where replay is possible.

### OWASP Transaction Authorization Cheat Sheet

https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html

Although mainly written for sensitive operations such as payments, its multi-step authorization patterns apply to an MFA challenge:

- Enforce authorization server-side.
- Prevent brute-force attempts and restart the flow after too many failures.
- Restrict authorization credentials to a short validity window.
- Accept each authorization credential only once.
- Enforce the allowed sequence of states.

### OWASP Multifactor Authentication Cheat Sheet

https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

Covers independent authentication factors, MFA recovery, downgrade prevention, factor changes, and monitoring for suspicious authentication activity.

### OWASP Cross-Site Request Forgery Prevention Cheat Sheet

https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

Relevant when a pending authentication flow uses cookies or browser form submissions. Pay particular attention to CSRF protection and the distinction between a pre-authentication session and a newly authenticated session.

## Authentication assurance and lifecycle

### NIST SP 800-63B — Digital Identity Guidelines

https://pages.nist.gov/800-63-4/sp800-63b.html

Covers authentication assurance levels, MFA authenticator requirements, reauthentication, session inactivity timeouts, absolute timeouts, and session termination.

## Proposed checklist for our pending MFA transaction

- Store the pending authorization context server-side.
- Give the browser only an opaque, cryptographically random transaction handle.
- Keep the client ID, validated redirect URI, scopes, `state`, nonce, and PKCE data in the server-side record.
- Track explicit states such as `password_verified`, `mfa_verified`, and `authorization_code_issued`.
- Do not issue an authorization code before MFA succeeds.
- Expire pending transactions quickly and make them single-use.
- Rate-limit failed TOTP attempts and invalidate the transaction after the configured limit.
- Atomically consume the pending transaction before issuing the authorization code.
- Treat transaction handles and hidden form fields as untrusted input.
- If a handle is placed in a URL, use `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and account for browser history and server-log exposure.
- If cookies are used, configure `Secure`, `HttpOnly`, and `SameSite` appropriately and consider multi-tab behavior.
- Redact transaction handles and TOTP values from logs.
