# Security notes

[Português (Brasil)](../seguranca.md) · **English**

- The port is published on **`127.0.0.1`** only. If you run the
  [optional integrations](integrations.md), the same holds for theirs, and Cassandra and
  MISP's MySQL in particular run with development-grade credentials and must never be
  exposed. To reach the interface from another machine, use an SSH tunnel or a reverse proxy
  with TLS instead of changing the port bindings ([how](faq.md#how-do-i-access-it-from-another-machine)).
- Secrets are never returned to the browser: the settings API answers with booleans
  (`hasApiKey`) and an empty field on save means "keep the stored value".
- **The container makes outbound requests to infrastructure the phisher chose.** Two features
  do this by design: the URL unshortener, while analyzing, and the *Como entregue* view,
  which fetches the images a reported email points at. It is the **container** that fetches
  them, never the analyst's browser: the workstation's address and user agent never leave,
  and everything reaching the browser is a `data:` URI inside a sandbox. But the request does
  leave your network, and it tells the sender that somebody looked. The interface names every
  host it contacted. Images are fetched **only when somebody opens *Como entregue***: the
  background loader lays every email out without them, so a report nobody opens tells its
  sender nothing.

  Three consequences worth deciding on before deployment: put the container's egress behind
  whatever proxy your outbound policy expects; expect a phishing campaign to learn that this
  mailbox is monitored; and if that is unacceptable for your operation, `fetch_remote` in
  `app/email_render.py` turns image fetching off at the source (links and scripts are inert
  either way). Every fetch is validated against the same SSRF guard as the analyst-defined
  analyzers: the internal network is never reachable and the cloud metadata service is
  refused outright, with redirects refused, image types read from the bytes rather than the
  `Content-Type`, SVG rejected, and count, size and wall-clock all capped.
- Passwords are hashed with **bcrypt**; sessions expire after **30 min idle / 12 h absolute**,
  are revoked on password change, and end when the browser tab that opened them is closed.
  All authentication events are audited to `auth.log`. After **5 failed logins** the account
  is locked for **15 minutes**, and the login route accepts at most **5 attempts per minute
  per IP**.
- **A second factor is mandatory for every account**, with no per-user or per-role exemption
  and no setting that turns it off. A correct password opens a 10-minute challenge, not a
  session: nothing is signed in until a valid TOTP code is presented, so a stolen password
  on its own reaches nothing. Accounts that predate this are intercepted at their next
  sign-in and must enrol before they get in, and sessions opened before it are dropped.
- **Authenticator apps only** (Google Authenticator, Microsoft Authenticator, Authy, or any
  RFC 6238 client). Codes by e-mail or SMS are deliberately not offered and should not be
  added: SMS falls to a SIM swap, and e-mail falls together with the very mailbox this
  platform exists to watch. Recovery is a `global_admin` clearing the factor, never a code
  sent through a channel an attacker may already hold.
- **SSO accounts are not exempt.** The identity provider proves one factor; the platform
  requires two, so the return from Entra ID lands on the same TOTP challenge.
- **SSO accounts have no password at all.** The stored hash is of a random value nobody has
  ever seen, password login refuses them outright, and *Resetar senha* is not offered for
  them: revocation belongs to the identity provider.
- Before opening this to a wider network, read the *Known constraints and traps* section of
  the [architecture](../../BLUEPHISH_ARCHITECTURE.md).
