**What this changes and why**

The problem, in a sentence or two, and the approach taken. Link the issue it
closes, if there is one (`Closes #...`).

**How it was checked**

The tests added or changed, and what you ran to see it work. A change to a
module that only imports inside the container (`list_emails`, `email_provider`,
`thephish_app`) needs to be proven there, not on the host.

**Risk**

What could this break silently? Say so even when the answer is "nothing I could
find".
