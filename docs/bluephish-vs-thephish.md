# Bluephish and ThePhish

**English** · [Português (Brasil)](bluephish-vs-thephish.pt-BR.md)

Bluephish was born inspired by [ThePhish](https://github.com/emalderson/ThePhish), by
Emanuele Galdi (`emalderson`), and has since grown into an independent project. This page is
for readers who know the original and want to see where the two differ. If you never used
ThePhish, you do not need it: start from the [README](../README.md).

The ThePhish column is taken from that project's public README at the time of writing; its
repository is the reference for what it does today.

| | ThePhish | Bluephish |
|---|---|---|
| **Who starts an analysis** | The analyst picks an email in the web interface and starts it | Manual (the analyst picks) **or** fully automatic, through a scheduler |
| **What it needs to run** | TheHive, Cortex and MISP | Only itself: one container. TheHive and MISP are optional extras |
| **Where the analyzers run** | In Cortex, a separate service | Inside Bluephish: built-in analyzers, vendors you add yourself, and local YARA rules |
| **Where the result is recorded** | A case in TheHive, exported to MISP when malicious | Any combination of TheHive, Jira, a disk archive and generic connectors for any REST API, or none of them |
| **How the verdict is formed** | From the verdicts of the analyzers | The analyzers, an LLM's social-engineering assessment, SPF/DKIM/DMARC sender authentication and a weighted score, each in a fixed order that can only raise a verdict |
| **Reporter notifications** | Sent through a Cortex responder | Sent by SMTP, configured in Bluephish, with one switch per notice |
| **Mailboxes** | A mailbox the application reads | Gmail (IMAP) and Microsoft 365 (Graph API) |
| **Who can do what** | (not part of its description) | Three roles, mandatory TOTP two-factor, corporate SSO, account lockout and an audit trail |

## What Bluephish adds

- Microsoft 365 mailboxes through the Graph API.
- An automatic analysis scheduler, with a per-cycle cap.
- An LLM assessment of the message and, for image-only phishing, of its images.
- Sender authentication (SPF, DKIM, DMARC) to tell a real brand email from an impersonation.
- An AI chat to question an already-analyzed case.
- A whitelist with five rule types, expiry on every rule, a dry run against past analyses and
  automatic suspension of a rule that hides too many bad verdicts.
- Reclassification by analysts, remembered for similar messages.
- Role-based access, mandatory second factor, SSO and an audit log.

## What it keeps from the original idea

A monitored mailbox where people forward suspicious emails as `.eml` attachments, the
extraction of observables from each one, their analysis, a verdict of Safe, Suspicious or
Malicious, a notification to whoever reported it, and a whitelist. Both are released under
the AGPL-3.0.

For the detailed design of Bluephish, see
[`THEPHISH_ARCHITECTURE.md`](../THEPHISH_ARCHITECTURE.md).
