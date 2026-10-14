---
name: Bug report
about: Something in Bluephish does not behave the way it should.
title: "[BUG] "
labels: bug
assignees: ''

---

> **Security problems do not go here.** A vulnerability reported in a public issue
> is a vulnerability published. Use *Security → Report a vulnerability* on the
> repository page instead.
>
> **Remove real data before you paste.** Logs and screenshots from this tool carry
> sender addresses, subjects, URLs and attachment names taken from real phishing
> reports. Replace anything that identifies a person or your organization.

**What happened**

What you saw, and what you expected to see instead.

**How to reproduce it**

1. Go to '...'
2. Do '...'
3. See the result

**Your setup**

| | |
| --- | --- |
| Bluephish version | commit hash or release (`git rev-parse --short HEAD`) |
| How it runs | Docker Compose / other |
| Docker and Compose versions | `docker --version`, `docker compose version` |
| Mailbox provider | Gmail (IMAP) / Microsoft 365 (Graph) / other IMAP |
| Analysis mode | attachment / raw |
| Where verdicts are recorded | TheHive / Jira / disk / generic connector |
| LLM provider | none / local (Ollama...) / hosted |
| Browser | name and version |

**Log output**

The relevant lines from `docker logs thephish`, with real data removed.

**Anything else**

Screenshots, or a guess at the cause if you have one.
