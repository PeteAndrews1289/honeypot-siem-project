# Cowrie Notes

## Purpose

Cowrie is used to capture:

- SSH brute-force attempts
- Telnet brute-force attempts
- successful logins
- session behavior
- attacker command execution

## Final Deployment Notes

Cowrie was installed in a Python virtual environment and started from the virtual environment entrypoint rather than older tutorial commands.

Useful runtime checks included:

- process checks for `twistd`
- port checks for `2222` and `23`

## Exposure

- SSH honeypot listener on `2222`
- Telnet honeypot listener on `23`
- port `22` redirected to the honeypot

## Working Weak Credentials

- `admin / admin`
- `root / root`
- `user / password`

## Observed Behavior

The environment produced:

- repeated brute-force attempts
- 613 successful authentication events in the retained high-signal export
- 457 command-input occurrences, including 433 non-empty values

Cowrie emulated the post-authentication environment. Observed commands are evidence of interaction with the honeypot, not execution on the underlying VPS.
