
## `configs/cowrie-notes.md`

```markdown
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
- successful authentications
- command execution events such as `uname` and `id`
