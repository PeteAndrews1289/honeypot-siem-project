# Phase 3 – Cowrie Deployment

## Objective

Deploy Cowrie to capture SSH and Telnet attack traffic, including brute-force attempts, successful logins, and post-authentication activity.

## Process

Cowrie was cloned to the VPS and installed in a Python virtual environment. Because the project used a modern package structure, older tutorial commands such as `bin/cowrie` did not work directly. The correct startup method came from the virtual environment entrypoint.

The deployment process included:

- installing Cowrie dependencies
- creating and activating a Python virtual environment
- copying and editing `cowrie.cfg`
- identifying the correct executable path
- confirming the service was running through the `twistd` process
- enabling both SSH and Telnet listeners

## Final Service Configuration

Cowrie was configured with:

- SSH listener on `2222`
- Telnet listener on `23`
- realistic SSH banner
- weak credentials in `userdb.txt`

Working credentials included:

- `admin / admin`
- `root / root`
- `user / password`

## Traffic Improvements

To increase useful attacker interaction:

- port **22** traffic was redirected toward Cowrie
- Telnet on **23** was enabled
- common weak credentials were added

These changes caused the project to move from simple scanning activity into successful authentications and command execution.

## Observed Behavior

Cowrie captured:

- repeated brute-force attempts
- successful logins
- session creation and closure
- attacker reconnaissance commands such as:
  - `uname`
  - `id`

The retained high-signal export contains 613 successful authentication events and 457 command-input occurrences, 433 of which were non-empty. Cowrie emulated the post-authentication environment; observed commands were not executed on the underlying VPS.

## Result

Cowrie became the highest-volume source of useful attacker interaction in the project.

## Insight

Redirecting port 22 and enabling synthetic weak credentials converted the environment from passive connection logging into observation of post-authentication interaction with Cowrie's emulated service.
