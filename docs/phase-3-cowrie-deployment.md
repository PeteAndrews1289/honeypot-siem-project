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

## Result

Cowrie became the highest-volume source of useful attacker interaction in the project.

## Insight

Redirecting port 22 and enabling weak credentials were the two most important changes in the entire project. They converted the environment from passive logging into active post-authentication attacker observation.
