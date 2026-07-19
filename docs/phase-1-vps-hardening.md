# Phase 1 – VPS Deployment & Hardening

## Objective

Deploy a publicly reachable DigitalOcean VPS with bounded controls for a time-limited attacker-facing honeypot experiment.

## Process

A new **DigitalOcean droplet** was created using Ubuntu. SSH key-based authentication was configured during initial setup. After first login, the system was updated and a non-root administrative user was created.

The VPS was hardened by:

- creating a dedicated non-root user
- granting administrative access through `sudo`
- disabling direct root SSH login
- disabling password-based SSH on the real system
- enabling UFW and allowing only required ports

## Key Configuration Steps

- Generated and added an SSH key
- Logged into the VPS using SSH
- Updated packages
- Created the `honeypot` user
- Copied SSH keys into the new user's account
- edited `sshd_config`
- restarted SSH safely
- enabled UFW
- validated access before removing root login

## Result

The droplet became the isolated public target for the project while administrative access was intended to remain separate through the non-root `honeypot` user. The retained documentation does not include the final firewall export, outbound-control evidence, or final service-user state, so this should be read as a deployment retrospective rather than proof of production hardening.

## Insight

This phase established the core safety boundary of the project: the VPS became the attack surface, while the operator machine remained only a management client.

Splunk Web was publicly reachable during the lab, which is a documented limitation. The VPS and associated services were destroyed after collection.
