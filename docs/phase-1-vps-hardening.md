# Phase 1 – VPS Deployment & Hardening

## Objective

Deploy a publicly reachable DigitalOcean VPS and harden it enough to safely host attacker-facing honeypot services.

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

The droplet became the isolated public target for the project while administrative access remained controlled through the non-root `honeypot` user.

## Insight

This phase established the core safety boundary of the project: the VPS became the attack surface, while the operator machine remained only a management client.
