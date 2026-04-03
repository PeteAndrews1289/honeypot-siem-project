# Phase 2 – Conpot Deployment

## Objective

Deploy Conpot to simulate infrastructure-facing and ICS / SCADA-style services and collect lower-volume, higher-signal traffic.

## Process

Conpot was cloned onto the VPS and installed inside a dedicated Python virtual environment. Deployment required several troubleshooting steps due to changes in the Conpot project structure and runtime requirements.

The main issues encountered were:

- missing `requirements.txt` due to newer packaging layout
- Python version mismatch on Ubuntu 22.04
- inability to install Python 3.12 on that droplet cleanly
- migration to a **new Ubuntu 24.04 droplet**
- startup argument confusion between template and config paths
- locating the correct Conpot config and template paths

Once the correct template, config, and runtime options were identified, Conpot was launched successfully.

## Deployment Notes

The final setup used:

- Ubuntu 24.04
- Python virtual environment
- Conpot default template
- local log file output at:

`/home/honeypot/conpot/conpot.log`

## Validation

The service was validated through:

- process checks
- listening port verification
- `nmap` scans from the operator system
- real unsolicited traffic showing up in `conpot.log`

Observed Conpot log behavior included:

- malformed HTTP / HTTP 0.9-style requests
- binary payload probes
- session creation and timeouts
- repeated source IPs

## Result

Conpot successfully generated and logged live attacker interaction against simulated infrastructure services.

## Insight

Conpot generated less traffic than Cowrie, but when it was hit, the traffic was more useful for demonstrating infrastructure-oriented probing rather than simple credential brute forcing.
