# Dashboard Overview

## Objective

Build a Splunk dashboard that presents the honeypot environment like a lightweight SOC console.

## Panels Included

- Event Distribution
- Top Attacking IPs
- Successful Logins
- Failed vs Successful Logins
- Attacker Commands
- Attack Timeline
- Global Attack Distribution

## What the Dashboard Answers

- How much attack activity is the environment receiving?
- Which IPs are most active?
- Are attackers only brute forcing, or are they getting in?
- What credentials are being used successfully?
- What commands are being run after login?
- Where is attacker traffic coming from geographically?

## Notes

Cowrie provides the majority of volume and post-authentication behavior.

Conpot provides lower-volume but more infrastructure-oriented activity.

Together, they allow the dashboard to compare generic attacker behavior with more specialized infrastructure probing.
