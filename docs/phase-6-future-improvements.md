# Phase 6 – Future Improvements

## Completed State

The completed project captured live traffic through:

- Cowrie SSH and Telnet
- Conpot ICS simulation
- Splunk ingestion and dashboarding

It produced:

- repeated brute-force attempts
- successful logins
- command-input records in Cowrie's emulated environment
- an operational IP-geolocation view, with no public country-level claim retained

The VPS and associated services were destroyed after collection. Raw exports remain private; sanitized aggregates, evidence-generation code, reconciliation tests, and privacy checks were added to this repository after decommissioning.

## Planned Improvements

### 1. Separate Collection and Analysis Planes

Run honeypots on an isolated collector while keeping the SIEM and administrative interfaces on a restricted management plane.

### 2. Infrastructure as Code and Automated Destruction

Use versioned infrastructure configuration, explicit egress controls, cost limits, and an automated destroy workflow.

### 3. Detection Regression Tests

Use synthetic Cowrie and Conpot fixtures to prove that expected searches and alerts continue to produce the correct results.

### 4. Longer Collection Window

If the experiment is repeated, predefine a time-bounded collection window in order to gather:

- more repeat attacker behavior
- more command execution
- possible payload download attempts
- stronger long-term trends

### 5. Better Dashboard Design
Refine the dashboard to look more modern and SOC-like by improving:

- panel layout
- color consistency
- geolocation visuals
- attack classification panels
- summary metrics

### 6. Command Classification
Classify attacker commands into behavior categories such as:

- reconnaissance
- download / delivery
- execution preparation
- persistence attempts

### 7. Better Infrastructure Correlation
Compare:

- high-volume source activity against Cowrie
- lower-volume protocol interaction against Conpot

### 8. Alerting
Add Splunk alerts for:

- successful logins
- command execution
- repeated attacker IPs
- Conpot activity spikes

## Why These Improvements Matter

The completed project demonstrates telemetry collection, Splunk analysis, privacy-preserving evidence publication, and automated reconciliation. These improvements would make a future deployment safer and more reproducible.
