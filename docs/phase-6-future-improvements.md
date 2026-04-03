# Phase 6 – Future Improvements

## Current State

The project now captures live traffic through:

- Cowrie SSH and Telnet
- Conpot ICS simulation
- Splunk ingestion and dashboarding

It has already produced:

- repeated brute-force attempts
- successful logins
- command execution
- geolocation-enriched attack data

## Planned Improvements

### 1. Longer Collection Window
Allow the environment to run for days or weeks in order to gather:

- more repeat attacker behavior
- more command execution
- possible payload download attempts
- stronger long-term trends

### 2. Better Dashboard Design
Refine the dashboard to look more modern and SOC-like by improving:

- panel layout
- color consistency
- geolocation visuals
- attack classification panels
- summary metrics

### 3. Command Classification
Classify attacker commands into behavior categories such as:

- reconnaissance
- download / delivery
- execution preparation
- persistence attempts

### 4. Better Infrastructure Correlation
Compare:

- high-volume opportunistic attacks against Cowrie
- lower-volume infrastructure probing against Conpot

### 5. Alerting
Add Splunk alerts for:

- successful logins
- command execution
- repeated attacker IPs
- Conpot activity spikes

## Why These Improvements Matter

The current project already demonstrates practical detection engineering and attacker observation. These next steps would turn it into a more polished security operations case study and stronger interview artifact.
