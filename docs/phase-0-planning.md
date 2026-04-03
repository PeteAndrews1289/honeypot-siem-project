# Phase 0 – Planning & Architecture

## Objective

Design a safe, public-facing honeypot environment capable of collecting real attacker traffic and analyzing it through a SIEM.

## Initial Requirements

The project needed to:

- run on a public VPS rather than a home network
- support multiple attacker-facing services
- collect both generic and infrastructure-style attack data
- centralize logs in Splunk for later analysis
- remain safe for the operator's home environment

## Design Decisions

The environment was built around a **DigitalOcean droplet** rather than local infrastructure. This ensured that all malicious traffic would target an isolated public system rather than a personal computer or residential network.

The project used:

- **Cowrie** for SSH and Telnet honeypot emulation
- **Conpot** for ICS / SCADA-style service simulation
- **Splunk Enterprise** for centralized log ingestion, searching, and dashboarding

## Planned Architecture

Attacker → Internet → DigitalOcean VPS → Honeypot Services → Splunk → Dashboards

## Why This Architecture

This design supports two different attacker classes:

- **high-volume opportunistic attackers** hitting SSH and Telnet
- **lower-volume, higher-signal infrastructure probing** against ICS-style services

## Insight

The most important design decision was keeping the project on an isolated VPS. That allowed live internet exposure without exposing the home network to inbound attack traffic.
