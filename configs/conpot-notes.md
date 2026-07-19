# Conpot Deployment Notes

These are retrospective deployment notes, not a complete deployable Conpot configuration.

## Purpose

Conpot simulates ICS / SCADA-style services in order to attract lower-volume but more infrastructure-oriented probing.

## Deployment Notes

Conpot required troubleshooting around:

- Python version compatibility
- changed packaging structure
- config and template path selection

The final log path used for Splunk ingestion was:

`/home/honeypot/conpot/conpot.log`

## Observed Behavior

Conpot logs captured:

- malformed request syntax
- HTTP / HTTP 0.9-style probes
- binary-looking payload attempts
- session timeouts
- repeated source IPs

The retained ICS export contains 721 records: 507 S7, 157 Modbus, 28 COTP, 12 SNMP, and 17 other interactions. These are protocol-specific observations against simulated services, not proof of successful exploitation or actor intent.

## Analytical Value

Conpot generated less source-attributed volume than Cowrie while providing evidence of interaction across several simulated industrial protocols.

The VPS and associated services were destroyed after evidence collection.
