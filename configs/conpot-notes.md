# Conpot Notes

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

## Analytical Value

Conpot generates less traffic than Cowrie, but its activity is more useful for showing simulated infrastructure exposure rather than simple credential abuse.
