# Exposure Controls and Retrospective Limitations

## Administrative Access

Administrative access remained separate from honeypot exposure. The VPS was the attack surface, while the operator system only connected to it for management and analysis.

## Publicly Relevant Services

The project intentionally exposed or redirected traffic for:

- 22 redirected toward Cowrie
- 23 for Cowrie Telnet
- 2222 for Cowrie SSH
- 8000 for Splunk web access
- Conpot-related service ports as needed

## Notes

The goal was to maximize interaction on an isolated VPS without exposing the operator's home network. The retained documentation supports the intended service exposure but does not include an export of the final UFW/iptables ruleset.

Splunk Web on port `8000` was reachable from the public internet during the lab. That simplified analysis but is not a recommended production design. A future deployment should restrict administration behind a VPN or allowlist, place the SIEM on a separate management plane, enforce egress controls, and retain machine-readable firewall evidence.

The VPS and associated services were destroyed after evidence collection.
