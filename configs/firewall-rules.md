# Firewall & Exposure Notes

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

Only intentionally exposed services were opened. The goal was to maximize attacker interaction on the VPS without exposing the operator's home network.
