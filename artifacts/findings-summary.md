# Findings Summary

## Summary

The project successfully deployed a public honeypot environment on a DigitalOcean VPS and ingested live attacker activity into Splunk.

## Main Findings

- The environment received repeated external attack traffic
- Cowrie generated the majority of attack volume
- Weak credentials produced successful logins
- Attackers executed reconnaissance commands after authentication
- Repeated source IPs indicated persistent automated scanning behavior
- Geolocation enrichment showed globally distributed attack sources
- Conpot generated lower-volume but higher-signal infrastructure-style probing

## Attacker Behavior Observed

### Opportunistic Activity
- brute-force attempts
- repeated login attempts
- rapid reconnect patterns

### Post-Authentication Activity
- `uname`
- `id`

These indicate environmental reconnaissance after compromise.

## Conclusion

The project demonstrates the ability to deploy attacker-facing services safely, centralize logs in Splunk, and analyze real attacker behavior across multiple simulated service types.
