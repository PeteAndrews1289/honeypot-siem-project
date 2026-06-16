# Honeypot Splunk Sample Queries

These searches are written as portfolio-friendly examples for analyzing Cowrie and Conpot honeypot data in Splunk. Field names may need adjustment depending on the ingestion configuration.

## Total Event Volume by Source

```spl
index=* (source="*cowrie*" OR source="*conpot*")
| stats count by source
| sort -count
```

Use this to compare event volume between SSH/Telnet and ICS/SCADA honeypot sources.

## Top Attacking IPs

```spl
index=* (source="*cowrie*" OR source="*conpot*")
| stats count by src_ip
| sort -count
| head 20
```

Use this to identify repeated scanners or high-volume sources.

## Successful Cowrie Logins

```spl
index=* source="*cowrie*" (eventid="cowrie.login.success" OR action="login_success")
| stats count by src_ip username password
| sort -count
```

Use this to identify weak credentials that resulted in successful honeypot interaction.

## Failed vs Successful Logins

```spl
index=* source="*cowrie*" (eventid="cowrie.login.failed" OR eventid="cowrie.login.success")
| eval outcome=case(match(eventid,"success"),"success",match(eventid,"failed"),"failed",true(),"other")
| timechart span=1h count by outcome
```

Use this to visualize brute-force activity and login outcomes over time.

## Attacker Commands

```spl
index=* source="*cowrie*" eventid="cowrie.command.input"
| stats count by input
| sort -count
| head 25
```

Use this to summarize post-authentication reconnaissance and payload-delivery attempts.

## ICS / SCADA Protocol Activity

```spl
index=* source="*conpot*"
| stats count by protocol src_ip
| sort -count
```

Use this to identify which simulated industrial protocols received traffic.

## Cross-Targeting IPs

```spl
index=* (source="*cowrie*" OR source="*conpot*")
| eval honeypot=case(match(source,"cowrie"),"cowrie",match(source,"conpot"),"conpot",true(),"other")
| stats values(honeypot) as honeypots dc(honeypot) as honeypot_count count by src_ip
| where honeypot_count > 1
| sort -count
```

Use this to find sources that interacted with both traditional IT services and ICS/SCADA services.

## Geographic Distribution

```spl
index=* (source="*cowrie*" OR source="*conpot*")
| iplocation src_ip
| geostats count by Country
```

Use this to create a high-level view of attacker source geography. Treat geolocation as approximate.

## Analyst Notes

- Honeypot data is noisy by design.
- High volume does not automatically mean high risk.
- Successful weak-credential logins and post-authentication commands are higher-value signals than raw connection counts.
- Cross-targeting behavior can help identify broader scanning campaigns.
