# Splunk Searches

These searches document the field contracts used in the completed lab. Replace the example index and time bounds with the values for a recreated environment. Queries intentionally avoid displaying passwords or publishing raw source identifiers.

## Cowrie Event Distribution

```spl
index=main source="*/cowrie.json"
| stats count by eventid
| sort -count
```

## Source Summary

```spl
index=main (source="*/cowrie.json" OR source="*/conpot.log")
| eval honeypot=case(match(source,"cowrie"),"Cowrie",match(source,"conpot"),"Conpot",true(),"Other")
| stats count values(honeypot) as targets dc(honeypot) as systems_targeted by src_ip
| sort -count
```

This query produced the private source-level aggregate from which the pseudonymized public summary was derived.

## Successful Cowrie Authentication Events

```spl
index=main source="*/cowrie.json" eventid="cowrie.login.success"
| stats count
```

The public portfolio records only the total. Raw IP, username, and password values remain private.

## Cowrie Command Summary

```spl
index=main source="*/cowrie.json" eventid="cowrie.command.input"
| stats count by input
| sort -count
```

Raw command strings remain private because they can contain IP addresses, URLs, credentials, and payload indicators. The public evidence publishes only behavior categories.

## Login Outcome Timeline

```spl
index=main source="*/cowrie.json" eventid IN ("cowrie.login.failed","cowrie.login.success")
| eval outcome=if(eventid="cowrie.login.success","success","failed")
| timechart span=1h count by outcome
```

## Cross-Service Sources

```spl
index=main (source="*/cowrie.json" OR source="*/conpot.log")
| eval honeypot=case(match(source,"cowrie"),"Cowrie",match(source,"conpot"),"Conpot",true(),"Other")
| stats count values(honeypot) as targets dc(honeypot) as systems_targeted by src_ip
| where systems_targeted=2
| sort -count
```

The same source value appearing in both datasets is an observable correlation, not actor or campaign attribution.

## ICS Protocol Summary

Conpot was ingested as line-oriented logs. The retained evidence classified exact protocol labels and used an explicit `Other` fallback:

```spl
index=main source="*/conpot.log"
| eval protocol=case(
    match(_raw,"(?i)\\bS7\\b"),"S7",
    match(_raw,"(?i)\\bmodbus\\b"),"Modbus",
    match(_raw,"(?i)\\bCOTP\\b"),"COTP",
    match(_raw,"(?i)\\bsnmp\\b"),"SNMP",
    true(),"Other"
  )
| stats count by protocol
| sort -count
```

## Geographic Distribution

```spl
index=main (source="*/cowrie.json" OR source="*/conpot.log")
| stats count by src_ip
| iplocation src_ip
| where isnotnull(Country)
| stats sum(count) as events by Country
| sort -events
```

IP geolocation is approximate and does not establish actor location. No geographic results are claimed in the public findings because the retained exports do not contain a country aggregate.
