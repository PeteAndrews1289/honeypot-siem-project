# Splunk Searches

## Cowrie Event Distribution

```spl
index=main source="/home/honeypot/cowrie/var/log/cowrie/cowrie.json"
| stats count by eventid
| sort - count
Top Attacker IPs
index=main source="/home/honeypot/cowrie/var/log/cowrie/cowrie.json"
| stats count by src_ip
| sort - count
Successful Logins
index=main source="/home/honeypot/cowrie/var/log/cowrie/cowrie.json" eventid=cowrie.login.success
| stats count by src_ip, username, password
| sort - count
Failed vs Successful Logins
index=main source="/home/honeypot/cowrie/var/log/cowrie/cowrie.json"
(eventid=cowrie.login.failed OR eventid=cowrie.login.success)
| stats count by eventid
Command Inputs
index=main source="/home/honeypot/cowrie/var/log/cowrie/cowrie.json" eventid=cowrie.command.input
| stats count by input
| sort - count
Timeline
index=main source="/home/honeypot/cowrie/var/log/cowrie/cowrie.json"
| timechart count by eventid
Geolocation Table
index=main source="/home/honeypot/cowrie/var/log/cowrie/cowrie.json"
| stats count by src_ip
| iplocation src_ip
Geolocation Map
index=main source="/home/honeypot/cowrie/var/log/cowrie/cowrie.json"
| stats count by src_ip
| iplocation src_ip
| where isnotnull(lat) AND isnotnull(lon)
| geostats latfield=lat longfield=lon sum(count) as total
Conpot Source Search
index=main source="/home/honeypot/conpot/conpot.log"
| sort - _time
Combined Source Volume
index=main (source="/home/honeypot/cowrie/var/log/cowrie/cowrie.json" OR source="/home/honeypot/conpot/conpot.log")
| stats count by source
