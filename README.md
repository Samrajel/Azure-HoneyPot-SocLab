# Azure-HoneyPot-SocLab
TL;DR

I exposed an Azure VM as an RDP honeypot and collected 200K+ security events in 2 days. Analysis of the failed-logon telemetry revealed two distinct brute-force campaigns (an 11K-attempt single-account dictionary and a slower multi-account spray) — but the attack map placed them in the wrong countries. Auditing the lab's static GeoIP watchlist uncovered duplicate conflicting entries, ~6% coverage gaps, and systematic mislabeling. I replaced the watchlist with KQL's built-in geo_info_from_ip_address(), verified attributions against RDAP registry data, and built a Sentinel analytics rule to catch any successful compromise. Full queries, tooling, and IOCs below


Lab architecture

It's the lab i made in Azure Free trial
1 Resource group with Log Analytics Workspace, 1 Virtual Network that has 1 VM running. I've set up sentinel to document and turn the raw data into heat-map and got a incident rule in-case honeypot turns into cypto-miner. 

