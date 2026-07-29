# Azure Honeypot SOC Lab — When Your Attack Map Lies to You

An RDP honeypot on Azure, a Sentinel detection pipeline, and an investigation that ended up
auditing its own enrichment data. What started as a standard lab exercise turned into a case
study in why analysts verify their sources: the GeoIP watchlist behind my attack map had
mislabeled my top attackers by thousands of kilometers.

> ⚠️ **TODO markers**: every `[LIKE_THIS]` value below needs final numbers from the live
> workspace before publishing. Search the file for `[` to find them all. Remove this block when done.

---

## TL;DR

I exposed an Azure VM as an RDP honeypot and collected **[FINAL_EVENT_COUNT]+ security events
in [SOAK_DAYS] days**. Analysis of the failed-logon telemetry revealed distinct brute-force
campaigns — an 11,004-attempt single-account dictionary run and a slower multi-account spray —
but the attack map placed them in the wrong countries. Auditing the lab's static GeoIP watchlist
uncovered duplicate conflicting entries, a ~6% coverage gap, and systematic mislabeling: my top
"Dutch" attackers were actually Russian and Romanian hosting, and a Turkish attacker had been
filed under Paris. I replaced the watchlist with KQL's built-in `geo_info_from_ip_address()`,
verified attributions against RDAP registry data, and built a Sentinel analytics rule to catch
any successful compromise. All queries, tooling, and IOCs are in this repo.

**Before — static watchlist:**

![Attack map built on the static GeoIP watchlist, top sources labeled as Dutch towns](images/01-old-map-watchlist.png)

**After — `geo_info_from_ip_address()`:**

![Corrected attack map using KQL's built-in geolocation, showing Russia, Romania and Türkiye](images/02-new-map-geofunction.png)

Same attack data. Two different worlds.

---

## Contents

1. [Lab architecture](#1-lab-architecture)
2. [First contact](#2-first-contact)
3. [Behavioral analysis: fingerprinting two bots](#3-behavioral-analysis-fingerprinting-two-bots)
4. [The map lies: auditing the GeoIP watchlist](#4-the-map-lies-auditing-the-geoip-watchlist)
5. [The fix: native geolocation + registry verification](#5-the-fix-native-geolocation--registry-verification)
6. [Detection engineering: catching the successful logon](#6-detection-engineering-catching-the-successful-logon)
7. [Lessons](#7-lessons)
8. [IOC appendix](#8-ioc-appendix)

---

## 1. Lab architecture

Everything runs in a single resource group on an Azure free trial — roughly ten resources total.
You do not need a budget to practice detection engineering.

![Resource group overview: VM, NSG, public IP, VNet, Log Analytics workspace, DCR, Sentinel](images/03-resource-group.png)

The pipeline:

```
Windows VM (RecieverCUS01, public IP, NSG open to Any on RDP/3389, host firewall disabled)
        │
        ▼
Azure Monitor Agent  ──(Data Collection Rule: Security Events)──►  Log Analytics workspace (LAW-SOCLAB)
        │
        ▼
Microsoft Sentinel (unified Defender portal) — KQL analysis, workbooks, watchlists, analytics rules
```

The deliberate misconfiguration that generates the entire dataset: the NSG inbound rule allows
TCP 3389 from `Any`, and the Windows host firewall is disabled. This is the "I'll just open RDP
real quick" mistake, made on purpose and contained — the VM is isolated in its own resource
group and VNet, holds nothing of value, and uses a strong unique local password so the honeypot
stays a honeypot.

Note: this lab was built during Sentinel's migration to the unified Defender portal
(security.microsoft.com). New workspaces are onboarded there directly, so screenshots show the
Defender portal rather than the classic Azure portal Sentinel experience most older guides use.

## 2. First contact

Time from VM deployment to first brute-force attempt: **minutes**. Azure's public IP ranges are
published and continuously scanned; a fresh RDP endpoint enters attacker target lists almost
immediately — and recycled Azure IPs may already be on them before you even boot.

Within the first ~4.5 hours the workspace logged **~17,600 failed logons** (Windows EventID
4625). After [SOAK_DAYS] days of soaking, that number stands at **[FINAL_4625_COUNT]** from
**[UNIQUE_IP_COUNT] unique source IPs**.

![Failed logon counts by source IP: two IPs dominate the dataset](images/04-top-talkers-query.png)

The first structural finding: attack volume is extremely concentrated. In the initial window,
**two IPs accounted for ~96% of all attempts**. "A country is attacking me" almost always
decomposes into "two rented servers are running loops."

## 3. Behavioral analysis: fingerprinting two bots

The per-IP timeline tells two completely different stories:

![Timechart of failed logons per IP in 5-minute bins, showing two distinct bot behaviors](images/05-timechart-two-bots.png)

```kusto
SecurityEvent
| where EventID == 4625
| summarize Count = count() by bin(TimeGenerated, 5m), IpAddress
| render timechart
```

**Bot #1 — the dictionary sprinter (82.208.111.94).** 11,004 attempts against a **single
username** at a machine-flat ~330 attempts per 5 minutes for 2h45m, then a hard stop
mid-window. Both the first and last 5-minute bins are partial — the run started and ended
mid-bin, and everything between is metronome-flat. That symmetry is the signature of a scripted
job with a finite input: ~11,000 attempts ÷ 1 account ≈ an 11K-line password dictionary,
executed sequentially to end-of-file, then process exit. No human varies that little.

**Bot #2 — the grinder (80.94.95.83).** Started ~37 minutes later, ran slower (~140/5min),
sprayed **7 different usernames**, and was still running days later. Different tool, different
strategy: breadth over depth.

**The attacker's wordlist, leaked into my telemetry.** RDP does not reveal whether a username
exists — a failed logon looks identical for a wrong user, wrong password, or both. So bots
guess both halves blindly, which means every 4625 exposes an entry from their dictionary:

![Failed logon events showing attempted usernames: ADMINISTRATOR, ADMINISTRADOR, ADMIN, USER, SYSTEM, BACKUP](images/06-username-wordlist.png)

`ADMINISTRATOR`, `ADMIN`, `USER`, `SYSTEM`, `BACKUP` — and `ADMINISTRADOR`, the **Spanish/Portuguese
localized Windows default**. The dictionary targets localized installs; the bot neither knows nor
cares that this machine isn't one. None of these accounts exist on the VM, which means every
single attempt in the dataset failed on the username before the password was ever evaluated.
(Renaming default accounts is not a substitute for closing port 3389 — but it is a real
defense-in-depth layer, and this dataset is the proof.)

## 4. The map lies: auditing the GeoIP watchlist

The lab guide this project started from enriches attacker IPs using a ~54,000-row GeoIP CSV
imported as a Sentinel watchlist, joined via `ipv4_lookup()`. The resulting map looked plausible:
top attackers in Amstelveen and Maarn, Netherlands — Europe's hosting hub, believable. I almost
published that finding.

Two absences bothered me. I expected my own failed logins from Istanbul to appear — they didn't
(for a good reason: my logins were *successful* 4624s, and the map only plots failures — the
hunch was wrong). And there was **no Russia anywhere on an RDP honeypot map**, which anyone
who has watched brute-force telemetry knows is an anomaly. The wrong hunch triggered the right
audit.

Auditing the watchlist file itself (script in [`audit/`](audit/)):

| Finding | Detail |
|---|---|
| Coverage | 54,803 rows, /16-summarized (+26 /8s) ≈ **93.7% of IPv4**. `ipv4_lookup` silently drops unmatched IPs — ~1 in 16 attackers never appears on the map at all |
| Duplicates | **2,684 networks listed twice; 1,750 with conflicting countries** (e.g. `1.1.0.0/16` as both Thailand and South Korea) — duplicated matches double-count events |
| Mislabels | Systematic. Verified against known allocations: `176.232.0.0/16` (Turkcell Superonline, TR) → "Loughborough, UK" · `195.175.0.0/16` (Türk Telekom) → "Wokingham, UK" · `88.255.0.0/16` (Türk Telekom) → "Norway" · `46.105.0.0/16` (OVH, FR) → "Ásványráró, Hungary" · `77.88.0.0/16` (Yandex, RU) → "Belfast, UK" |

The root cause is mechanical, not malicious: a stale GeoIP snapshot, summarized to /16
boundaries. Real allocations don't align to /16s, so each summarized row inherits whichever
sub-block won an aggregation step — and then drifts further as address space gets reassigned.
The failure mode is the dangerous kind: **it doesn't fail loudly, it fails plausibly.**

## 5. The fix: native geolocation + registry verification

Log Analytics has a built-in, Microsoft-maintained geolocation function that replaces the entire
watchlist mechanism:

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailureCount = count() by IpAddress
| extend geo = geo_info_from_ip_address(IpAddress)
| extend city = tostring(geo.city), country = tostring(geo.country),
         latitude = toreal(geo.latitude), longitude = toreal(geo.longitude)
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city, country,
          friendly_location = strcat(city, " (", country, ")")
```

(Summarizing *before* the geo lookup also means one enrichment per unique IP instead of per
event — cheaper and faster than the original per-event join.)

The corrected map redrew the threat picture:

| Old map said | Corrected attribution | Volume |
|---|---|---|
| Maarn, Netherlands | **Romania** (hosting) [RDAP_VERIFY] | [BOT2_FINAL_COUNT] |
| Amstelveen, Netherlands | **Nizhniy Novgorod, Russia** [RDAP_VERIFY] | 11,004 |
| Dhaka, Bangladesh | Bhiwandi, India [RDAP_VERIFY] | [COUNT] |
| Paris, France | **Türkiye** — a genuine Turkish attacker, not me | 3,134 |
| Ásványráró, Hungary | OVH datacenter, France ✓ (registry-confirmed) | 1 |

Russia, absent from the old map entirely, lights up in multiple locations on the corrected one.

**Verification layer.** MaxMind-backed geolocation is current, but attribution in a published
writeup deserves a second, independent source. [`verify_geoip.py`](verify_geoip.py) queries
authoritative registry data via **RDAP** (Registration Data Access Protocol — the structured
JSON successor to whois): it takes a list of IPs, bootstraps through rdap.org to the owning
regional registry (RIPE/ARIN/APNIC…), and outputs a claim-vs-registry verdict table.

![RDAP verification output comparing watchlist claims against registry data](images/07-rdap-verification.png)

One nuance worth stating: registry data gives the *registered owner and country* of an
allocation. For hosting providers, the physical server can sit in another country's datacenter,
and the operator behind the rented server can be anywhere. Attribution has layers —
registration ≠ server location ≠ attacker location — and honest analysis names which layer it's
claiming.

## 6. Detection engineering: catching the successful logon

A honeypot with the firewall off will eventually be compromised — that's the design. The signal
that it happened is a *successful* logon (EventID 4624) from an external IP: the moment the
honeypot stops being mine and starts being someone's crypto-miner. A scheduled Sentinel
analytics rule watches for exactly that:

```kusto
SecurityEvent
| where EventID == 4624
| where LogonType in (3, 10)
| where IpAddress !in ("-", "127.0.0.1", "::1")
| where AccountType == "User"
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| project TimeGenerated, TargetUserName, IpAddress, LogonType, LogonProcessName, WorkstationName
```

Filter rationale: LogonType 10 = RemoteInteractive (RDP), 3 = Network; machine-local logons and
computer accounts (`$` suffix) are noise; `ANONYMOUS LOGON` is excluded because exposed SMB
(port 445) completes benign anonymous NTLM sessions that would otherwise fire the rule
constantly — the classic false positive of 4624-based detections.

Rule configuration: runs every 5 minutes over a 10-minute lookback (overlap beats gaps),
severity High, MITRE ATT&CK Initial Access (T1078 Valid Accounts), **entity mapping** of
`IpAddress` → IP and `TargetUserName` → Account (which enables entity pages and the
investigation graph), and a dynamic alert name:
`Successful remote logon: {{TargetUserName}} from {{IpAddress}}`.

I deliberately did **not** exclude my own IP from the rule. Every one of my own RDP sessions
fires an incident, which I then triage and close as *Benign Positive — suspicious but expected*.
That trades alert fidelity for continuous end-to-end validation of the pipeline — and for triage
practice. The known risk of this model is autopilot: closing your own alerts without looking is
exactly how real SOCs miss real intrusions hiding in expected noise. The mitigation is checking
the IP field every time, and switching back to a high-fidelity exclusion if triage starts
feeling like a chore.

![Closed incident: dynamic title, mapped entities, Benign Positive classification with comment](images/08-closed-incident.png)

## 7. Lessons

**Enrichment data is an attack surface for your conclusions.** Nothing was wrong with my events,
my queries, or my map rendering — the lie entered through a reference CSV nobody thinks to
question. Stale enrichment doesn't fail loudly; it fails plausibly, which is worse.

**Absence of expected signal is itself a detection.** "No Russia on an RDP honeypot map" is what
triggered the audit. Knowing what the data *should* look like is as important as reading what it
does look like.

**Geography is mostly hosting, not attackers.** Even on the corrected map, top sources are
datacenter space — rented infrastructure. GeoIP tells you where the server is at best, never who
is behind it.

**A wrong hunch can drive a right investigation.** My original suspicion (my logins are missing)
rested on a wrong premise. Checking it anyway surfaced real defects. Verify your hunches; don't
pre-filter them.

**You can fingerprint tooling from aggregate telemetry alone.** Flat rate + single account +
symmetric partial bins = finite dictionary script. Slower + multi-account + long-running =
spray tool. No packet capture needed — the shape of a timechart was enough.

**None of it matters if port 3389 is open.** The remediation is boring and Azure-native:
NSG source restriction, Just-in-Time VM Access via Defender for Cloud, or Azure Bastion so RDP
never touches the internet. This honeypot exists so that lesson comes from someone else's VM,
not yours.

## 8. IOC appendix

Failed-logon sources observed on this honeypot, [DATE_RANGE]. Attribution is
registry-registered ownership (RDAP), not asserted attacker location.

| IP | Attempts | Behavior | Registry attribution |
|---|---|---|---|
| 82.208.111.94 | 11,004 | Single-account dictionary, ~330/5min, 2h45m run | [RDAP_VERIFY — Russia?] |
| 80.94.95.83 | [FINAL] | Multi-account spray (7 usernames), long-running | [RDAP_VERIFY — Romania?] |
| 103.117.186.132 | [FINAL] | Low-rate continuous | [RDAP_VERIFY] |
| [TURKISH_IP] | 3,134 | [BEHAVIOR] | [RDAP_VERIFY — Türkiye] |
| 45.142.193.145 | [FINAL] | [BEHAVIOR] | [RDAP_VERIFY] |
| 124.88.46.182 | 1 | Single probe | [RDAP_VERIFY — China Unicom?] |
| 46.105.132.55 | 1 | Single probe | OVH SAS, France ✓ |

Usernames attempted: `ADMINISTRATOR`, `ADMINISTRADOR`, `ADMIN`, `USER`, `SYSTEM`, `BACKUP`, [SEVENTH_USERNAME].

---

## Repository contents

```
├── README.md                 ← this writeup
├── images/                   ← screenshots (identifiers redacted)
├── queries/
│   ├── map-corrected.kql     ← geo_info_from_ip_address map query
│   ├── top-talkers.kql       ← per-IP breakdown with account counts and time bounds
│   ├── timechart.kql         ← 5-minute-bin per-IP timechart
│   └── detection-4624.kql    ← successful-logon analytics rule query
├── audit/
│   └── watchlist_audit.py    ← structural audit of the GeoIP watchlist CSV
└── verify_geoip.py           ← RDAP registry verification tool
```

## Credits & ethics

Lab foundation: [Josh Madakor's SOC honeypot project](https://www.youtube.com/@JoshMadakor) —
extended here with the watchlist audit, the native-geolocation rework, RDAP verification
tooling, and the detection rule. The honeypot is an isolated, disposable VM containing no real
data; attacker IPs are published as standard defensive IOC sharing. My own identifiers are
redacted from screenshots.

*Built as part of my SOC analyst portfolio. Feedback and questions welcome —
[LinkedIn]([YOUR_LINKEDIN_URL]).*
