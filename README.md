# Python IOC Enrichment Tool — AbuseIPDB + Splunk Lookup Pipeline

## Summary
A SOAR-style IOC enrichment pipeline: SSH brute-force activity is ingested into Splunk, unique source IPs are extracted via SPL, enriched in bulk against AbuseIPDB's reputation API using a Python script, and the results are pushed back into Splunk as a lookup table, allowing any analyst to enrich future search results inline (| lookup) without live API calls at search time. One IP (197.248.207.139) returned a maximum-confidence malicious verdict from real, currently active threat intelligence, validating the pipeline end to end against genuine (not fabricated) abuse data.

## Authorized Lab Disclaimer
All activity in this repository was performed against infrastructure I built, own, or was explicitly authorized to test (a synthetic log file, a personal local Splunk instance). No production systems or third-party assets were accessed or scanned. IP reputation lookups were performed only as read-only, passive queries against a public threat-intelligence API (AbuseIPDB) -- no IPs listed here were contacted, probed, or attacked. Published for educational and professional-demonstration purposes only.

## Environment / Architecture
- WSL (Ubuntu), consistent with the rest of this portfolio
- Splunk Enterprise, installed locally in WSL (~/splunk), index ioc_enrichment
- Python 3 (venv), requests + python-dotenv
- AbuseIPDB API (free tier) for IP reputation enrichment
- API key stored in a local .env file, excluded from version control

Pipeline flow:

1. sample-logs/ssh-auth.log
2. --> ingested into Splunk index=ioc_enrichment
3. --> SPL extraction search (detections/ioc-extraction-search.spl)
4. --> evidence/iocs-raw-export.csv (unique IPs + attempt counts)
5. --> scripts/enrich_iocs.py calls AbuseIPDB API
6. --> evidence/iocs-enriched.csv (abuse score, verdict, country, ISP, reports)
7. --> uploaded as Splunk lookup table ioc_enrichment.csv
8. --> any future Splunk search can enrich src_ip fields inline via | lookup

## Objective & Scope
Build a working enrichment pipeline that closes the loop between a SIEM (Splunk) and an external threat-intelligence source (AbuseIPDB), demonstrating the core building block of SOAR (Security Orchestration, Automation and Response) tooling: automatically adding context to raw security events so an analyst doesn't have to manually pivot to a browser for every IOC.

In scope: IP reputation enrichment for SSH brute-force source IPs.
Out of scope (documented as stretch goals below): file hash enrichment via VirusTotal, fully automated scheduled-alert triggering.

## Methodology
1. Generated a synthetic SSH auth log (sample-logs/ssh-auth.log) modeling a brute-force scenario: repeated failed logins from a small set of source IPs, plus benign public DNS resolver IPs as a noise/false-positive control group.
2. Ingested the log into a dedicated Splunk index (ioc_enrichment), sourcetype auto-detected as linux_secure.
3. Authored an SPL search (detections/ioc-extraction-search.spl) to extract unique source IPs and failed-attempt counts via rex + stats.
4. Exported extraction results to CSV (evidence/iocs-raw-export.csv).
5. Wrote a Python script (scripts/enrich_iocs.py) that reads the CSV, queries AbuseIPDB's /check endpoint for each unique IP (90-day report window), classifies each IP into a verdict bucket (malicious >=75, suspicious >=25, benign below), and writes enriched results to evidence/iocs-enriched.csv.
6. Uploaded the enriched CSV into Splunk as a lookup table (ioc_enrichment.csv) with a corresponding lookup definition.
7. Validated the full pipeline with a second SPL search (detections/ioc-lookup-enrichment.spl) joining raw log events against the lookup table, confirming enrichment data appears inline with zero live API calls at search time.

## Findings

| ID | Severity | Description | Evidence | Reference |
|----|----------|--------------|----------|-----------|
| F1 | High | 197.248.207.139 (Kenya, Safaricom Limited) returned an AbuseIPDB confidence score of 100 with 5,581 reports -- confirmed, currently active malicious source performing SSH brute-force. Generated 3 failed-login events in the sample log. | evidence/02-lookup-enrichment-demo.png, evidence/iocs-enriched.csv | MITRE ATT&CK T1110.001 |
| F2 | Low-Medium | 167.99.75.138 (Singapore, DigitalOcean) generated the highest raw attempt count in the sample (7 attempts) but returned a comparatively low AbuseIPDB score (16) despite 34 historical reports -- illustrates that confidence score and raw report volume do not move in lockstep. | evidence/iocs-enriched.csv | MITRE ATT&CK T1110.001 |
| F3 | Informational | 165.154.23.26 (Hong Kong, UCloud) returned a low but nonzero score (5) -- a marginal/watchlist case rather than a clear verdict either way. | evidence/iocs-enriched.csv | -- |
| F4 | Informational | Public DNS resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9) accumulated substantial historical report counts (up to 205) purely from shared/misattributed usage, yet correctly returned a 0 abuse score -- validating that the enrichment pipeline resists false-positive flagging on high-report-volume-but-benign IPs. | evidence/iocs-enriched.csv | -- |

## Detection & Remediation
- Detection: The extraction search (detections/ioc-extraction-search.spl) can be scheduled to run periodically against live auth logs, surfacing new source IPs for enrichment on a recurring basis (not implemented as a standing scheduled alert in this iteration -- see Lessons Learned).
- Remediation (for a real environment): Block/deny confirmed-malicious source IPs (verdict = malicious) at the firewall or via fail2ban; rate-limit or alert on suspicious-tier IPs pending analyst review; no action needed on benign-tier IPs beyond normal baseline logging.

## Lessons Learned
- Threat intel goes stale. IPs pulled from a several-year-old public documentation example returned a 0 abuse score once queried live -- their historical reports had aged out of AbuseIPDB's 90-day scoring window. A "known-bad" IP list is only as good as its last verification date; this pipeline's maxAgeInDays parameter makes that staleness visible rather than hiding it.
- Report volume does not equal confidence. Public DNS resolvers accumulate large report counts from shared/misattributed usage without being malicious; AbuseIPDB's confidence score correctly discounts this, but a naive "sort by report count" approach would have produced false positives.
- Score and report count can also disagree in the other direction. 167.99.75.138 had the highest raw brute-force attempt count in the sample but only a moderate score -- a reminder that automated verdict buckets are a starting point for triage, not a substitute for analyst judgment on a borderline case.
- Running Splunk as root, even once, causes cascading permission failures. An early sudo splunk start (this WSL Splunk instance is installed under the home directory and should never need root) left config and PID files owned by root, breaking normal-user access to the instance days later. Recovered via chown -R back to the user account; when that didn't fully resolve it, a clean reinstall from the still-available original .tgz archive was faster and safer than continuing to patch permissions file-by-file.
- Deleting Splunk's etc/auth directory breaks credential decryption instance-wide, not just certificates -- this cost an extra troubleshooting cycle before the decision was made to do a full clean reinstall rather than keep patching. Back up (mv, don't rm) before deleting anything under a running application's auth/secrets directory.
- Splunk's default search time range ("Last 24 hours") silently returns zero results against fixed-date synthetic data as real-world time passes -- always explicitly set "All time" when working with static sample logs rather than assuming a 0-event result means an ingest failure.
- Uploaded lookup tables default to "Private" sharing under the uploading user's personal context and must be explicitly set to a broader sharing scope (App/Global) before they're usable the way a shared organizational detection artifact should be.
- Stretch goals not pursued here: wiring the extraction search as a standing scheduled Splunk alert that automatically triggers the enrichment script (Project 1 has a real implementation of this pattern for a different detection); file-hash enrichment via VirusTotal as a second IOC type; response caching to avoid repeat API calls against the same IP across multiple runs; explicit handling for AbuseIPDB's free-tier daily rate limit (1,000 requests/day) once IOC volume scales beyond a handful of IPs per run.

## Evidence files (in evidence/)
00 Splunk ingest confirmed (15 events) -- 01 IOC extraction search results (6 unique IPs, sorted by attempt count) -- 02 Full lookup-enrichment demo (raw events joined against enrichment data) -- iocs-raw-export.csv raw extraction output -- iocs-enriched.csv final AbuseIPDB-enriched results with verdicts
