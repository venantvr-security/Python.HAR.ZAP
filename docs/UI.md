# Web UI tour (Streamlit)

Real screenshots of the HAR-ZAP Streamlit app (`streamlit run app.py`).

## Guide
![Guide tab](assets/streamlit-home.png)

## Upload & Configure
Upload a HAR, set scope/exclude domains and attack types, then run.
![Upload & scan configuration](assets/streamlit-upload.png)

## Red Team
Offensive tests — unauthenticated replay, mass assignment, hidden parameters, race conditions.
![Red Team tab](assets/streamlit-redteam.png)

## IDOR Testing
Two-session cross-user access-control testing (BOLA / API1).
![IDOR testing tab](assets/streamlit-idor.png)

## Passive Scan
Non-invasive checks — security headers, sensitive-data leaks, token entropy.
![Passive scan tab](assets/streamlit-passive.png)

## Findings-first report
Severity-sorted, each finding with impact, a replayable curl proof, the fix, and its OWASP API tag.
![Findings-first report](assets/findings-report.png)

### Findings-first report — dark theme
The report is theme-aware (follows the viewer's light/dark preference).
![Findings-first report (dark)](assets/findings-report-dark.png)
