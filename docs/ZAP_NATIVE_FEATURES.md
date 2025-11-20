# ZAP Native Features - Advanced API Guide

## Overview

Comprehensive reference for leveraging OWASP ZAP built-in capabilities before writing custom code. Organized by security testing phase.

## Table of Contents

1. [Discovery & Crawling](#discovery--crawling)
2. [Passive Scanning](#passive-scanning)
3. [Active Scanning](#active-scanning)
4. [Authentication & Session](#authentication--session)
5. [Context Management](#context-management)
6. [Script Engine](#script-engine)
7. [Fuzzing](#fuzzing)
8. [Automation Framework](#automation-framework)
9. [Reporting](#reporting)
10. [API Integration](#api-integration)

## Discovery & Crawling

### Traditional Spider

**Purpose:** Crawl HTML links, forms, comments for static content.

```python
from zapv2 import ZAPv2

zap = ZAPv2(proxies={'http': 'http://localhost:8080'})

# Start spider
scan_id = zap.spider.scan(
    url='https://target.app',
    maxchildren=10,  # Max nodes per level
    recurse=True,
    contextname='MyContext',
    subtreeonly=False
)

# Monitor progress
while int(zap.spider.status(scan_id)) < 100:
    print(f"Spider progress: {zap.spider.status(scan_id)}%")
    time.sleep(2)

# Get results
urls = zap.spider.results(scan_id)
print(f"Discovered {len(urls)} URLs")
```

**Configuration Options:**

```python
# Set max duration (minutes)
zap.spider.set_option_max_duration(10)

# Set max depth
zap.spider.set_option_max_depth(5)

# Parse robots.txt
zap.spider.set_option_parse_robots_txt(True)

# Handle GET forms
zap.spider.set_option_handle_parameters(True)
```

**Use Cases:**

- Traditional web apps (server-side rendering)
- Multi-page forms
- Documentation sites

### Ajax Spider

**Purpose:** Execute JavaScript, capture AJAX requests, handle SPAs.

```python
# Start Ajax spider (uses Firefox headless)
scan_id = zap.ajaxSpider.scan(
    url='https://spa.target.app',
    inscope='true',
    contextname='MyContext'
)

# Monitor (no percentage, just running/stopped)
while zap.ajaxSpider.status(scan_id) == 'running':
    print(f"Requests: {zap.ajaxSpider.number_of_results(scan_id)}")
    time.sleep(5)

# Get full results
results = zap.ajaxSpider.full_results(scan_id)

# Stop manually if needed
zap.ajaxSpider.stop(scan_id)
```

**Configuration:**

```python
# Set browser (firefox/chrome-headless)
zap.ajaxSpider.set_option_browser_id('firefox-headless')

# Max duration (minutes)
zap.ajaxSpider.set_option_max_duration(10)

# Max crawl depth
zap.ajaxSpider.set_option_max_crawl_depth(5)

# Number of browser instances
zap.ajaxSpider.set_option_number_of_browsers(2)

# Click elements even if already visited
zap.ajaxSpider.set_option_click_elems_once(False)

# Custom click elements (CSS selectors)
zap.ajaxSpider.set_option_click_default_elems(True)
```

**Use Cases:**

- React/Vue/Angular SPAs
- Infinite scroll pages
- Dynamic menus
- AJAX-loaded content

**Performance Comparison:**
| App Type | Traditional Spider | Ajax Spider |
|----------|-------------------|-------------|
| Static blog | 50 URLs, 10s | 50 URLs, 45s |
| SPA dashboard | 5 URLs, 5s | 120 URLs, 90s |

## Passive Scanning

### Built-in Scanners

**Purpose:** Analyze HTTP traffic without sending additional requests.

```python
# Enable all passive scanners (50+ rules)
zap.pscan.enable_all_scanners()

# Or enable specific scanners
zap.pscan.enable_scanners('10055,10096,10109')  # CSP, Timestamp, Wappalyzer

# Set alert thresholds
zap.pscan.set_scanner_alert_threshold('10055', 'MEDIUM')

# Disable noisy scanners
zap.pscan.disable_scanners('10027')  # Information disclosure

# Wait for queue to drain
while int(zap.pscan.records_to_scan) > 0:
    print(f"Remaining: {zap.pscan.records_to_scan}")
    time.sleep(2)

# Get alerts
alerts = zap.core.alerts(baseurl='https://target.app')
```

### Key Passive Scanners

| Scanner ID | Name                                         | Description                       |
|------------|----------------------------------------------|-----------------------------------|
| 10010      | Cookie No HttpOnly Flag                      | Detects cookies without HttpOnly  |
| 10011      | Cookie Without Secure Flag                   | HTTP-only cookies                 |
| 10015      | Incomplete or No Cache-control               | Missing cache headers             |
| 10017      | Cross-Domain JavaScript Source               | External JS inclusion             |
| 10020      | X-Frame-Options Header                       | Clickjacking protection           |
| 10021      | X-Content-Type-Options Header                | MIME sniffing protection          |
| 10023      | Information Disclosure - Debug Errors        | Stack traces                      |
| 10027      | Information Disclosure - Suspicious Comments | TODO, FIXME, passwords            |
| 10035      | Strict-Transport-Security Header             | Missing HSTS                      |
| 10055      | CSP Header Not Set                           | Content Security Policy           |
| 10096      | Timestamp Disclosure                         | Unix timestamps                   |
| 10109      | Modern Web Application                       | Technology detection (Wappalyzer) |

**Custom Passive Scanner Script:**

```python
# scripts/passive/token_entropy.py
def scan(ps, msg, src):
    """Check JWT token entropy"""
    import re
    import math

    body = msg.getResponseBody().toString()
    tokens = re.findall(r'[A-Za-z0-9\-_]{20,}', body)

    for token in tokens:
        entropy = calculate_entropy(token)
        if entropy < 3.5:  # Low entropy = predictable
            ps.raiseAlert(
                2,  # Medium risk
                'Low Token Entropy',
                f'Token "{token[:10]}..." has entropy {entropy:.2f}',
                msg.getRequestHeader().getURI().toString(),
                token
            )


def calculate_entropy(s):
    from collections import Counter

    prob = [float(count) / len(s) for count in Counter(s).values()]
    return -sum(p * math.log(p, 2) for p in prob)
```

## Active Scanning

### Basic Active Scan

```python
# Start active scan
scan_id = zap.ascan.scan(
    url='https://target.app/api',
    recurse=True,
    inscopeonly=True,
    scanpolicyname='Default Policy',
    method='GET',
    postdata=None
)

# Monitor progress
while int(zap.ascan.status(scan_id)) < 100:
    print(f"Active scan: {zap.ascan.status(scan_id)}%")
    time.sleep(5)

# Get results
alerts = zap.core.alerts(baseurl='https://target.app')
```

### Scan Policy Management

```python
# List available policies
policies = zap.ascan.scan_policy_names

# Create custom policy
zap.ascan.add_scan_policy('APIPolicy')

# List all scanners
scanners = zap.ascan.scanners()

# Configure scanners in policy
for scanner in scanners:
    scanner_id = scanner['id']

    # Set strength (LOW/MEDIUM/HIGH/INSANE)
    zap.ascan.set_policy_attack_strength('APIPolicy', scanner_id, 'HIGH')

    # Set threshold (OFF/LOW/MEDIUM/HIGH)
    zap.ascan.set_policy_alert_threshold('APIPolicy', scanner_id, 'LOW')

# Enable specific scanners
zap.ascan.set_scanner_attack_strength(scanner_id, 'HIGH')
zap.ascan.set_scanner_alert_threshold(scanner_id, 'MEDIUM')
```

### Key Active Scanners

| Scanner ID | Name                                | Category        |
|------------|-------------------------------------|-----------------|
| 40012      | Cross Site Scripting (Reflected)    | Injection       |
| 40014      | Cross Site Scripting (Persistent)   | Injection       |
| 40018      | SQL Injection                       | Injection       |
| 40019      | SQL Injection - MySQL               | Injection       |
| 40020      | SQL Injection - Hypersonic SQL      | Injection       |
| 40021      | SQL Injection - PostgreSQL          | Injection       |
| 40022      | SQL Injection - Oracle              | Injection       |
| 6          | Path Traversal                      | File Access     |
| 7          | Remote File Inclusion               | File Access     |
| 41         | Source Code Disclosure - Git        | Info Disclosure |
| 42         | Session Fixation                    | Session         |
| 10048      | Remote Code Execution - Shell Shock | RCE             |
| 90019      | Server Side Code Injection          | Injection       |
| 90020      | Remote OS Command Injection         | Injection       |

### Advanced Scan Configuration

```python
# Concurrent threads per host
zap.ascan.set_option_thread_per_host(5)

# Max scan duration (minutes)
zap.ascan.set_option_max_scan_duration_in_mins(60)

# Delay between requests (ms)
zap.ascan.set_option_delay_in_ms(100)

# Handle anti-CSRF tokens
zap.ascan.set_option_handle_anti_csrf_tokens(True)

# Inject plugin ID in header (for debugging)
zap.ascan.set_option_inject_plugin_id_in_header(False)

# Scan headers all requests
zap.ascan.set_option_scan_headers_all_requests(True)
```

## Authentication & Session

### Form-Based Authentication

```python
# Create context
context_id = zap.context.new_context('AuthContext')
zap.context.include_in_context('AuthContext', 'https://target.app/.*')

# Set form-based auth
login_url = 'https://target.app/login'
login_request_data = 'username={%username%}&password={%password%}'

zap.authentication.set_authentication_method(
    contextid=context_id,
    authmethodname='formBasedAuthentication',
    authmethodconfigparams=f'loginUrl={login_url}&loginRequestData={login_request_data}'
)

# Set logged-in indicator (regex)
zap.authentication.set_logged_in_indicator(
    contextid=context_id,
    loggedinindicatorregex='\\QLogout\\E'
)

# Set logged-out indicator
zap.authentication.set_logged_out_indicator(
    contextid=context_id,
    loggedoutindicatorregex='\\QLogin\\E'
)

# Create user
user_id = zap.users.new_user(context_id, 'testuser')
zap.users.set_authentication_credentials(
    contextid=context_id,
    userid=user_id,
    authcredentialsconfigparams='username=admin&password=admin123'
)

zap.users.set_user_enabled(context_id, user_id, True)
```

### HTTP/NTLM Authentication

```python
zap.authentication.set_authentication_method(
    contextid=context_id,
    authmethodname='httpAuthentication',
    authmethodconfigparams='hostname=target.app&realm=Admin&port=443'
)

zap.users.set_authentication_credentials(
    contextid=context_id,
    userid=user_id,
    authcredentialsconfigparams='username=admin&password=admin123'
)
```

### Script-Based Authentication

```python
# Load auth script
zap.script.load(
    scriptname='CustomAuth',
    scripttype='authentication',
    scriptengine='ECMAScript',
    filename='/zap/scripts/auth/custom_oauth.js'
)

# Set as auth method
zap.authentication.set_authentication_method(
    contextid=context_id,
    authmethodname='scriptBasedAuthentication',
    authmethodconfigparams=f'scriptName=CustomAuth'
)
```

**Example OAuth2 Script:**

```javascript
// custom_oauth.js
function authenticate(helper, paramsValues, credentials) {
    var msg = helper.prepareMessage();

    // Request access token
    msg.setRequestHeader(
        "POST /oauth/token HTTP/1.1\r\n" +
        "Host: auth.target.app\r\n" +
        "Content-Type: application/x-www-form-urlencoded"
    );

    msg.setRequestBody(
        "grant_type=password&" +
        "username=" + credentials.getParam("username") + "&" +
        "password=" + credentials.getParam("password") + "&" +
        "client_id=app_client"
    );

    helper.sendAndReceive(msg);

    var token = extractToken(msg.getResponseBody().toString());

    // Store for session management
    paramsValues.put("access_token", token);

    return msg;
}

function extractToken(body) {
    var json = JSON.parse(body);
    return json.access_token;
}
```

### Session Management

```python
# Cookie-based sessions
zap.sessionManagement.set_session_management_method(
    contextid=context_id,
    methodname='cookieBasedSessionManagement'
)

# HTTP auth sessions
zap.sessionManagement.set_session_management_method(
    contextid=context_id,
    methodname='httpAuthSessionManagement'
)

# Script-based sessions
zap.script.load('SessionManager', 'session', 'ECMAScript', '/zap/scripts/session.js')
zap.sessionManagement.set_session_management_method(
    contextid=context_id,
    methodname='scriptBasedSessionManagement',
    methodconfigparams='scriptName=SessionManager'
)
```

## Context Management

### Create and Configure Context

```python
# Create context
context_id = zap.context.new_context('APIContext')

# Include URLs (regex)
zap.context.include_in_context('APIContext', 'https://api.target.app/v1/.*')
zap.context.include_in_context('APIContext', 'https://api.target.app/v2/.*')

# Exclude URLs
zap.context.exclude_from_context('APIContext', '.*logout.*')
zap.context.exclude_from_context('APIContext', '.*delete.*')

# Set in scope
zap.context.set_context_in_scope('APIContext', True)

# Technology detection
technologies = ['Db.PostgreSQL', 'Language.Python', 'OS.Linux']
for tech in technologies:
    zap.context.include_technology(context_id, tech)

# Export context
context_json = zap.context.export_context('APIContext', '/tmp/context.json')
```

### Available Technologies

```python
# List all technologies
techs = zap.context.technology_names

# Common technologies:
# - Db.MySQL, Db.PostgreSQL, Db.MongoDB
# - Language.Python, Language.Java, Language.PHP
# - OS.Linux, OS.Windows
# - WS.Tomcat, WS.nginx, WS.IIS
```

## Script Engine

### Script Types

| Type             | Purpose                       | Invocation                |
|------------------|-------------------------------|---------------------------|
| `standalone`     | One-off automation            | Manual execution          |
| `active`         | Custom attack payloads        | During active scan        |
| `passive`        | Custom vulnerability checks   | On HTTP traffic           |
| `proxy`          | Request/response manipulation | Before forwarding         |
| `targeted`       | Right-click context menu      | Manual invocation         |
| `authentication` | Custom login flows            | Before authenticated scan |
| `session`        | Session management            | Token refresh             |
| `httpsender`     | Global request interceptor    | Every request             |

### Load and Manage Scripts

```python
# Load script
zap.script.load(
    scriptname='MyScript',
    scripttype='active',
    scriptengine='ECMAScript',  # or 'python', 'Zest'
    filename='/zap/scripts/active/myscript.js',
    scriptdescription='Custom mass assignment check',
    charset='UTF-8'
)

# Enable script
zap.script.enable('MyScript')

# List scripts
scripts = zap.script.list_scripts

# Remove script
zap.script.remove('MyScript')
```

### Active Script Template

```javascript
// scripts/active/hidden_params.js
var Control = Java.type('org.parosproxy.paros.control.Control');
var ExtensionHistory = Java.type('org.zaproxy.zap.extension.history.ExtensionHistory');

function scan(as, msg, src) {
    var url = msg.getRequestHeader().getURI().toString();

    // Hidden parameters to test
    var hiddenParams = ['debug', 'admin', 'isTest', 'role'];

    hiddenParams.forEach(function(param) {
        var testMsg = msg.cloneRequest();

        // Add parameter to URL
        var newUrl = url + (url.indexOf('?') > 0 ? '&' : '?') + param + '=true';
        testMsg.getRequestHeader().setURI(new org.apache.commons.httpclient.URI(newUrl, true));

        as.sendAndReceive(testMsg);

        var responseCode = testMsg.getResponseHeader().getStatusCode();
        var responseBody = testMsg.getResponseBody().toString();

        // Check for privilege escalation indicators
        if (responseBody.indexOf('admin') > 0 || responseBody.indexOf('debug') > 0) {
            as.raiseAlert(
                1, // risk: High
                'Hidden Parameter Exposure',
                'Parameter "' + param + '" reveals sensitive functionality',
                newUrl,
                param,
                '',
                'Remove or protect hidden parameters',
                responseBody.substring(0, 200),
                testMsg
            );
        }
    });
}
```

### Passive Script Template

```python
# scripts/passive/jwt_expiry.py
def scan(ps, msg, src):
    import base64
    import json
    import time

    auth_header = msg.getRequestHeader().getHeader('Authorization')

    if auth_header and 'Bearer ' in auth_header:
        token = auth_header.replace('Bearer ', '')
        parts = token.split('.')

        if len(parts) == 3:
            try:
                # Decode JWT payload
                payload = base64.urlsafe_b64decode(parts[1] + '==')
                claims = json.loads(payload)

                exp = claims.get('exp')
                if exp:
                    ttl = exp - int(time.time())

                    if ttl > 86400:  # > 1 day
                        ps.raiseAlert(
                            1,  # Info
                            'Long-Lived JWT Token',
                            f'Token expires in {ttl / 3600:.1f} hours',
                            msg.getRequestHeader().getURI().toString(),
                            'Authorization'
                        )
            except:
                pass
```

## Fuzzing

### Basic Fuzzing

```python
# Start HTTP fuzzer
zap.fuzzer.add_fuzzer(
    url='https://target.app/api/user/123',
    name='UserID Fuzzer',
    method='GET',
    postdata='',
    headerregex='',
    payloadsjson='["1","2","999","admin","../etc/passwd"]'
)

# Start fuzzer
scan_id = zap.fuzzer.scan()

# Monitor
while zap.fuzzer.scan_progress(scan_id) < 100:
    print(f"Fuzzing: {zap.fuzzer.scan_progress(scan_id)}%")
    time.sleep(2)

# Get results
results = zap.fuzzer.scan_results(scan_id)
```

### Advanced Fuzzing with Processors

```python
# Use built-in fuzzers
zap.fuzzer.add_fuzzer(
    url='https://target.app/api/user/{id}',
    fuzzlocations='[{"method":"url","location":"id"}]',
    fuzzersource='file',
    fuzzersourcefile='/usr/share/wordlists/ids.txt'
)

# Add request processor (e.g., base64 encode)
zap.fuzzer.add_request_processor(
    scan_id,
    processor_type='base64_encode',
    location='body'
)
```

## Automation Framework

### Complete Automation Plan

```yaml
# config/automation.yaml
env:
  contexts:
    - name: "Production API"
      urls:
        - "https://api.prod.app"
      includePaths:
        - "https://api.prod.app/v1/.*"
      excludePaths:
        - ".*logout.*"
        - ".*delete.*"
      authentication:
        method: "form"
        parameters:
          loginUrl: "https://api.prod.app/login"
          loginRequestData: "username={%username%}&password={%password%}"
        verification:
          method: "response"
          loggedInRegex: "\\QLogout\\E"
          loggedOutRegex: "\\QLogin\\E"
      users:
        - name: "admin"
          credentials:
            username: "admin@example.com"
            password: "${ADMIN_PASSWORD}"  # From env var

  parameters:
    failOnError: true
    failOnWarning: false
    progressToStdout: true

jobs:
  - type: addOns
    install:
      - "pscanrulesBeta"
      - "ascanrulesBeta"

  - type: script
    parameters:
      action: "add"
      type: "passive"
      engine: "ECMAScript"
      name: "CustomTokenCheck"
      file: "/zap/scripts/passive/token_entropy.js"

  - type: passiveScan-config
    parameters:
      maxAlertsPerRule: 10
      scanOnlyInScope: true
      enableScanners:
        - 10055  # CSP
        - 10096  # Timestamp
        - 10109  # Technology detection

  - type: spider
    parameters:
      context: "Production API"
      user: "admin"
      maxDuration: 10
      maxDepth: 5
      maxChildren: 10

  - type: ajaxSpider
    parameters:
      context: "Production API"
      user: "admin"
      maxDuration: 10
      maxCrawlDepth: 5
      browserId: "firefox-headless"

  - type: passiveScan-wait
    parameters:
      maxDuration: 10

  - type: activeScan
    parameters:
      context: "Production API"
      user: "admin"
      policy: "SQL-Injection,Path-Traversal,XSS"
      maxRuleDurationInMins: 5
      maxScanDurationInMins: 60
      threadPerHost: 5

  - type: report
    parameters:
      template: "traditional-json"
      reportDir: "/zap/reports"
      reportFile: "automation-report"
      reportTitle: "Production API Security Scan"
      reportDescription: "Automated scan via ZAP Automation Framework"

  - type: outputSummary
    parameters:
      format: "json"
      summaryFile: "/zap/reports/summary.json"
```

### Run Automation Plan

```python
# Python API
zap.automation.run_plan('/zap/config/automation.yaml')

# CLI
# docker run -v $(pwd):/zap/wrk/:rw -t zaproxy/zap-stable zap.sh \
#   -cmd -autorun /zap/wrk/automation.yaml
```

## Reporting

### Generate Reports

```python
# HTML report
report = zap.core.htmlreport()
with open('report.html', 'w') as f:
    f.write(report)

# XML report
report = zap.core.xmlreport()
with open('report.xml', 'w') as f:
    f.write(report)

# JSON report (custom)
alerts = zap.core.alerts(baseurl='https://target.app')
import json

with open('report.json', 'w') as f:
    json.dump(alerts, f, indent=2)

# Markdown report
report = zap.core.mdreport()
with open('report.md', 'w') as f:
    f.write(report)
```

### Alert Filtering

```python
# Get high-risk alerts only
high_alerts = [
    alert for alert in zap.core.alerts()
    if alert['risk'] == 'High'
]

# Group by type
from collections import defaultdict

grouped = defaultdict(list)
for alert in zap.core.alerts():
    grouped[alert['alert']].append(alert)

# Get unique vulnerabilities (deduplicate)
unique = {alert['alert']: alert for alert in zap.core.alerts()}
```

## API Integration

### OpenAPI Import

```python
# Import OpenAPI spec
zap.openapi.import_url(
    url='https://api.target.app/swagger.json',
    hostoverride='api.target.app',
    contextid=context_id
)

# Or import from file
zap.openapi.import_file(
    file='/tmp/openapi.yaml',
    target='https://api.target.app',
    contextid=context_id
)
```

### GraphQL Support

```python
# Import GraphQL schema
zap.graphql.import_url(
    url='https://api.target.app/graphql',
    endurl='https://api.target.app/graphql'
)

# Set query generation depth
zap.graphql.set_option_max_query_depth(5)
```

### SOAP/XML Support

```python
# Import WSDL
zap.soap.import_wsdl(
    file='/tmp/service.wsdl'
)
```

## Performance Tuning

### Memory Configuration

```bash
# Increase ZAP heap size
docker run -e JAVA_OPTS="-Xmx4g" zaproxy/zap-stable
```

### Scan Optimization

```python
# Reduce threads for rate-limited APIs
zap.ascan.set_option_thread_per_host(2)

# Increase for internal testing
zap.ascan.set_option_thread_per_host(10)

# Delay between requests (ms)
zap.ascan.set_option_delay_in_ms(500)

# Max alerts per rule (prevent alert flood)
zap.ascan.set_option_max_results_to_list(100)
```

### Database Cleanup

```python
# Clear session (keeps config)
zap.core.new_session(name='', overwrite=True)

# Delete old alerts
zap.core.delete_all_alerts()

# Clear sites tree
zap.core.delete_site_node(url='https://target.app', method='GET')
```

## Security Best Practices

### API Key Protection

```python
# Use environment variable
api_key = os.getenv('ZAP_API_KEY')
zap = ZAPv2(apikey=api_key, proxies={'http': 'http://localhost:8080'})

# Restrict API access
# In Docker: -config api.addrs.addr.name=localhost -config api.addrs.addr.regex=false
```

### Safe Mode (Prevent Attacks on Production)

```python
# Enable safe mode (disables attacks)
zap.core.set_mode('safe')

# Standard mode (allows attacks on in-scope targets)
zap.core.set_mode('standard')

# Protected mode (attacks only with confirmation)
zap.core.set_mode('protect')
```

### Scope Management

```python
# Only scan in-scope targets
zap.ascan.scan(url=target, inscopeonly=True)

# Verify scope before scanning
in_scope = zap.core.is_in_scope(url)
if not in_scope:
    raise ValueError(f"{url} not in scope!")
```

## Troubleshooting

### Common Issues

```python
# Check ZAP version
version = zap.core.version()

# Get ZAP logs
logs = zap.core.messages()

# Test connectivity
try:
    zap.core.version()
except Exception as e:
    print(f"ZAP not reachable: {e}")

# Verify API key
try:
    zap.core.alerts()
except Exception as e:
    print(f"Invalid API key: {e}")
```

### Debug Mode

```bash
# Start ZAP with debug logging
docker run -e ZAP_LOGGING="-config log4j.logger.org.zaproxy=DEBUG" zaproxy/zap-stable
```

## References

- [ZAP API Docs](https://www.zaproxy.org/docs/api/)
- [ZAP Python API](https://pypi.org/project/python-owasp-zap-v2.4/)
- [Community Scripts](https://github.com/zaproxy/community-scripts)
- [Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
