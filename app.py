#!/usr/bin/env python3
import json
import tempfile

import pandas as pd
import streamlit as st

from modules.acceptance_engine import AcceptanceEngine
from modules.docker_manager import DockerZAPManager
from modules.har_analyzer import HARAnalyzer
from modules.idor_detector import IDORDetector, IDORStatus
from modules.passive_analysis import PassiveAnalysisOrchestrator
from modules.redteam_attacks import RedTeamOrchestrator
from modules.redteam_ui_helpers import render_redteam_results, render_passive_results
from modules.zap_scanner import ZAPScanner

st.set_page_config(
    page_title="DAST Security Platform",
    page_icon="🛡️",
    layout="wide"
)

if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'idor_results' not in st.session_state:
    st.session_state.idor_results = None
if 'docker_manager' not in st.session_state:
    st.session_state.docker_manager = None
if 'redteam_results' not in st.session_state:
    st.session_state.redteam_results = None
if 'passive_results' not in st.session_state:
    st.session_state.passive_results = None
if 'fuzzer_results' not in st.session_state:
    st.session_state.fuzzer_results = None
if 'extracted_tokens' not in st.session_state:
    st.session_state.extracted_tokens = None
if 'preprocessed_data' not in st.session_state:
    st.session_state.preprocessed_data = None


def main():
    st.title("🛡️ DAST Security Platform")
    st.markdown("**Automated Dynamic Application Security Testing with OWASP ZAP**")

    tabs = st.tabs(
        ["📤 Upload & Configure", "🔧 HAR Preprocessing", "🔍 ZAP Scan", "⚡ ZAP Fuzzer", "🎯 IDOR Testing", "🔴 Red Team", "🔵 Passive Scan", "📊 Results", "✅ Acceptance"])

    with tabs[0]:
        render_upload_tab()

    with tabs[1]:
        render_preprocessing_tab()

    with tabs[2]:
        render_zap_scan_tab()

    with tabs[3]:
        render_fuzzer_tab()

    with tabs[4]:
        render_idor_tab()

    with tabs[5]:
        render_redteam_tab()

    with tabs[6]:
        render_passive_tab()

    with tabs[7]:
        render_results_tab()

    with tabs[8]:
        render_acceptance_tab()


def render_upload_tab():
    st.header("HAR File Upload & Configuration")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Primary HAR File")
        har_file = st.file_uploader("Upload HAR file", type=['har'], key='har_primary')

        if har_file:
            try:
                har_data = json.load(har_file)
                st.session_state.har_data = har_data
                st.success(f"✓ Loaded: {len(har_data.get('log', {}).get('entries', []))} requests")

                config = {
                    'scope_domains': [],
                    'exclude_domains': [],
                    'allowed_methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
                }

                # Extract tokens for fuzzing
                from modules.token_extractor import TokenExtractor

                extractor = TokenExtractor(har_data)
                extracted_tokens = extractor.extract_all()
                fuzzing_recommendations = extractor.get_fuzzing_recommendations()

                st.session_state.extracted_tokens = extracted_tokens
                st.session_state.fuzzing_recommendations = fuzzing_recommendations

                # Show extraction summary
                total_ids = len(extracted_tokens.get('ids', []))
                total_usernames = len(extracted_tokens.get('usernames', []))
                total_params = len(extracted_tokens.get('params', []))

                st.info(f"🔍 Extracted {total_ids} IDs, {total_usernames} usernames, {total_params} parameters for fuzzing")

                analyzer = HARAnalyzer('', config)
                analyzer.entries = har_data.get('log', {}).get('entries', [])

                with st.expander("Preview URLs"):
                    urls = set()
                    for entry in analyzer.entries[:50]:
                        urls.add(entry.get('request', {}).get('url', ''))
                    for url in list(urls)[:20]:
                        st.code(url, language=None)

            except Exception as e:
                st.error(f"Error parsing HAR: {e}")

    with col2:
        st.subheader("Scan Configuration")

        scope_domains = st.text_area(
            "Scope Domains (one per line)",
            help="Only scan these domains. Leave empty for all."
        )

        exclude_domains = st.text_area(
            "Exclude Domains (one per line)",
            value="google-analytics.com\ngoogletagmanager.com\nfacebook.com",
            help="Skip these domains"
        )

        scan_types = st.multiselect(
            "Attack Types",
            ["SQL Injection", "XSS", "Path Traversal", "Command Injection", "XXE", "SSRF"],
            default=["SQL Injection", "XSS"]
        )

        full_assault = st.checkbox("🔥 FULL ZAP ASSAULT (All Policies)", value=False)

        if st.button("🔍 Analyze HAR", type="primary"):
            if 'har_data' in st.session_state:
                with st.spinner("Analyzing HAR file..."):
                    config = {
                        'scope_domains': [d.strip() for d in scope_domains.split('\n') if d.strip()],
                        'exclude_domains': [d.strip() for d in exclude_domains.split('\n') if d.strip()],
                        'allowed_methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                        'scan_fuzzable_urls': True,
                        'scan_api_endpoints': True
                    }

                    with tempfile.NamedTemporaryFile(mode='w', suffix='.har', delete=False) as f:
                        json.dump(st.session_state.har_data, f)
                        temp_har_path = f.name

                    analyzer = HARAnalyzer(temp_har_path, config)
                    parsed_data = analyzer.analyze()

                    st.session_state.parsed_data = parsed_data
                    st.session_state.config = config
                    st.session_state.scan_types = scan_types
                    st.session_state.full_assault = full_assault

                    st.success("✓ Analysis complete!")
                    st.json({
                        'total_urls': len(parsed_data['urls']),
                        'api_endpoints': len(parsed_data['api_endpoints']),
                        'fuzzable_urls': len(parsed_data['fuzzable_urls']),
                        'domains': list(parsed_data['domains'])
                    })


def render_zap_scan_tab():
    st.header("OWASP ZAP Scanner")

    if 'parsed_data' not in st.session_state:
        st.warning("⚠️ Please upload and analyze a HAR file first")
        return

    parsed_data = st.session_state.parsed_data

    st.subheader("Target Selection")

    fuzzable_df = pd.DataFrame([
        {
            'URL': item['url'],
            'Method': item['method'],
            'Parameters': ', '.join(item['params'])
        }
        for item in parsed_data['fuzzable_urls'][:50]
    ])

    if not fuzzable_df.empty:
        st.dataframe(fuzzable_df, use_container_width=True)

        selected_indices = st.multiselect(
            "Select targets to scan (or leave empty for all)",
            options=list(range(len(fuzzable_df))),
            format_func=lambda i: f"{fuzzable_df.iloc[i]['Method']} {fuzzable_df.iloc[i]['URL'][:80]}"
        )

        if st.button("🚀 Launch ZAP Scan", type="primary"):
            launch_zap_scan(parsed_data, selected_indices)
    else:
        st.info("No fuzzable URLs found in HAR file")


def launch_zap_scan(parsed_data, selected_indices):
    config = st.session_state.config

    progress_container = st.container()
    status_text = st.empty()

    try:
        with progress_container:
            status_text.text("Starting ZAP Docker container...")

            docker_manager = DockerZAPManager(config)
            zap_config = docker_manager.start_zap()
            st.session_state.docker_manager = docker_manager

            status_text.text("Configuring scanner...")

            scanner = ZAPScanner(zap_config, parsed_data, config)
            scanner.configure_context()
            scanner.configure_scan_policies()
            scanner.populate_site_tree()

            status_text.text("Executing scans...")

            progress_bar = st.progress(0)

            scan_results = scanner.execute_targeted_scans()

            progress_bar.progress(100)
            status_text.text("Collecting results...")

            alerts = scanner.get_alerts()

            st.session_state.scan_results = {
                'alerts': alerts,
                'scan_results': scan_results,
                'scanner': scanner
            }

            st.success(f"✓ Scan complete! Found {len(alerts)} alerts")

            st.rerun()

    except Exception as e:
        st.error(f"Scan failed: {e}")
        import traceback

        st.code(traceback.format_exc())


def render_idor_tab():
    st.header("🎯 IDOR Detection")

    st.markdown("""
    **Insecure Direct Object Reference Testing**

    Upload two HAR files from different user sessions to test for IDOR vulnerabilities.
    """)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Session A (User A)")
        har_a = st.file_uploader("HAR file for User A", type=['har'], key='har_user_a')

    with col2:
        st.subheader("Session B (User B)")
        har_b = st.file_uploader("HAR file for User B", type=['har'], key='har_user_b')

    max_workers = st.slider("Parallel Workers", 1, 10, 5)

    if st.button("🔬 Run IDOR Detection", type="primary"):
        if not har_a or not har_b:
            st.error("Please upload both HAR files")
            return

        try:
            session_a_data = json.load(har_a)
            session_b_data = json.load(har_b)

            with st.spinner("Running IDOR detection..."):
                detector = IDORDetector(
                    session_a_data,
                    session_b_data,
                    {'max_workers': max_workers}
                )

                results = detector.run_detection()
                st.session_state.idor_results = results
                st.session_state.idor_detector = detector

                summary = detector.get_summary()

                st.success("✓ IDOR detection complete!")

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Tests", summary['total_tests'])
                col2.metric("🚨 Vulnerable", summary['vulnerable'])
                col3.metric("✅ Protected", summary['protected'])
                col4.metric("⚠️ False Positives", summary['false_positives'])

                st.rerun()

        except Exception as e:
            st.error(f"IDOR detection failed: {e}")
            import traceback

            st.code(traceback.format_exc())


def show_attack_help(attack_type):
    """Display attack explanation in a popup"""
    doc_mapping = {
        "Unauthenticated Replay": "docs/redteam/unauthenticated_replay.md",
        "Mass Assignment": "docs/redteam/mass_assignment.md",
        "Hidden Parameters": "docs/redteam/hidden_parameters.md",
        "Race Conditions": "docs/redteam/race_conditions.md"
    }

    doc_path = doc_mapping.get(attack_type)
    if doc_path:
        try:
            with open(doc_path, 'r', encoding='utf-8') as f:
                content = f.read()
                st.markdown(content)
        except FileNotFoundError:
            st.error(f"Documentation not found: {doc_path}")


def render_redteam_tab():
    st.header("🔴 Red Team Attacks")

    st.markdown("""
    **Offensive Security Testing - Business Logic & Access Control**

    Tests:
    - 🔓 Unauthenticated Replay (Critical)
    - 🎭 Mass Assignment / Privilege Escalation
    - 🔍 Hidden Parameter Discovery
    - ⚡ Race Condition Detection
    """)

    if 'har_data' not in st.session_state:
        st.warning("⚠️ Please upload a HAR file first")
        return

    # Attack selection with help popups
    st.subheader("Attack Configuration")

    all_attacks = [
        ("🔓 Unauthenticated Replay", "Unauthenticated Replay"),
        ("🎭 Mass Assignment", "Mass Assignment"),
        ("🔍 Hidden Parameters", "Hidden Parameters"),
        ("⚡ Race Conditions", "Race Conditions")
    ]

    selected_attacks = []

    for display_name, attack_key in all_attacks:
        col1, col2 = st.columns([0.9, 0.1])

        with col1:
            if st.checkbox(display_name, value=attack_key in ["Unauthenticated Replay", "Mass Assignment"], key=f"attack_{attack_key}"):
                selected_attacks.append(attack_key)

        with col2:
            if st.button("❓", key=f"help_{attack_key}", help="Learn about this attack"):
                with st.expander(f"📚 {attack_key} - Explained", expanded=True):
                    show_attack_help(attack_key)

    attack_types = selected_attacks

    if st.button("🚀 Launch Red Team Attacks", type="primary"):
        with st.spinner("Running offensive security tests..."):
            try:
                orchestrator = RedTeamOrchestrator(st.session_state.har_data)
                results = orchestrator.run_all_attacks()

                st.session_state.redteam_results = results

                critical_findings = orchestrator.get_critical_findings()

                st.success(f"✓ Red Team scan complete! Found {len(critical_findings)} critical issues")

                summary = orchestrator.generate_report()

                col1, col2, col3 = st.columns(3)
                col1.metric("Total Tests", summary['total_tests'])
                col2.metric("🚨 Vulnerabilities", summary['total_vulnerabilities'])
                col3.metric("🔴 Critical", len(critical_findings))

                st.rerun()

            except Exception as e:
                st.error(f"Red Team scan failed: {e}")
                import traceback

                st.code(traceback.format_exc())


def render_fuzzer_tab():
    st.header("⚡ ZAP Intelligent Fuzzer")

    st.markdown("""
    **Smart Fuzzing with Extracted Tokens from HAR**

    Uses real values from your application traffic to:
    - Test IDOR with actual user IDs
    - Enumerate usernames/accounts
    - Fuzz parameters with observed values
    """)

    if 'har_data' not in st.session_state:
        st.warning("⚠️ Please upload a HAR file first")
        return

    # Show extracted tokens summary
    if st.session_state.get('extracted_tokens'):
        st.subheader("📊 Extracted Intelligence")

        tokens = st.session_state.extracted_tokens
        col1, col2, col3, col4 = st.columns(4)

        col1.metric("IDs Found", len(tokens.get('ids', [])))
        col2.metric("Usernames", len(tokens.get('usernames', [])))
        col3.metric("Emails", len(tokens.get('emails', [])))
        col4.metric("Parameters", len(tokens.get('params', [])))

        # Show fuzzing recommendations
        if st.session_state.get('fuzzing_recommendations'):
            st.subheader("💡 Fuzzing Recommendations")

            for rec in st.session_state.fuzzing_recommendations[:5]:
                with st.expander(f"{rec['priority']}: {rec['target']}"):
                    st.write(f"**Reason:** {rec['reason']}")
                    st.write(f"**Parameters:** {', '.join(rec['params'])}")
                    st.write(f"**Wordlist size:** {len(rec['wordlist'])} items")

                    if st.button(f"Preview wordlist", key=f"preview_{rec['target']}"):
                        st.code('\n'.join(str(x) for x in rec['wordlist'][:20]))

    st.subheader("🎯 Fuzzing Configuration")

    # Docker ZAP check
    if not st.session_state.get('docker_manager'):
        st.warning("⚠️ ZAP Docker must be running. Start it in the ZAP Scan tab first.")
        return

    fuzzing_type = st.selectbox(
        "Fuzzing Type",
        ["IDOR (ID Parameters)", "Username Enumeration", "Custom Parameter", "All Parameters"]
    )

    if fuzzing_type == "Custom Parameter":
        custom_url = st.text_input("Target URL")
        custom_param = st.text_input("Parameter to fuzz")
        wordlist_choice = st.selectbox("Wordlist", ["ids", "usernames", "emails", "paths", "params"])

        if st.button("🚀 Start Custom Fuzzing", type="primary"):
            st.info("Custom fuzzing feature requires ZAP integration - coming soon")

    elif st.button("🚀 Start Smart Fuzzing", type="primary"):
        if not st.session_state.get('extracted_tokens'):
            st.error("No tokens extracted. Upload a HAR file with traffic first.")
            return

        with st.spinner("Running intelligent fuzzing..."):
            try:
                st.info(f"Fuzzing type: {fuzzing_type}")
                st.info("⚠️ Full ZAP Fuzzer integration requires ZAP Docker to be running")

                # For now, show what would be fuzzed
                tokens = st.session_state.extracted_tokens

                if fuzzing_type == "IDOR (ID Parameters)":
                    ids = tokens.get('ids', [])
                    st.success(f"Would fuzz {len(ids)} unique IDs across IDOR-vulnerable endpoints")

                    if ids:
                        st.write("**Sample IDs:**")
                        st.code('\n'.join(str(x) for x in ids[:10]))

                elif fuzzing_type == "Username Enumeration":
                    usernames = tokens.get('usernames', [])
                    st.success(f"Would test {len(usernames)} usernames for enumeration")

                    if usernames:
                        st.write("**Sample usernames:**")
                        st.code('\n'.join(usernames[:10]))

            except Exception as e:
                st.error(f"Fuzzing failed: {e}")
                import traceback

                st.code(traceback.format_exc())

    # Export wordlists
    if st.session_state.get('extracted_tokens'):
        st.subheader("💾 Export Wordlists")

        if st.button("Export to ./wordlists/"):
            try:
                from modules.token_extractor import TokenExtractor

                # Create a dummy extractor just for export
                extractor = TokenExtractor(st.session_state.har_data)
                extractor.tokens = {
                    'ids': set(st.session_state.extracted_tokens.get('ids', [])),
                    'usernames': set(st.session_state.extracted_tokens.get('usernames', [])),
                    'emails': set(st.session_state.extracted_tokens.get('emails', [])),
                    'api_keys': set(st.session_state.extracted_tokens.get('api_keys', [])),
                    'session_tokens': set(st.session_state.extracted_tokens.get('session_tokens', [])),
                    'paths': set(st.session_state.extracted_tokens.get('paths', [])),
                    'params': set(st.session_state.extracted_tokens.get('params', [])),
                }

                extractor.export_for_zap_fuzzer('./wordlists')
                st.success("✓ Wordlists exported to ./wordlists/")

            except Exception as e:
                st.error(f"Export failed: {e}")


def render_passive_tab():
    st.header("🔵 Passive Security Analysis")

    st.markdown("""
    **Non-Invasive Security Checks**

    - 🛡️ Security Headers Analysis
    - 🔑 Token Entropy Analysis
    - 📄 PII/Sensitive Data Leakage
    - 📚 Stack Trace Detection
    """)

    if 'har_data' not in st.session_state:
        st.warning("⚠️ Please upload a HAR file first")
        return

    if st.button("🔍 Run Passive Analysis", type="primary"):
        with st.spinner("Analyzing HAR data..."):
            try:
                orchestrator = PassiveAnalysisOrchestrator(st.session_state.har_data)
                results = orchestrator.run_all_checks()

                st.session_state.passive_results = results

                summary = orchestrator.generate_summary()

                st.success(f"✓ Passive analysis complete!")

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Issues", summary['total_issues'])
                col2.metric("🔴 Critical", summary['by_severity']['CRITICAL'])
                col3.metric("🟠 High", summary['by_severity']['HIGH'])
                col4.metric("🟡 Medium", summary['by_severity']['MEDIUM'])

                st.rerun()

            except Exception as e:
                st.error(f"Passive analysis failed: {e}")
                import traceback

                st.code(traceback.format_exc())


def render_results_tab():
    st.header("📊 Scan Results")

    if st.session_state.scan_results:
        render_zap_results()

    if st.session_state.idor_results:
        st.divider()
        render_idor_results()

    if st.session_state.redteam_results:
        st.divider()
        render_redteam_results()

    if st.session_state.passive_results:
        st.divider()
        render_passive_results()

    if not any([st.session_state.scan_results, st.session_state.idor_results,
                st.session_state.redteam_results, st.session_state.passive_results]):
        st.info("No scan results available yet")


def render_zap_results():
    st.subheader("ZAP Scan Results")

    alerts = st.session_state.scan_results['alerts']

    high = [a for a in alerts if a.get('risk') == 'High']
    medium = [a for a in alerts if a.get('risk') == 'Medium']
    low = [a for a in alerts if a.get('risk') == 'Low']

    col1, col2, col3 = st.columns(3)
    col1.metric("🔴 High", len(high))
    col2.metric("🟠 Medium", len(medium))
    col3.metric("🟡 Low", len(low))

    risk_filter = st.selectbox("Filter by Risk", ["All", "High", "Medium", "Low"])

    filtered = alerts
    if risk_filter != "All":
        filtered = [a for a in alerts if a.get('risk') == risk_filter]

    for alert in filtered[:20]:
        with st.expander(f"[{alert.get('risk')}] {alert.get('alert')}"):
            st.write(f"**URL:** {alert.get('url')}")
            st.write(f"**CWE:** {alert.get('cweid')}")
            st.write(f"**Description:** {alert.get('description')}")
            st.code(f"Attack: {alert.get('attack', 'N/A')}", language=None)
            st.code(f"Evidence: {alert.get('evidence', 'N/A')}", language=None)
            st.write(f"**Solution:** {alert.get('solution')}")

    if st.button("🛑 Stop ZAP Container"):
        if st.session_state.docker_manager:
            st.session_state.docker_manager.stop_zap()
            st.success("ZAP container stopped")


def render_idor_results():
    st.subheader("🎯 IDOR Test Results")

    results = st.session_state.idor_results
    detector = st.session_state.idor_detector

    vulnerable = [r for r in results if r.status == IDORStatus.VULNERABLE]

    if vulnerable:
        st.error(f"🚨 Found {len(vulnerable)} IDOR vulnerabilities!")

        for result in vulnerable:
            with st.expander(f"IDOR: {result.url} (Confidence: {result.confidence:.0%})"):
                st.write(f"**Method:** {result.method}")
                st.write(f"**Status:** {result.status.value}")
                st.json(result.proof)

                col1, col2 = st.columns(2)

                with col1:
                    st.write("**Baseline Response (User A)**")
                    if result.baseline_response:
                        st.json({
                            'status': result.baseline_response.get('status_code'),
                            'length': result.baseline_response.get('content_length')
                        })

                with col2:
                    st.write("**Test Response (User B → Resource A)**")
                    if result.test_response:
                        st.json({
                            'status': result.test_response.get('status_code'),
                            'length': result.test_response.get('content_length')
                        })

                if result.diff_html:
                    st.write("**Visual Diff:**")
                    # noinspection PyUnresolvedReferences
                    st.components.v1.html(result.diff_html, height=600, scrolling=True)

                curl_cmd = detector.generate_curl_commands(
                    result,
                    detector.extract_auth_tokens(detector.session_b)
                )
                st.code(curl_cmd, language='bash')
    else:
        st.success("✅ No IDOR vulnerabilities detected")


def render_preprocessing_tab():
    st.header("🔧 HAR Preprocessing")

    st.markdown("""
    **Unified HAR Processing Pipeline**

    Extract everything in one pass:
    - 🎯 Endpoints & API patterns
    - 🔍 Querystring parameters
    - 📦 JSON payloads (request/response)
    - 📚 Dictionaries (keys, values, headers)
    - 📊 Statistics
    """)

    if 'har_data' not in st.session_state:
        st.warning("⚠️ Please upload a HAR file first")
        return

    from modules.har_preprocessor import HARPreprocessor

    st.subheader("⚙️ Filters")

    col1, col2 = st.columns(2)

    with col1:
        methods_filter = st.multiselect(
            "HTTP Methods",
            ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
            default=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
            help="Filter by HTTP methods (leave empty for all)"
        )

        content_types_filter = st.multiselect(
            "Content Types",
            ['application/json', 'application/xml', 'text/html', 'application/x-www-form-urlencoded'],
            default=['application/json'],
            help="Filter by content type"
        )

        exclude_static = st.checkbox("Exclude static resources (.js, .css, images)", value=True)

    with col2:
        domains_filter = st.text_area(
            "Include domains (one per line)",
            help="Only include these domains. Leave empty for all."
        )

        exclude_domains_filter = st.text_area(
            "Exclude domains (one per line)",
            value="google-analytics.com\ncdn.example.com",
            help="Exclude these domains"
        )

        status_codes_filter = st.text_input(
            "Status codes (comma-separated)",
            value="200,201,204",
            help="Filter by status codes. Leave empty for all."
        )

    if st.button("🔄 Preprocess HAR", type="primary"):
        with st.spinner("Processing HAR in single pass..."):
            try:
                preprocessor = HARPreprocessor(har_data=st.session_state.har_data)

                # Apply filters
                filters = {
                    'exclude_static': exclude_static
                }

                if methods_filter:
                    filters['methods'] = methods_filter

                if content_types_filter:
                    filters['content_types'] = content_types_filter

                if domains_filter.strip():
                    filters['domains'] = [d.strip() for d in domains_filter.split('\n') if d.strip()]

                if exclude_domains_filter.strip():
                    filters['exclude_domains'] = [d.strip() for d in exclude_domains_filter.split('\n') if d.strip()]

                if status_codes_filter.strip():
                    filters['status_codes'] = [int(s.strip()) for s in status_codes_filter.split(',') if s.strip().isdigit()]

                preprocessor.set_filters(**filters)

                # Process
                result = preprocessor.process()
                st.session_state.preprocessed_data = result

                st.success("✓ Preprocessing complete!")

                # Statistics
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Endpoints", result.statistics['total_endpoints'])
                col2.metric("Unique Patterns", result.statistics['unique_endpoint_patterns'])
                col3.metric("Payloads", result.statistics['total_payloads'])
                col4.metric("Unique Keys", result.statistics['total_unique_keys'])

                st.rerun()

            except Exception as e:
                st.error(f"Preprocessing failed: {e}")
                import traceback

                st.code(traceback.format_exc())

    # Display results
    if st.session_state.preprocessed_data:
        result = st.session_state.preprocessed_data

        st.divider()
        st.subheader("📊 Preprocessing Results")

        tabs_inner = st.tabs(["Statistics", "Endpoints", "Payloads", "Dictionaries", "Export"])

        with tabs_inner[0]:
            st.write("**Processing Statistics:**")
            st.json(result.statistics)

        with tabs_inner[1]:
            st.write(f"**{len(result.endpoints)} Endpoints Extracted**")

            if result.endpoints:
                endpoints_df = pd.DataFrame(result.endpoints[:100])
                st.dataframe(endpoints_df, use_container_width=True)

        with tabs_inner[2]:
            st.write(f"**{len(result.payloads)} Payload Patterns**")

            for endpoint, payloads in list(result.payloads.items())[:5]:
                with st.expander(f"{endpoint} ({len(payloads)} payloads)"):
                    for payload_data in payloads[:3]:
                        st.write(f"**Direction:** {payload_data['direction']}")
                        st.write(f"**Method:** {payload_data['method']}")
                        st.json(payload_data['payload'])

        with tabs_inner[3]:
            st.write("**Extracted Dictionaries:**")

            col1, col2, col3 = st.columns(3)
            col1.metric("Unique Keys", len(result.dictionaries['keys']))
            col2.metric("Parameters", len(result.dictionaries['parameters']))
            col3.metric("Headers", len(result.dictionaries['headers']))

            st.write("**Top Keys:**")
            for key, data in list(result.dictionaries['keys'].items())[:20]:
                st.write(f"- `{key}` ({data['type']}) - {len(data['endpoints'])} endpoints")

        with tabs_inner[4]:
            st.write("**Export Options:**")

            output_name = st.text_input("Output filename", value="preprocessed.json")

            col1, col2 = st.columns(2)

            with col1:
                if st.button("💾 Save Unified File"):
                    try:
                        from dataclasses import asdict
                        import json
                        import os

                        os.makedirs('output', exist_ok=True)
                        output_path = f"output/{output_name}"

                        with open(output_path, 'w') as f:
                            json.dump(asdict(result), f, indent=2, default=str)

                        st.success(f"✓ Saved to {output_path}")

                        # Offer download
                        with open(output_path, 'r') as f:
                            st.download_button(
                                label="⬇️ Download preprocessed.json",
                                data=f.read(),
                                file_name=output_name,
                                mime="application/json"
                            )
                    except Exception as e:
                        st.error(f"Save failed: {e}")

            with col2:
                if st.button("📂 Save Granular Extracts"):
                    try:
                        from dataclasses import asdict
                        import json
                        import os

                        base_path = 'output/extracts'
                        os.makedirs(base_path, exist_ok=True)

                        components = {
                            'metadata.json': result.metadata,
                            'endpoints.json': result.endpoints,
                            'querystrings.json': result.querystrings,
                            'payloads.json': result.payloads,
                            'dictionaries.json': result.dictionaries,
                            'statistics.json': result.statistics
                        }

                        for filename, data in components.items():
                            path = os.path.join(base_path, filename)
                            with open(path, 'w') as f:
                                json.dump(data, f, indent=2, default=str)

                        st.success(f"✓ Saved {len(components)} files to {base_path}/")

                    except Exception as e:
                        st.error(f"Save failed: {e}")


def render_acceptance_tab():
    st.header("✅ Test Acceptance Criteria")

    st.markdown("""
    Define security requirements that must be met for the build to pass.
    """)

    criteria = []

    st.subheader("Define Criteria")

    with st.form("acceptance_criteria"):
        criterion_type = st.selectbox(
            "Criterion Type",
            ["Max High Alerts", "Max Medium Alerts", "No IDOR Vulnerabilities", "Specific URL Must Be Clean"]
        )

        if criterion_type == "Max High Alerts":
            threshold = st.number_input("Maximum allowed High alerts", min_value=0, value=0)
            criteria.append({'type': 'max_high', 'threshold': threshold})

        elif criterion_type == "Max Medium Alerts":
            threshold = st.number_input("Maximum allowed Medium alerts", min_value=0, value=5)
            criteria.append({'type': 'max_medium', 'threshold': threshold})

        elif criterion_type == "No IDOR Vulnerabilities":
            criteria.append({'type': 'no_idor'})

        elif criterion_type == "Specific URL Must Be Clean":
            url_pattern = st.text_input("URL pattern")
            criteria.append({'type': 'clean_url', 'pattern': url_pattern})

        submitted = st.form_submit_button("Add Criterion")

        if submitted:
            st.session_state.setdefault('criteria', []).append(criteria[0])
            st.success("Criterion added!")

    if 'criteria' in st.session_state and st.session_state.criteria:
        st.subheader("Active Criteria")
        for i, crit in enumerate(st.session_state.criteria):
            st.write(f"{i + 1}. {crit}")

    if st.button("🎯 Evaluate Acceptance", type="primary"):
        if 'criteria' not in st.session_state or not st.session_state.criteria:
            st.warning("No criteria defined")
            return

        engine = AcceptanceEngine(st.session_state.criteria)

        results = {
            'zap_alerts': st.session_state.scan_results['alerts'] if st.session_state.scan_results else [],
            'idor_results': st.session_state.idor_results if st.session_state.idor_results else []
        }

        evaluation = engine.evaluate(results)

        if evaluation['passed']:
            st.success("✅ All acceptance criteria passed!")
        else:
            st.error("❌ Acceptance criteria failed!")

        for result in evaluation['results']:
            status_icon = "✅" if result['passed'] else "❌"
            st.write(f"{status_icon} {result['criterion']}: {result['message']}")


if __name__ == '__main__':
    main()
