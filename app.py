#!/usr/bin/env python3
import json
import tempfile

import pandas as pd
import streamlit as st

from modules.acceptance_engine import AcceptanceEngine
from modules.docker_manager import DockerZAPManager
from modules.har_analyzer import HARAnalyzer
from modules.idor_detector import IDORDetector, IDORStatus
from modules.zap_scanner import ZAPScanner
from modules.redteam_attacks import RedTeamOrchestrator
from modules.passive_analysis import PassiveAnalysisOrchestrator
from modules.redteam_ui_helpers import render_redteam_results, render_passive_results

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


def main():
    st.title("🛡️ DAST Security Platform")
    st.markdown("**Automated Dynamic Application Security Testing with OWASP ZAP**")

    tabs = st.tabs(["📤 Upload & Configure", "🔍 ZAP Scan", "🎯 IDOR Testing", "🔴 Red Team", "🔵 Passive Scan", "📊 Results", "✅ Acceptance"])

    with tabs[0]:
        render_upload_tab()

    with tabs[1]:
        render_zap_scan_tab()

    with tabs[2]:
        render_idor_tab()

    with tabs[3]:
        render_redteam_tab()

    with tabs[4]:
        render_passive_tab()

    with tabs[5]:
        render_results_tab()

    with tabs[6]:
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

    attack_types = st.multiselect(
        "Select Attack Types",
        ["Unauthenticated Replay", "Mass Assignment", "Hidden Parameters", "Race Conditions"],
        default=["Unauthenticated Replay", "Mass Assignment"]
    )

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
                    st.components.v1.html(result.diff_html, height=600, scrolling=True)

                curl_cmd = detector.generate_curl_commands(
                    result,
                    detector.extract_auth_tokens(detector.session_b)
                )
                st.code(curl_cmd, language='bash')
    else:
        st.success("✅ No IDOR vulnerabilities detected")


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
