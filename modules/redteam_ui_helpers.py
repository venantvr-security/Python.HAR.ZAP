"""UI helper functions for displaying Red Team and Passive scan results"""
import streamlit as st


def show_attack_docs(attack_type):
    """Display attack documentation in expander"""
    doc_mapping = {
        "Unauthenticated Replay": "docs/redteam/UNAUTHENTICATED_REPLAY.md",
        "Mass Assignment": "docs/redteam/MASS_ASSIGNMENT.md",
        "Hidden Parameters": "docs/redteam/HIDDEN_PARAMETERS.md",
        "Race Conditions": "docs/redteam/RACE_CONDITIONS.md"
    }

    doc_path = doc_mapping.get(attack_type)
    if doc_path:
        try:
            with open(doc_path, 'r', encoding='utf-8') as f:
                content = f.read()
                return content
        except FileNotFoundError:
            return f"Documentation not found: {doc_path}"
    return "No documentation available"


def render_redteam_results():
    """Render Red Team attack results"""
    st.subheader("🔴 Red Team Attack Results")

    results = st.session_state.redteam_results

    tabs = st.tabs([
        "🔓 Unauthenticated Replay",
        "🎭 Mass Assignment",
        "🔍 Hidden Parameters",
        "📋 All Findings"
    ])

    with tabs[0]:
        col1, col2 = st.columns([0.95, 0.05])
        with col1:
            st.markdown("### Unauthenticated Replay Results")
        with col2:
            if st.button("❓", key="help_unauth_results"):
                with st.expander("📚 About this attack", expanded=True):
                    st.markdown(show_attack_docs("Unauthenticated Replay"))

        unauth_results = results.get('unauth_replay', [])
        vulnerable = [r for r in unauth_results if r.vulnerable]

        if vulnerable:
            st.error(f"🚨 Found {len(vulnerable)} endpoints accessible without authentication!")

            for result in vulnerable:
                with st.expander(f"CRITICAL: {result.url}"):
                    st.write(f"**Attack Type:** {result.attack_type.value}")
                    st.write(f"**Confidence:** {result.confidence:.0%}")
                    st.write(f"**Description:** {result.description}")

                    st.json(result.evidence)

                    st.write(f"**Remediation:** {result.remediation}")
        else:
            st.success("✅ All authenticated endpoints require proper authentication")

    with tabs[1]:
        col1, col2 = st.columns([0.95, 0.05])
        with col1:
            st.markdown("### Mass Assignment Results")
        with col2:
            if st.button("❓", key="help_mass_results"):
                with st.expander("📚 About this attack", expanded=True):
                    st.markdown(show_attack_docs("Mass Assignment"))

        mass_assignment = results.get('mass_assignment', [])
        vulnerable = [r for r in mass_assignment if r.vulnerable]

        if vulnerable:
            st.warning(f"⚠️  Found {len(vulnerable)} potential mass assignment vulnerabilities!")

            for result in vulnerable:
                with st.expander(f"{result.url}"):
                    st.write(f"**Confidence:** {result.confidence:.0%}")
                    st.write(f"**Description:** {result.description}")
                    st.json(result.evidence)
                    st.write(f"**Remediation:** {result.remediation}")
        else:
            st.success("✅ No mass assignment vulnerabilities detected")

    with tabs[2]:
        col1, col2 = st.columns([0.95, 0.05])
        with col1:
            st.markdown("### Hidden Parameters Results")
        with col2:
            if st.button("❓", key="help_hidden_results"):
                with st.expander("📚 About this attack", expanded=True):
                    st.markdown(show_attack_docs("Hidden Parameters"))

        hidden_params = results.get('hidden_params', [])

        if hidden_params:
            st.warning(f"⚠️  Found {len(hidden_params)} hidden parameters!")

            for result in hidden_params:
                with st.expander(f"{result.url}"):
                    st.write(f"**Description:** {result.description}")
                    st.json(result.evidence)
        else:
            st.success("✅ No hidden parameters discovered")

    with tabs[3]:
        all_findings = []
        for attack_results in results.values():
            all_findings.extend([r for r in attack_results if r.vulnerable])

        if all_findings:
            st.write(f"**Total Vulnerabilities:** {len(all_findings)}")

            for i, result in enumerate(all_findings, 1):
                st.markdown(f"### {i}. {result.attack_type.value}")
                st.write(f"**URL:** {result.url}")
                st.write(f"**Confidence:** {result.confidence:.0%}")
                st.write(f"**Description:** {result.description}")
                st.write(f"**Remediation:** {result.remediation}")
                # Bouton « rejouer manuellement » — le curl reproductible
                # construit à partir de l'évidence permet au pentesteur de
                # relancer le test en dehors de l'outil (Burp, Insomnia, CLI)
                # pour confirmer et documenter la vulnérabilité.
                curl = _build_replay_curl(result)
                if curl:
                    st.markdown("**Reproduce manually:**")
                    st.code(curl, language="bash")
                st.divider()
        else:
            st.success("✅ No vulnerabilities found")


def _build_replay_curl(result) -> str:
    """Build a best-effort curl to replay a red-team finding.

    Les modules red-team ne stockent pas systématiquement un payload curl
    pré-construit ; on le reconstruit depuis l'évidence quand on peut.
    """
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    method = (evidence.get("method") or "GET").upper()
    url = result.url
    parts = ["curl"]
    if method != "GET":
        parts.append(f"-X {method}")
    for name, value in (evidence.get("headers") or {}).items():
        safe = str(value).replace("'", "'\\''")
        parts.append(f"-H '{name}: {safe}'")
    body = evidence.get("body") or evidence.get("payload")
    if method in {"POST", "PUT", "PATCH"} and body:
        safe = str(body).replace("'", "'\\''")
        parts.append(f"--data-raw '{safe}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


def render_passive_results():
    """Render Passive analysis results"""
    st.subheader("🔵 Passive Security Analysis Results")

    results = st.session_state.passive_results

    tabs = st.tabs([
        "Security Headers",
        "Data Leakage",
        "Token Strength",
        "All Issues"
    ])

    with tabs[0]:
        header_issues = results.get('headers', [])

        severity_filter = st.selectbox("Filter by Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

        filtered = header_issues
        if severity_filter != "All":
            filtered = [i for i in header_issues if i.severity == severity_filter]

        st.write(f"**Total Issues:** {len(filtered)}")

        for issue in filtered:
            severity_color = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵',
                'INFO': '⚪'
            }.get(issue.severity, '⚪')

            with st.expander(f"{severity_color} [{issue.severity}] {issue.title}"):
                st.write(f"**Category:** {issue.category}")
                st.write(f"**Description:** {issue.description}")
                st.json(issue.evidence)
                st.info(f"**Remediation:** {issue.remediation}")

    with tabs[1]:
        leak_issues = results.get('data_leaks', [])

        if leak_issues:
            st.error(f"🚨 Found {len(leak_issues)} data leakage issues!")

            for issue in leak_issues:
                severity_color = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡'
                }.get(issue.severity, '⚪')

                with st.expander(f"{severity_color} {issue.title}"):
                    st.write(f"**Description:** {issue.description}")
                    st.json(issue.evidence)
                    st.warning(f"**Remediation:** {issue.remediation}")
        else:
            st.success("✅ No sensitive data leakage detected")

    with tabs[2]:
        token_issues = results.get('token_strength', [])

        if token_issues:
            st.warning(f"⚠️  Found {len(token_issues)} weak tokens!")

            for issue in token_issues:
                with st.expander(f"{issue.title}"):
                    st.write(f"**Severity:** {issue.severity}")
                    st.write(f"**Description:** {issue.description}")

                    evidence = issue.evidence
                    col1, col2 = st.columns(2)
                    col1.metric("Token Length", evidence.get('length'))
                    col2.metric("Entropy", f"{evidence.get('entropy', 0):.2f} bits")

                    st.info(f"**Remediation:** {issue.remediation}")
        else:
            st.success("✅ All tokens have sufficient entropy")

    with tabs[3]:
        all_issues = []
        for issue_type, issues in results.items():
            all_issues.extend(issues)

        critical_high = [i for i in all_issues if i.severity in ['CRITICAL', 'HIGH']]

        st.write(f"**Total Issues:** {len(all_issues)}")
        st.write(f"**Critical/High:** {len(critical_high)}")

        for issue in sorted(all_issues, key=lambda x: (x.severity, x.title)):
            severity_color = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵'
            }.get(issue.severity, '⚪')

            st.markdown(f"{severity_color} **[{issue.severity}] {issue.title}**")
            st.write(f"   {issue.description}")
            st.divider()
