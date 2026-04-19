#!/usr/bin/env python3
"""
Application Streamlit — interface interactive de HAR-ZAP.

Rôle de ce fichier :
- Orchestrer la navigation entre les 10 onglets du pentest (Upload → Advanced
  → Results → Acceptance).
- Conserver l'état de session (HAR chargé, scan en cours, FP marqués, langue,
  workflow) via `st.session_state`.
- Router tous les libellés utilisateur via `t()` pour qu'ils soient traduisibles
  en/fr sans toucher au code.

Principes de découplage :
- Aucune logique d'attaque ici — chaque onglet appelle un module dédié
  (`ZAPScanner`, `IDORDetector`, `run_advanced_attack`, …) et se contente de
  rendre les résultats. Cela permet aux mêmes attaques d'être exposées par la
  CLI et l'API REST sans dupliquer le code.
- Les helpers de rendu complexe sont dans `modules/ui_*.py`
  (ui_llm_plan, ui_advanced, ui_components) pour que l'app.py reste un
  orchestrateur lisible, pas un mur de Streamlit.
"""
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
from modules.workflow_state import (
    WorkflowState, restore_to_session_state, save_from_session_state
)
from modules.ui_components import inject_tooltips_js
from modules.i18n import t, SUPPORTED_LANGS, DEFAULT_LANG, load_locale
from modules.correlator import correlate_alerts, correlation_summary
from modules.har_diff import diff_hars
from modules.script_reports import collect_reports, summary as script_summary
from modules.reporter import Reporter
from modules.ui_llm_plan import render_plan as render_llm_plan, summarize as summarize_llm_plan
from modules.fp_store import get_store as get_fp_store, fingerprint as fp_fingerprint
from modules.scan_planner import plan_scan, format_plan
from modules.ui_advanced import (
    ADVANCED_ATTACKS,
    ATTACK_LABELS,
    run as run_advanced_attack,
    verdict_color,
)

st.set_page_config(
    page_title="DAST Security Platform",
    page_icon="🛡️",
    layout="wide"
)

if 'lang' not in st.session_state:
    st.session_state.lang = DEFAULT_LANG
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
if 'workflow' not in st.session_state:
    st.session_state.workflow = None


def render_language_selector():
    """Render a language selector at the top of the sidebar.

    Subtilité Streamlit : le selectbox retourne la valeur au rendu courant,
    mais `t()` (dans tous les autres onglets déjà rendus au-dessus) a déjà lu
    `st.session_state.lang` avec l'ancienne valeur. Il faut donc un `st.rerun()`
    quand l'utilisateur change de langue pour que toute la page soit
    re-rendue avec la nouvelle locale — sinon seul le selectbox change.
    """
    names = {lang: load_locale(lang).get("_meta", {}).get("name", lang) for lang in SUPPORTED_LANGS}
    current = st.session_state.get("lang", DEFAULT_LANG)
    labels = [f"{names[lang]}" for lang in SUPPORTED_LANGS]
    index = SUPPORTED_LANGS.index(current) if current in SUPPORTED_LANGS else 0
    choice = st.sidebar.selectbox(
        t("lang_selector.label"),
        options=list(range(len(SUPPORTED_LANGS))),
        format_func=lambda i: labels[i],
        index=index,
        key="lang_selector",
        help=t("lang_selector.help"),
    )
    picked = SUPPORTED_LANGS[choice]
    if picked != current:
        st.session_state.lang = picked
        st.rerun()


def render_workflow_sidebar():
    """Render workflow progress and resume controls in sidebar."""
    st.sidebar.markdown("---")
    st.sidebar.subheader(t("sidebar.session_header"))

    has_saved = WorkflowState.exists()
    workflow = st.session_state.workflow

    if workflow is None and has_saved:
        saved = WorkflowState.load()
        if saved:
            done, total = saved.get_progress()
            st.sidebar.info(t("sidebar.session_info", id=saved.session_id[:10], done=done, total=total))
            if st.sidebar.button(t("sidebar.resume_btn"), key="resume_btn"):
                st.session_state.workflow = saved
                restored = restore_to_session_state(saved, st.session_state)
                st.sidebar.success(t("sidebar.restored_toast", n=len(restored)))
                st.rerun()
            if st.sidebar.button(t("sidebar.new_btn"), key="new_btn"):
                WorkflowState.delete()
                st.session_state.workflow = WorkflowState.create_new()
                st.rerun()
    elif workflow is None:
        st.session_state.workflow = WorkflowState.create_new()
        workflow = st.session_state.workflow

    if workflow:
        st.sidebar.markdown(f"**{t('sidebar.progress_header')}**")
        icons = {"done": "✅", "in_progress": "🔄", "pending": "⬚", "skipped": "⏭️"}
        for i, step in enumerate(workflow.steps, 1):
            icon = icons.get(step.status, "⬚")
            st.sidebar.text(f"{icon} {i}. {step.name}")

        done, total = workflow.get_progress()
        st.sidebar.progress(done / total if total > 0 else 0)

        if st.sidebar.button(t("sidebar.reset_btn"), key="reset_btn"):
            # Reset complet : on vide le fichier `.harzap_session.json`, puis
            # on purge TOUT le session_state sauf `workflow` (qu'on recrée
            # juste après). Sans cette boucle, des résidus (scan_results,
            # har_data, FP non confirmés) resteraient en mémoire et fausseraient
            # le scan suivant. L'ordre est critique : purger PUIS recréer,
            # sinon on détruit immédiatement le nouveau workflow.
            WorkflowState.delete()
            for key in list(st.session_state.keys()):
                if key != "workflow":
                    del st.session_state[key]
            st.session_state.workflow = WorkflowState.create_new()
            st.rerun()


def main():
    st.title(f"🛡️ {t('app.title')}")
    st.markdown(f"**{t('app.subtitle')}**")

    render_language_selector()
    inject_tooltips_js()
    render_workflow_sidebar()

    tab_labels = [
        f"📤 {t('tabs.upload')}",
        f"🔧 {t('tabs.preprocess')}",
        f"🔍 {t('tabs.zap_scan')}",
        f"⚡ {t('tabs.fuzzer')}",
        f"🎯 {t('tabs.idor')}",
        f"🔴 {t('tabs.redteam')}",
        f"🔵 {t('tabs.passive')}",
        f"🧪 {t('tabs.advanced')}",
        f"📊 {t('tabs.results')}",
        f"✅ {t('tabs.acceptance')}",
    ]
    tabs = st.tabs(tab_labels)

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
        render_advanced_tab()

    with tabs[8]:
        render_results_tab()

    with tabs[9]:
        render_acceptance_tab()


def _render_llm_plan_section(har_data: dict) -> None:
    """Show the LLM attack plan (gated by button — LLM calls cost money/time).

    Le bouton est *obligatoire* — on ne lance jamais un appel LLM
    automatiquement au chargement du HAR : 1) ça coûte de l'argent à chaque
    upload, 2) l'utilisateur peut tester sans clé API et s'en sortir grâce
    au cache `LLMCache` qui réutilise le plan par empreinte HAR.
    """
    import os

    has_key = any(
        os.environ.get(k)
        for k in ("HARZAP_ANTHROPIC_API_KEY", "HARZAP_GEMINI_API_KEY", "HARZAP_LLM_API_KEY")
    )

    st.markdown("---")
    st.subheader("🤖 LLM attack plan")

    if not has_key:
        st.info(
            "Set `HARZAP_GEMINI_API_KEY` or `HARZAP_ANTHROPIC_API_KEY` in `.env` to "
            "let the LLM produce a prioritized attack plan from this HAR."
        )
        return

    if "llm_plan" in st.session_state and st.session_state.get("llm_plan_har_hash"):
        summary = summarize_llm_plan(st.session_state.llm_plan)
        st.caption(
            f"{summary['strategies']} strategies · "
            f"{summary['prioritized_endpoints']} endpoints · "
            f"{summary['regex_patterns']} regex patterns · "
            f"{summary['business_flows']} flows"
        )
        render_llm_plan(st.session_state.llm_plan, key_prefix="upload_llm_plan")
        if st.button("🔄 Re-run LLM analysis", key="llm_refresh_btn"):
            st.session_state.pop("llm_plan", None)
            st.session_state.pop("llm_plan_har_hash", None)
            st.rerun()
        return

    if st.button("🚀 Generate attack plan with LLM", key="llm_generate_btn", type="primary"):
        try:
            from modules.llm.analyzer import LLMSecurityAnalyzer
            with st.spinner("Calling LLM (one call, cached by HAR hash)..."):
                analyzer = LLMSecurityAnalyzer.from_config({})
                plan = analyzer.analyze(har_data)
                st.session_state.llm_plan = plan
                st.session_state.llm_plan_har_hash = plan.har_hash
            st.success("✓ Plan ready")
            st.rerun()
        except Exception as e:
            st.error(f"LLM analysis failed: {e}")


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

                # Auto-save workflow
                if st.session_state.workflow:
                    save_from_session_state(st.session_state.workflow, st.session_state, "upload")
                    save_from_session_state(st.session_state.workflow, st.session_state, "tokens")

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

                _render_llm_plan_section(har_data)

            except Exception as e:
                st.error(f"Error parsing HAR: {e}")

    with col2:
        st.subheader("Scan Configuration")

        scope_domains = st.text_area(
            "Scope Domains (one per line)",
            key="scope_domains",
            help="Only scan these domains. Leave empty for all."
        )

        exclude_domains = st.text_area(
            "Exclude Domains (one per line)",
            value="google-analytics.com\ngoogletagmanager.com\nfacebook.com",
            key="exclude_domains",
            help="Skip these domains"
        )

        scan_types = st.multiselect(
            "Attack Types",
            ["SQL Injection", "XSS", "Path Traversal", "Command Injection", "XXE", "SSRF"],
            default=["SQL Injection", "XSS"],
            key="scan_types_select",
            help="Select vulnerability categories to test"
        )

        full_assault = st.checkbox(
            "🔥 FULL ZAP ASSAULT (All Policies)",
            value=False,
            key="full_assault_check",
            help="Enable all ZAP scan policies (slower but thorough)"
        )

        if st.button("🔍 Analyze HAR", type="primary", key="analyze_har_btn", help="Parse HAR and extract endpoints"):
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

        dry_run = st.checkbox(
            "🔍 Preview only (dry-run)",
            value=False,
            key="zap_dry_run",
            help="Show what the scan would do (targets, policies, estimated volume/time) without sending any request.",
        )

        col1, col2 = st.columns([3, 1])
        with col1:
            launch_clicked = st.button("🚀 Launch ZAP Scan", type="primary")
        with col2:
            preview_clicked = st.button("📋 Preview plan", key="zap_plan_btn")

        if preview_clicked or (dry_run and launch_clicked):
            _show_scan_plan(parsed_data, st.session_state.config)
        elif launch_clicked:
            launch_zap_scan(parsed_data, selected_indices)
    else:
        st.info("No fuzzable URLs found in HAR file")


def _show_scan_plan(parsed_data, config):
    plan = plan_scan(parsed_data, config)
    data = plan.to_dict()
    summary = data['summary']
    st.subheader("🔍 Dry-run plan")
    cols = st.columns(4)
    cols[0].metric("Targets", summary['target_count'])
    cols[1].metric("Scripts", summary['script_count'])
    cols[2].metric("Est. requests", plan.estimated_requests)
    cols[3].metric("Est. duration", summary['estimated_duration_pretty'])

    if plan.warnings:
        for w in plan.warnings:
            st.warning(w)

    if plan.targets:
        st.markdown("**Targets and policies**")
        st.dataframe(plan.targets, use_container_width=True)

    with st.expander("JS scripts that would load"):
        if plan.scripts_to_load:
            for s in plan.scripts_to_load:
                st.code(s, language=None)
        else:
            st.caption("None")

    with st.expander("Python attacks enabled"):
        for a in plan.python_attacks:
            st.markdown(f"- `{a}`")


def launch_zap_scan(parsed_data, selected_indices):
    """Lance un scan ZAP complet en propageant la progression vers la UI.

    Séquence obligatoire : Docker → configure context → policies → site tree
    → scripts JS → scan actif avec callback → collecte des outputs. Changer
    l'ordre casse ZAP (ex. lancer un scan avant `populate_site_tree` donne
    un spider à vide).

    Les 3 `st.empty()` (progress_bar, current_target, live_metrics) sont
    volontairement créés avant la boucle pour que le callback puisse les
    mettre à jour sur place sans re-render complet. Streamlit n'a pas de
    vrai thread UI — c'est cette astuce qui donne l'illusion du temps réel.
    """
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

            status_text.text("Loading custom scripts...")
            script_stats = scanner.load_custom_scripts()
            if script_stats['active'] or script_stats['passive']:
                st.info(f"Loaded {script_stats['active']} active + {script_stats['passive']} passive scripts")

            status_text.text("Executing scans...")

            progress_bar = st.progress(0)
            current_target = st.empty()
            live_metrics = st.empty()

            def _progress_cb(event):
                # Progression agrégée : barre de 0 à 1 basée sur « cibles
                # terminées + fraction de la cible courante ». Sans ça, la
                # barre resterait à 0 puis sauterait à 100 quand ZAP rend
                # le contrôle — inutilisable sur un scan de 10 minutes.
                # Toutes les erreurs du callback sont absorbées : un scan
                # ne doit jamais crasher à cause d'un widget Streamlit.
                idx = event.get('target_index') or 0
                total = event.get('target_total') or 1
                target_pct = (idx - 1) / total if total else 0
                scan_pct = (event.get('scan_progress') or 0) / 100.0
                overall = min(1.0, target_pct + (scan_pct / total if total else 0))
                try:
                    progress_bar.progress(overall)
                    current_target.info(
                        f"[{idx}/{total}] {event.get('type', '?')} · "
                        f"{event.get('url', '')[:100]} · scan {event.get('scan_progress', 0)}%"
                    )
                    snap = scanner.get_scan_progress()
                    if snap:
                        live_metrics.caption(
                            f"Passive queue: {snap.get('passive_records_to_scan', '?')} · "
                            f"Alerts so far — "
                            f"🔴{snap['alerts_by_risk'].get('High', 0)} "
                            f"🟠{snap['alerts_by_risk'].get('Medium', 0)} "
                            f"🟡{snap['alerts_by_risk'].get('Low', 0)}"
                        )
                except Exception:
                    pass

            scan_results = scanner.execute_targeted_scans(progress_callback=_progress_cb)

            progress_bar.progress(100)
            current_target.empty()
            live_metrics.empty()
            status_text.text("Collecting results...")

            alerts = scanner.get_alerts()

            # Correlate alerts with HAR entries so the UI can link each
            # finding back to the original captured request.
            har_raw = st.session_state.get('har_data') or {}
            correlated = correlate_alerts(alerts, har_raw)
            enriched_alerts = [c.to_dict() for c in correlated]

            # Attach a curl_reproduce field so the report and UI always expose
            # a one-liner to replay the vulnerable request.
            reporter = Reporter(output_dir='./output')
            enriched_alerts = reporter.enrich_findings(enriched_alerts)

            # Pull the JS scripts' outputs from ZAP — otherwise they run blind.
            try:
                reports = collect_reports(scanner.zap)
            except Exception:
                reports = []

            st.session_state.scan_results = {
                'alerts': enriched_alerts,
                'scan_results': scan_results,
                'scanner': scanner,
                'correlation_summary': correlation_summary(correlated),
                'script_reports': [r.to_dict() for r in reports],
                'script_reports_summary': script_summary(reports),
            }

            # Auto-save workflow
            if st.session_state.workflow:
                save_from_session_state(st.session_state.workflow, st.session_state, "zap_scan")

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

    if har_a and har_b:
        try:
            session_a_preview = json.load(har_a)
            har_a.seek(0)
            session_b_preview = json.load(har_b)
            har_b.seek(0)
            with st.expander("🔍 HAR diff — endpoints only in one session (likely IDOR candidates)"):
                diff = diff_hars(session_a_preview, session_b_preview).to_dict()
                cols = st.columns(3)
                cols[0].metric("Only in A", diff['summary']['only_a'])
                cols[1].metric("Only in B", diff['summary']['only_b'])
                cols[2].metric("IDOR candidates", diff['summary']['idor_candidates'])
                if diff['only_in_b']:
                    st.markdown("**Endpoints only in B (privileged?):**")
                    st.write(diff['only_in_b'][:20])
                if diff['idor_candidates']:
                    st.markdown("**Best IDOR targets (2xx + id-like path segment):**")
                    st.dataframe(diff['idor_candidates'][:20], use_container_width=True)
        except Exception as e:
            st.warning(f"HAR diff preview unavailable: {e}")

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

                # Auto-save workflow
                if st.session_state.workflow:
                    save_from_session_state(st.session_state.workflow, st.session_state, "idor")

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

                # Auto-save workflow
                if st.session_state.workflow:
                    save_from_session_state(st.session_state.workflow, st.session_state, "redteam")

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

                # Auto-save workflow
                if st.session_state.workflow:
                    save_from_session_state(st.session_state.workflow, st.session_state, "passive")

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

    results = st.session_state.scan_results
    alerts = results['alerts']

    high = [a for a in alerts if a.get('risk') == 'High']
    medium = [a for a in alerts if a.get('risk') == 'Medium']
    low = [a for a in alerts if a.get('risk') == 'Low']

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🔴 High", len(high))
    col2.metric("🟠 Medium", len(medium))
    col3.metric("🟡 Low", len(low))

    corr_summary = results.get('correlation_summary') or {}
    matched = sum(v for k, v in corr_summary.items() if k != 'none')
    col4.metric("🔗 Correlated to HAR", f"{matched}/{len(alerts)}")

    with st.expander("HAR correlation breakdown"):
        st.write(corr_summary)
        st.caption("exact > normalized > path > domain > none — higher confidence means the alert cleanly maps to a HAR entry.")

    script_reports = results.get('script_reports') or []
    if script_reports:
        with st.expander(f"📜 ZAP JS script reports ({len(script_reports)})"):
            scr_sum = results.get('script_reports_summary') or {}
            st.caption(
                f"{scr_sum.get('enabled', 0)}/{scr_sum.get('total', 0)} enabled · "
                f"{scr_sum.get('with_findings', 0)} produced findings · "
                f"{scr_sum.get('errored', 0)} errored"
            )
            for rep in script_reports:
                head = f"[{rep['type']}] {rep['name']}"
                if rep['has_error']:
                    head = f"❌ {head}"
                elif rep['findings']:
                    head = f"🎯 {head} ({rep['finding_count']} findings)"
                elif rep['enabled']:
                    head = f"🟢 {head} (no finding)"
                else:
                    head = f"⚪ {head} (disabled)"
                with st.container():
                    st.markdown(f"**{head}**")
                    if rep['error_message']:
                        st.error(rep['error_message'])
                    if rep['findings']:
                        st.json(rep['findings'])
                    elif rep['raw_output']:
                        st.code(rep['raw_output'][:500], language=None)

    fp_store = get_fp_store()
    annotated = fp_store.annotate_alerts(alerts)

    col_a, col_b = st.columns([3, 1])
    with col_a:
        risk_filter = st.selectbox("Filter by Risk", ["All", "High", "Medium", "Low"])
    with col_b:
        show_fp = st.checkbox("Show FPs", value=False, key="show_fp_toggle",
                              help="Include alerts marked as false positives")

    filtered = annotated
    if risk_filter != "All":
        filtered = [a for a in filtered if a.get('risk') == risk_filter]
    if not show_fp:
        filtered = [a for a in filtered if not a.get('is_false_positive')]

    fp_count = sum(1 for a in annotated if a.get('is_false_positive'))
    if fp_count:
        st.caption(f"🚫 {fp_count} alert(s) marked as false-positive and hidden. Toggle to see them.")

    for alert in filtered[:20]:
        is_fp = alert.get('is_false_positive', False)
        tag = "🚫 FP " if is_fp else ""
        with st.expander(f"{tag}[{alert.get('risk')}] {alert.get('alert')}"):
            correlation = alert.get('correlation') or {}
            st.write(f"**URL:** {alert.get('url')}")
            if correlation.get('har_entry_index') is not None:
                st.write(
                    f"**HAR entry:** #{correlation['har_entry_index']} · "
                    f"confidence `{correlation['confidence']}` · "
                    f"status `{correlation.get('response_status')}`"
                )
            st.write(f"**CWE:** {alert.get('cweid')}")
            st.write(f"**Description:** {alert.get('description')}")
            st.code(f"Attack: {alert.get('attack', 'N/A')}", language=None)
            st.code(f"Evidence: {alert.get('evidence', 'N/A')}", language=None)
            st.write(f"**Solution:** {alert.get('solution')}")
            curl = alert.get('curl_reproduce')
            if curl:
                st.markdown("**Reproduce:**")
                st.code(curl, language="bash")

            # La clé du bouton inclut le fingerprint pour que Streamlit les
            # distingue dans la boucle (même libellé pour 20 alertes = collision
            # de clés → erreur de rendu). Le `st.rerun()` est nécessaire pour
            # que le filtre `is_false_positive` soit recalculé à la prochaine
            # passe et que l'alerte bascule immédiatement de côté.
            fp_btn_key = f"fp_btn_{alert.get('fingerprint')}"
            if is_fp:
                if st.button("♻️ Un-mark false positive", key=fp_btn_key):
                    fp_store.unmark(alert.get('fingerprint'))
                    st.rerun()
            else:
                reason_key = f"fp_reason_{alert.get('fingerprint')}"
                reason = st.text_input("FP reason (optional)", key=reason_key,
                                       placeholder="e.g. protected by WAF, intentional behaviour")
                if st.button("🚫 Mark as false positive", key=fp_btn_key):
                    fp_store.mark(alert, reason=reason)
                    st.rerun()

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

                # Auto-save workflow
                if st.session_state.workflow:
                    save_from_session_state(st.session_state.workflow, st.session_state, "preprocess")

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


def render_advanced_tab():
    """Expose the protocol-specialised attack modules (JWT/CORS/cache/smuggling/timing/GraphQL/WS).

    Each attack takes only the HAR we already have — no extra form fields are
    required beyond the explicit confirmation click.
    """
    st.header(f"🧪 {t('tabs.advanced')}")
    st.caption(t("advanced.intro"))

    har_data = st.session_state.get("har_data")
    if not har_data:
        st.warning(t("common.warning_upload_first"))
        return

    attack_key = st.selectbox(
        t("advanced.picker_label"),
        options=ADVANCED_ATTACKS,
        format_func=lambda k: ATTACK_LABELS.get(k, k),
        key="advanced_attack_pick",
        help=t("advanced.picker_help"),
    )

    zap_client = None
    scan_session = st.session_state.get("scan_results")
    if scan_session and scan_session.get("scanner") is not None:
        zap_client = scan_session["scanner"].zap

    st.caption(
        t("advanced.zap_on") if zap_client is not None else t("advanced.zap_off")
    )

    if st.button(
        f"🚀 {t('advanced.run_btn')}",
        key=f"advanced_run_{attack_key}",
        type="primary",
    ):
        result = _run_advanced_attack_with_spinner(attack_key, har_data, zap_client)
        if result is not None:
            st.session_state.setdefault("advanced_results", {})[attack_key] = result
            st.rerun()

    cached = st.session_state.get("advanced_results", {}).get(attack_key)
    if cached:
        _render_advanced_result(cached)


def _run_advanced_attack_with_spinner(attack_key: str, har_data: dict, zap_client) -> dict | None:
    config = st.session_state.get("config") or {}
    try:
        with st.spinner(t("advanced.running", attack=ATTACK_LABELS.get(attack_key, attack_key))):
            return run_advanced_attack(attack_key, har_data, config=config, zap_client=zap_client)
    except Exception as e:
        st.error(f"{t('advanced.failed')}: {e}")
        import traceback
        st.code(traceback.format_exc(), language=None)
        return None


def _render_advanced_result(result: dict) -> None:
    verdict = result.get("verdict", "NO_TARGETS")
    total = len(result.get("findings") or [])
    vuln = sum(1 for r in (result.get("findings") or []) if r.get("vulnerable"))

    cols = st.columns(3)
    cols[0].metric(t("advanced.m_verdict"), verdict, delta_color=verdict_color(verdict))
    cols[1].metric(t("advanced.m_total"), total)
    cols[2].metric(t("advanced.m_vuln"), vuln)

    st.caption(result.get("summary", ""))

    endpoints = result.get("endpoints")
    if endpoints:
        with st.expander(t("advanced.endpoints_expander", n=len(endpoints))):
            st.dataframe(endpoints, use_container_width=True)

    findings = result.get("findings") or []
    if not findings:
        st.info(t("advanced.no_findings"))
        return

    st.markdown(f"### {t('advanced.findings_header')}")
    for i, finding in enumerate(findings[:50]):
        title = (
            finding.get("alert")
            or finding.get("attack_type")
            or finding.get("vulnerability_type")
            or finding.get("type")
            or f"Finding #{i + 1}"
        )
        icon = "🚨" if finding.get("vulnerable") else "✅"
        severity = finding.get("severity") or finding.get("risk") or ""
        with st.expander(f"{icon} {title} · {severity}"):
            st.json(finding)


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
