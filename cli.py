#!/usr/bin/env python3
"""
HAR-ZAP: Professional DAST Security Platform
CI/CD-friendly CLI with fail-fast mode, incremental scanning, and multi-protocol support.
"""
import argparse
import json
import sys
import time
from pathlib import Path

from modules.config_loader import load_config, get_zap_config, get_scan_config
from modules.acceptance_engine import AcceptanceEngine
from modules.docker_manager import DockerZAPManager
from modules.har_analyzer import HARAnalyzer
from modules.idor_detector import IDORDetector
from modules.reporter import Reporter
from modules.zap_scanner import ZAPScanner
from modules.incremental_scanner import IncrementalScanner
from modules.graphql_scanner import GraphQLScanner
from modules.websocket_scanner import WebSocketScanner
from modules.owasp_mapper import OWASPMapper
from modules.notifications import NotificationManager, NotificationType
from modules.utils import get_logger

logger = get_logger("cli")


def main():
    parser = argparse.ArgumentParser(
        description='HAR-ZAP: Professional DAST Security Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan with OWASP compliance
  %(prog)s scan traffic.har --owasp --fail-fast --max-high 0

  # Incremental scan (skip already-scanned requests)
  %(prog)s scan traffic.har --incremental

  # GraphQL security testing
  %(prog)s graphql api.har --introspection --batch-test

  # WebSocket security testing
  %(prog)s websocket traffic.har --cswsh

  # IDOR detection with notifications
  %(prog)s idor --session-a user1.har --session-b user2.har --webhook slack

  # Export multiple formats
  %(prog)s scan traffic.har --format json,sarif,html --output ./reports

  # Use existing ZAP instance
  %(prog)s scan traffic.har --no-docker --zap-url http://localhost:8080
        """
    )

    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version='HAR-ZAP 2.0.0')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # === SCAN COMMAND ===
    scan_parser = subparsers.add_parser('scan', help='Run ZAP security scan')
    scan_parser.add_argument('har_file', help='HAR file to scan')
    scan_parser.add_argument('-c', '--config', help='Config YAML file')
    scan_parser.add_argument('-o', '--output', default='./output', help='Output directory')
    scan_parser.add_argument('--format', default='json',
                             help='Output formats (comma-separated): json,html,sarif,junit')
    scan_parser.add_argument('--max-high', type=int, help='Max high severity alerts')
    scan_parser.add_argument('--max-medium', type=int, help='Max medium severity alerts')
    scan_parser.add_argument('--fail-fast', action='store_true',
                             help='Exit code 1 if criteria fail')
    scan_parser.add_argument('--incremental', action='store_true',
                             help='Skip already-scanned requests (uses local cache)')
    scan_parser.add_argument('--owasp', action='store_true',
                             help='Include OWASP Top 10 compliance report')
    scan_parser.add_argument('--graphql', action='store_true',
                             help='Enable GraphQL endpoint scanning')
    scan_parser.add_argument('--websocket', action='store_true',
                             help='Enable WebSocket endpoint scanning')
    scan_parser.add_argument('--no-docker', action='store_true',
                             help='Use existing ZAP instance')
    scan_parser.add_argument('--zap-url', default='http://localhost:8080',
                             help='ZAP URL if using existing instance')
    scan_parser.add_argument('--api-key', help='ZAP API key')
    scan_parser.add_argument('--webhook', help='Webhook type: slack, teams, discord')
    scan_parser.add_argument('--rate-limit', type=float, help='Requests per second')

    # === GRAPHQL COMMAND ===
    gql_parser = subparsers.add_parser('graphql', help='GraphQL security testing')
    gql_parser.add_argument('har_file', help='HAR file containing GraphQL requests')
    gql_parser.add_argument('-o', '--output', default='./output', help='Output directory')
    gql_parser.add_argument('--introspection', action='store_true',
                            help='Test introspection endpoints')
    gql_parser.add_argument('--batch-test', action='store_true',
                            help='Test batching/aliasing DoS')
    gql_parser.add_argument('--depth-test', action='store_true',
                            help='Test query depth limits')
    gql_parser.add_argument('--fuzz', action='store_true',
                            help='Fuzz GraphQL arguments')

    # === WEBSOCKET COMMAND ===
    ws_parser = subparsers.add_parser('websocket', help='WebSocket security testing')
    ws_parser.add_argument('har_file', help='HAR file containing WebSocket connections')
    ws_parser.add_argument('-o', '--output', default='./output', help='Output directory')
    ws_parser.add_argument('--cswsh', action='store_true',
                           help='Test Cross-Site WebSocket Hijacking')
    ws_parser.add_argument('--fuzz', action='store_true',
                           help='Fuzz WebSocket messages')

    # === IDOR COMMAND ===
    idor_parser = subparsers.add_parser('idor', help='IDOR detection')
    idor_parser.add_argument('--session-a', required=True, help='HAR file for User A')
    idor_parser.add_argument('--session-b', required=True, help='HAR file for User B')
    idor_parser.add_argument('-o', '--output', default='./output', help='Output directory')
    idor_parser.add_argument('--workers', type=int, default=5, help='Parallel workers')
    idor_parser.add_argument('--fail-on-idor', action='store_true',
                             help='Exit code 1 if IDOR found')
    idor_parser.add_argument('--webhook', help='Webhook type: slack, teams, discord')

    # === CACHE COMMAND ===
    cache_parser = subparsers.add_parser('cache', help='Manage incremental scan cache')
    cache_parser.add_argument('action', choices=['stats', 'clear', 'export'],
                              help='Cache action')
    cache_parser.add_argument('--older-than', type=int,
                              help='Clear entries older than N days')
    cache_parser.add_argument('-o', '--output', help='Export output file')

    # === DIAGNOSE COMMAND (FULL SUITE) ===
    diag_parser = subparsers.add_parser('diagnose', help='Run full diagnostic attack suite')
    diag_parser.add_argument('har_file', help='HAR file to analyze')
    diag_parser.add_argument('--target', required=True, help='Target URL (e.g., https://www.example.com)')
    diag_parser.add_argument('-o', '--output', default='./output', help='Output directory')
    diag_parser.add_argument('--format', default='json,html',
                             help='Output formats: json,html,sarif,junit')
    diag_parser.add_argument('--max-high', type=int, help='Max high severity (fail-fast)')
    diag_parser.add_argument('--fail-fast', action='store_true', help='Exit 1 on criteria fail')
    diag_parser.add_argument('--skip-zap', action='store_true', help='Skip ZAP active scan')
    diag_parser.add_argument('--skip-redteam', action='store_true', help='Skip red team attacks')
    diag_parser.add_argument('--no-docker', action='store_true', help='Use existing ZAP')
    diag_parser.add_argument('--zap-url', default='http://localhost:8080', help='ZAP URL')
    diag_parser.add_argument('--api-key', help='ZAP API key')

    # === ADVANCED ATTACKS COMMAND ===
    adv_parser = subparsers.add_parser('advanced', help='Advanced attack testing')
    adv_parser.add_argument('har_file', help='HAR file to analyze')
    adv_parser.add_argument('-o', '--output', default='./output', help='Output directory')
    adv_parser.add_argument('--smuggling', action='store_true',
                            help='Test HTTP request smuggling (CL.TE, TE.CL)')
    adv_parser.add_argument('--cache-poison', action='store_true',
                            help='Test web cache poisoning')
    adv_parser.add_argument('--jwt', action='store_true',
                            help='Test JWT vulnerabilities (none alg, weak secrets)')
    adv_parser.add_argument('--cors', action='store_true',
                            help='Test CORS misconfigurations')
    adv_parser.add_argument('--timing', action='store_true',
                            help='Test blind injection via timing analysis (slow)')
    adv_parser.add_argument('--all', action='store_true',
                            help='Run all advanced tests (except timing)')
    adv_parser.add_argument('--no-docker', action='store_true',
                            help='Use existing ZAP instance')
    adv_parser.add_argument('--zap-url', default='http://localhost:8080',
                            help='ZAP URL if using existing instance')
    adv_parser.add_argument('--api-key', help='ZAP API key')
    adv_parser.add_argument('--webhook', help='Webhook type: slack, teams, discord')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'scan':
        return run_scan(args)
    elif args.command == 'graphql':
        return run_graphql(args)
    elif args.command == 'websocket':
        return run_websocket(args)
    elif args.command == 'idor':
        return run_idor(args)
    elif args.command == 'cache':
        return run_cache(args)
    elif args.command == 'advanced':
        return run_advanced(args)
    elif args.command == 'diagnose':
        return run_diagnose(args)

    return 0


def run_scan(args):
    """Execute ZAP scan with acceptance criteria."""
    start_time = time.time()

    if not Path(args.har_file).exists():
        logger.error("har_not_found", path=args.har_file)
        print(f"Error: HAR file not found: {args.har_file}", file=sys.stderr)
        return 1

    Path(args.output).mkdir(parents=True, exist_ok=True)
    config = load_config(args.config)

    # Apply CLI overrides
    if args.rate_limit:
        config['rate_limit'] = args.rate_limit

    # Setup notifications
    notifier = None
    if args.webhook:
        config['webhooks'] = [{'type': args.webhook, 'url': '', 'events': ['all']}]
        notifier = NotificationManager(config)

    # Setup reporter
    report_config = {
        'include_owasp': args.owasp,
        'include_curl': True,
        'include_timeline': True,
        'formats': args.format.split(',')
    }
    reporter = Reporter(args.output, report_config)
    reporter.add_timeline_event('scan_start', f'Scanning {args.har_file}')

    # Incremental scanning
    incremental = None
    if args.incremental:
        incremental = IncrementalScanner()
        incremental.start_session(args.har_file)

    print("[1/5] Analyzing HAR file...")
    analyzer = HARAnalyzer(args.har_file, config)
    har_data = analyzer.analyze()
    print(analyzer.get_summary())
    reporter.add_timeline_event('har_analyzed', f'{len(har_data["urls"])} URLs found')

    if len(har_data['urls']) == 0:
        print("Error: No URLs found in HAR", file=sys.stderr)
        return 1

    # Delta analysis for incremental
    if incremental:
        delta = incremental.get_delta_requests({'entries': har_data.get('entries', [])})
        print(f"Incremental: {delta['stats']['new']} new, {delta['stats']['cached']} cached")
        reporter.add_timeline_event('incremental_analysis', str(delta['stats']))

    docker_manager = None
    zap_config = None

    try:
        if not args.no_docker:
            print("[2/5] Starting ZAP container...")
            docker_manager = DockerZAPManager(config)
            zap_config = docker_manager.start_zap()
            reporter.add_timeline_event('zap_started', 'Docker container ready')
        else:
            zap_config = {
                'zap_url': args.zap_url,
                'api_key': args.api_key or '',
                'port': 8080
            }

        print("[3/5] Executing scans...")
        scanner = ZAPScanner(zap_config, har_data, get_scan_config(config))
        scanner.configure_context()
        scanner.configure_scan_policies()
        scanner.populate_site_tree()
        script_stats = scanner.load_custom_scripts()
        print(f"[Scripts] {script_stats['active']} active + {script_stats['passive']} passive loaded")
        scan_results = scanner.execute_targeted_scans()
        reporter.add_timeline_event('scan_complete', f'{len(scan_results)} targets scanned')

        # GraphQL scanning
        if args.graphql:
            print("[3b/5] Scanning GraphQL endpoints...")
            gql_scanner = GraphQLScanner(har_data, config.get('graphql', {}))
            gql_results = gql_scanner.scan_all()
            reporter.add_timeline_event('graphql_scan', str(gql_results['summary']))
            print(f"GraphQL: {gql_results['summary']}")

        # WebSocket scanning
        if args.websocket:
            print("[3c/5] Scanning WebSocket endpoints...")
            ws_scanner = WebSocketScanner(har_data, config.get('websocket', {}))
            ws_results = ws_scanner.scan_all_sync()
            reporter.add_timeline_event('websocket_scan', str(ws_results['summary']))
            print(f"WebSocket: {ws_results['summary']}")

        alerts = scanner.get_alerts()

        # Notify critical findings immediately
        if notifier:
            for alert in alerts:
                if alert.get('risk') == 'High':
                    notifier.notify_critical_finding(alert)

        # Update incremental cache
        if incremental:
            for alert in alerts:
                url = alert.get('url', '')
                incremental.update_cache(
                    incremental.hash_request(url, 'GET'),
                    url, 'GET', None, [alert], 0
                )
            incremental.end_session({'total': len(har_data['urls']), 'new': len(alerts)})

        print(f"[4/5] Generating reports...")
        duration = f"{time.time() - start_time:.1f}s"

        # Save reports
        saved = reporter.save_all_reports(
            alerts,
            analyzer.get_summary(),
            scanner.zap if not args.no_docker else None,
            args.format.split(',')
        )

        for fmt, path in saved.items():
            print(f"  {fmt}: {path}")

        # OWASP compliance
        if args.owasp:
            owasp = OWASPMapper(config.get('owasp', {}))
            compliance = owasp.map_alerts(alerts)
            report = owasp.generate_report(compliance)
            print(f"\n[OWASP] Score: {report['overall_score']}/100 - {'PASS' if report['passed'] else 'FAIL'}")
            if report['failed_categories']:
                print(f"  Failed: {', '.join(report['failed_categories'])}")

        # Console summary
        reporter.generate_console_report(alerts)

        # Acceptance criteria
        if args.fail_fast:
            criteria = build_criteria(args)
            engine = AcceptanceEngine(criteria)
            evaluation = engine.evaluate({'zap_alerts': alerts, 'idor_results': []})

            print("\n[5/5] Acceptance Criteria:")
            for result in evaluation['results']:
                status = "PASS" if result['passed'] else "FAIL"
                print(f"  [{status}] {result['criterion']}: {result['message']}")

            if not evaluation['passed']:
                print(f"\nFAILED - Duration: {duration}")
                if notifier:
                    notifier.notify_error("Acceptance criteria failed")
                return 1
            else:
                print(f"\nPASSED - Duration: {duration}")

        # Final notification
        if notifier:
            high_count = len([a for a in alerts if a.get('risk') == 'High'])
            notifier.notify_scan_complete({
                'target': args.har_file,
                'alerts_count': len(alerts),
                'high_count': high_count,
                'duration': duration
            })

        return 0

    except Exception as e:
        logger.error("scan_error", error=str(e))
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if docker_manager:
            docker_manager.stop_zap()


def run_graphql(args):
    """Execute GraphQL security testing."""
    if not Path(args.har_file).exists():
        print(f"Error: HAR file not found: {args.har_file}", file=sys.stderr)
        return 1

    Path(args.output).mkdir(parents=True, exist_ok=True)

    print("[1/3] Loading HAR file...")
    with open(args.har_file) as f:
        har_data = json.load(f)

    print("[2/3] Scanning GraphQL endpoints...")
    scanner = GraphQLScanner(har_data)
    endpoints = scanner.detect_endpoints()

    if not endpoints:
        print("No GraphQL endpoints detected")
        return 0

    print(f"Found {len(endpoints)} GraphQL endpoints")

    results = scanner.scan_all()

    print(f"[3/3] Results:")
    print(f"  Endpoints: {results['summary']['total_endpoints']}")
    print(f"  Introspection enabled: {results['summary']['introspection_enabled']}")
    print(f"  Vulnerabilities: {results['summary']['vulnerabilities_found']}")

    output_file = Path(args.output) / 'graphql_results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved: {output_file}")
    return 0


def run_websocket(args):
    """Execute WebSocket security testing."""
    import asyncio

    if not Path(args.har_file).exists():
        print(f"Error: HAR file not found: {args.har_file}", file=sys.stderr)
        return 1

    Path(args.output).mkdir(parents=True, exist_ok=True)

    print("[1/3] Loading HAR file...")
    with open(args.har_file) as f:
        har_data = json.load(f)

    print("[2/3] Scanning WebSocket endpoints...")
    scanner = WebSocketScanner(har_data)
    endpoints = scanner.detect_endpoints()

    if not endpoints:
        print("No WebSocket endpoints detected")
        return 0

    print(f"Found {len(endpoints)} WebSocket endpoints")

    results = asyncio.get_event_loop().run_until_complete(scanner.scan_all())

    print(f"[3/3] Results:")
    print(f"  Endpoints: {results['summary']['total_endpoints']}")
    print(f"  Require auth: {results['summary']['require_auth']}")
    print(f"  Vulnerabilities: {results['summary']['vulnerabilities_found']}")

    output_file = Path(args.output) / 'websocket_results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved: {output_file}")
    return 0


def run_idor(args):
    """Execute IDOR detection."""
    if not Path(args.session_a).exists():
        print(f"Error: Session A HAR not found: {args.session_a}", file=sys.stderr)
        return 1

    if not Path(args.session_b).exists():
        print(f"Error: Session B HAR not found: {args.session_b}", file=sys.stderr)
        return 1

    Path(args.output).mkdir(parents=True, exist_ok=True)

    try:
        print("[1/2] Loading HAR files...")
        with open(args.session_a) as f:
            session_a = json.load(f)
        with open(args.session_b) as f:
            session_b = json.load(f)

        print("[2/2] Running IDOR detection...")
        detector = IDORDetector(session_a, session_b, {'max_workers': args.workers})
        results = detector.run_detection()

        summary = detector.get_summary()

        print("\nIDOR Detection Summary:")
        print(f"  Total tests: {summary['total_tests']}")
        print(f"  Vulnerable: {summary['vulnerable']}")
        print(f"  Protected: {summary['protected']}")
        print(f"  False positives: {summary['false_positives']}")

        output_file = f"{args.output}/idor_results.json"
        with open(output_file, 'w') as f:
            json.dump({
                'summary': summary,
                'results': [
                    {
                        'url': r.url,
                        'method': r.method,
                        'status': r.status.value,
                        'confidence': r.confidence,
                        'proof': r.proof
                    }
                    for r in results
                ]
            }, f, indent=2)

        print(f"\nResults saved: {output_file}")

        if args.fail_on_idor and summary['vulnerable'] > 0:
            print("\nFAILED: IDOR vulnerabilities detected!")
            return 1

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def run_cache(args):
    """Manage incremental scan cache."""
    cache = IncrementalScanner()

    if args.action == 'stats':
        stats = cache.get_cache_stats()
        print("Cache Statistics:")
        print(f"  Total entries: {stats['total_entries']}")
        print(f"  Unique URLs: {stats['unique_urls']}")
        print(f"  Total alerts: {stats['total_alerts']}")
        print(f"  DB size: {stats['db_size_bytes'] / 1024:.1f} KB")

        if stats['recent_sessions']:
            print("\nRecent sessions:")
            for s in stats['recent_sessions']:
                print(f"  {s['session_id']}: {s['total_requests']} total, {s['new_requests']} new")

    elif args.action == 'clear':
        cache.clear_cache(older_than_days=args.older_than)
        print("Cache cleared")

    elif args.action == 'export':
        output = args.output or 'cache_export.json'
        count = cache.export_cache(output)
        print(f"Exported {count} entries to {output}")

    cache.close()
    return 0


def run_advanced(args):
    """Execute advanced attack testing - all requests via ZAP."""
    if not Path(args.har_file).exists():
        print(f"Error: HAR file not found: {args.har_file}", file=sys.stderr)
        return 1

    Path(args.output).mkdir(parents=True, exist_ok=True)

    print("[1/3] Loading HAR file...")
    with open(args.har_file) as f:
        har_data = json.load(f)

    config = load_config()
    results = {}
    total_vulns = 0
    docker_manager = None
    zap_client = None

    # Determine which tests to run
    run_all = args.all
    run_smuggling = args.smuggling or run_all
    run_cache_poison = args.cache_poison or run_all
    run_jwt = args.jwt or run_all
    run_cors = args.cors or run_all
    run_timing = args.timing  # Not included in --all (slow)

    if not any([run_smuggling, run_cache_poison, run_jwt, run_cors, run_timing]):
        print("No tests selected. Use --all or specific flags (--smuggling, --jwt, etc.)")
        return 1

    try:
        # Initialize ZAP
        print("[2/3] Initializing ZAP proxy...")
        if not args.no_docker:
            docker_manager = DockerZAPManager(config)
            zap_config = docker_manager.start_zap()
            zap_url = zap_config['zap_url']
            api_key = zap_config.get('api_key', '')
        else:
            zap_url = args.zap_url
            api_key = args.api_key or ''

        # Create ZAP HTTP client
        from modules.zap_http_client import ZAPHttpClient
        zap_client = ZAPHttpClient(zap_url=zap_url, api_key=api_key)

        print("[3/3] Running advanced attacks via ZAP...")

        # HTTP Smuggling (uses raw sockets, not ZAP)
        if run_smuggling:
            from modules.http_smuggling import HTTPSmugglingTester
            tester = HTTPSmugglingTester(har_data, config)
            smuggling_results = tester.run_tests()
            results['http_smuggling'] = tester.generate_report(smuggling_results)
            vuln_count = len([r for r in smuggling_results if r.vulnerable])
            total_vulns += vuln_count
            print(f"  HTTP Smuggling: {vuln_count} findings")

        # Cache Poisoning
        if run_cache_poison:
            from modules.cache_poisoning import CachePoisoningTester
            tester = CachePoisoningTester(har_data, config, zap_client=zap_client)
            poison_results = tester.run_tests()
            results['cache_poisoning'] = tester.generate_report(poison_results)
            vuln_count = len([r for r in poison_results if r.vulnerable])
            total_vulns += vuln_count
            print(f"  Cache Poisoning: {vuln_count} findings")

        # JWT Attacks
        if run_jwt:
            from modules.jwt_attacks import JWTAttackTester
            tester = JWTAttackTester(har_data, config, zap_client=zap_client)
            jwt_results = tester.run_tests()
            results['jwt_attacks'] = tester.generate_report(jwt_results)
            vuln_count = len([r for r in jwt_results if r.vulnerable])
            total_vulns += vuln_count
            print(f"  JWT Attacks: {vuln_count} findings")

        # CORS Misconfiguration
        if run_cors:
            from modules.cors_tester import CORSTester
            tester = CORSTester(har_data, config, zap_client=zap_client)
            cors_results = tester.run_tests()
            results['cors'] = tester.generate_report(cors_results)
            vuln_count = len([r for r in cors_results if r.vulnerable])
            total_vulns += vuln_count
            print(f"  CORS: {vuln_count} findings")

        # Timing Analysis
        if run_timing:
            from modules.timing_analysis import TimingAnalyzer
            tester = TimingAnalyzer(har_data, config, zap_client=zap_client)
            timing_results = tester.run_tests()
            results['timing_analysis'] = tester.generate_report(timing_results)
            vuln_count = len([r for r in timing_results if r.vulnerable])
            total_vulns += vuln_count
            print(f"  Timing Analysis: {vuln_count} findings")

        # Get alerts from ZAP
        if zap_client:
            zap_alerts = zap_client.get_alerts()
            results['zap_alerts_count'] = len(zap_alerts)

    finally:
        if docker_manager:
            docker_manager.stop_zap()

    # Save results
    output_file = Path(args.output) / 'advanced_attacks.json'
    with open(output_file, 'w') as f:
        json.dump({
            'total_vulnerabilities': total_vulns,
            'results': results
        }, f, indent=2)

    print(f"\nTotal vulnerabilities: {total_vulns}")
    print(f"Results saved: {output_file}")

    # Webhook notification
    if args.webhook and total_vulns > 0:
        notifier = NotificationManager({'webhooks': [{'type': args.webhook, 'url': '', 'events': ['all']}]})
        notifier.notify_critical_finding({
            'name': 'Advanced Attack Findings',
            'risk': 'High',
            'description': f'{total_vulns} vulnerabilities found in advanced testing',
            'url': args.har_file
        })

    return 0


def run_diagnose(args):
    """Run full diagnostic attack suite."""
    import time
    start_time = time.time()

    if not Path(args.har_file).exists():
        print(f"Error: HAR file not found: {args.har_file}", file=sys.stderr)
        return 1

    Path(args.output).mkdir(parents=True, exist_ok=True)

    print(f"[DIAGNOSE] Target: {args.target}")
    print(f"[DIAGNOSE] HAR: {args.har_file}\n")

    with open(args.har_file) as f:
        har_data = json.load(f)

    config = load_config()
    all_findings = []
    docker_manager = None
    zap_client = None

    try:
        # Initialize ZAP
        print("[1/6] Starting ZAP...")
        if not args.no_docker:
            docker_manager = DockerZAPManager(config)
            zap_config = docker_manager.start_zap()
            zap_url = zap_config['zap_url']
            api_key = zap_config.get('api_key', '')
        else:
            zap_url = args.zap_url
            api_key = args.api_key or ''

        from modules.zap_http_client import ZAPHttpClient
        zap_client = ZAPHttpClient(zap_url=zap_url, api_key=api_key)

        # ZAP Active Scan
        if not args.skip_zap:
            print("[2/6] ZAP Active Scan...")
            analyzer = HARAnalyzer(args.har_file, config)
            har_analysis = analyzer.analyze()
            scanner = ZAPScanner({'zap_url': zap_url, 'api_key': api_key}, har_analysis, config)
            scanner.configure_context()
            scanner.populate_site_tree()
            scanner.execute_targeted_scans()
            zap_alerts = scanner.get_alerts()
            all_findings.extend([{'source': 'zap', **a} for a in zap_alerts])
            print(f"  Found: {len(zap_alerts)} alerts")
        else:
            print("[2/6] ZAP Active Scan... SKIPPED")

        # Advanced Attacks
        print("[3/6] Advanced Attacks...")
        adv_results = {}

        from modules.http_smuggling import HTTPSmugglingTester
        smuggler = HTTPSmugglingTester(har_data, config)
        smuggling = smuggler.run_tests()
        vuln = [r for r in smuggling if r.vulnerable]
        adv_results['smuggling'] = len(vuln)
        all_findings.extend([{'source': 'smuggling', 'risk': 'Critical', 'name': 'HTTP Smuggling', 'url': r.url} for r in vuln])
        print(f"  HTTP Smuggling: {len(vuln)}")

        from modules.jwt_attacks import JWTAttackTester
        jwt_tester = JWTAttackTester(har_data, config, zap_client=zap_client)
        jwt_results = jwt_tester.run_tests()
        vuln = [r for r in jwt_results if r.vulnerable]
        adv_results['jwt'] = len(vuln)
        all_findings.extend([{'source': 'jwt', 'risk': 'High', 'name': r.attack_type, 'url': r.url} for r in vuln])
        print(f"  JWT Attacks: {len(vuln)}")

        from modules.cors_tester import CORSTester
        cors_tester = CORSTester(har_data, config, zap_client=zap_client)
        cors_results = cors_tester.run_tests()
        vuln = [r for r in cors_results if r.vulnerable]
        adv_results['cors'] = len(vuln)
        all_findings.extend([{'source': 'cors', 'risk': 'Medium', 'name': 'CORS Misconfiguration', 'url': r.url} for r in vuln])
        print(f"  CORS: {len(vuln)}")

        from modules.cache_poisoning import CachePoisoningTester
        cache_tester = CachePoisoningTester(har_data, config, zap_client=zap_client)
        cache_results = cache_tester.run_tests()
        vuln = [r for r in cache_results if r.vulnerable]
        adv_results['cache_poison'] = len(vuln)
        all_findings.extend([{'source': 'cache', 'risk': 'High', 'name': 'Cache Poisoning', 'url': r.url} for r in vuln])
        print(f"  Cache Poisoning: {len(vuln)}")

        # Red Team Attacks
        if not args.skip_redteam:
            print("[4/6] Red Team Attacks...")
            from modules.redteam_attacks import RedTeamOrchestrator
            redteam = RedTeamOrchestrator(har_data, config, zap_client=zap_client)
            rt_results = redteam.run_all()
            rt_vulns = rt_results.get('total_vulnerabilities', 0)
            adv_results['redteam'] = rt_vulns
            for attack_name, findings in rt_results.get('attacks', {}).items():
                for f in findings.get('findings', []):
                    if f.get('vulnerable'):
                        all_findings.append({'source': 'redteam', 'risk': 'High', 'name': attack_name, 'url': f.get('url', '')})
            print(f"  Red Team: {rt_vulns}")
        else:
            print("[4/6] Red Team Attacks... SKIPPED")

        # Passive Analysis
        print("[5/6] Passive Analysis...")
        from modules.passive_analysis import PassiveAnalysisOrchestrator
        passive = PassiveAnalysisOrchestrator(har_data, config)
        passive_results = passive.run_all()
        passive_issues = passive_results.get('total_issues', 0)
        adv_results['passive'] = passive_issues
        for issue in passive_results.get('security_headers', {}).get('missing', []):
            all_findings.append({'source': 'passive', 'risk': 'Low', 'name': f'Missing Header: {issue}', 'url': args.target})
        print(f"  Passive Issues: {passive_issues}")

        # Summary
        print("[6/6] Generating Report...")
        duration = time.time() - start_time

        high_count = len([f for f in all_findings if f.get('risk') in ['High', 'Critical']])
        medium_count = len([f for f in all_findings if f.get('risk') == 'Medium'])
        low_count = len([f for f in all_findings if f.get('risk') == 'Low'])

        report = {
            'target': args.target,
            'har_file': args.har_file,
            'duration_seconds': round(duration, 1),
            'summary': {
                'total': len(all_findings),
                'critical_high': high_count,
                'medium': medium_count,
                'low': low_count
            },
            'breakdown': adv_results,
            'findings': all_findings
        }

        # Save JSON
        json_path = Path(args.output) / 'diagnostic_report.json'
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Save HTML if requested
        if 'html' in args.format:
            html_path = Path(args.output) / 'diagnostic_report.html'
            html_content = generate_diagnostic_html(report)
            with open(html_path, 'w') as f:
                f.write(html_content)

        print(f"\n{'='*50}")
        print(f"DIAGNOSTIC COMPLETE - {args.target}")
        print(f"{'='*50}")
        print(f"Duration: {duration:.1f}s")
        print(f"Critical/High: {high_count}")
        print(f"Medium: {medium_count}")
        print(f"Low: {low_count}")
        print(f"Total: {len(all_findings)}")
        print(f"\nReports: {args.output}/diagnostic_report.*")

        # Fail-fast check
        if args.fail_fast:
            max_high = args.max_high if args.max_high is not None else 0
            if high_count > max_high:
                print(f"\nFAILED: {high_count} critical/high findings (max: {max_high})")
                return 1
            print(f"\nPASSED: Within acceptance criteria")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        if docker_manager:
            docker_manager.stop_zap()


def generate_diagnostic_html(report):
    """Generate HTML report for diagnostic results."""
    findings_html = ""
    for f in report['findings']:
        risk_class = f.get('risk', 'Info').lower()
        findings_html += f"""
        <tr class="{risk_class}">
            <td>{f.get('risk', 'Info')}</td>
            <td>{f.get('source', '')}</td>
            <td>{f.get('name', '')}</td>
            <td>{f.get('url', '')[:80]}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Diagnostic Report - {report['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #333; color: white; }}
        .critical, .high {{ background: #ffcccc; }}
        .medium {{ background: #fff3cd; }}
        .low {{ background: #d4edda; }}
    </style>
</head>
<body>
    <h1>Diagnostic Security Report</h1>
    <div class="summary">
        <strong>Target:</strong> {report['target']}<br>
        <strong>Duration:</strong> {report['duration_seconds']}s<br>
        <strong>Critical/High:</strong> {report['summary']['critical_high']}<br>
        <strong>Medium:</strong> {report['summary']['medium']}<br>
        <strong>Low:</strong> {report['summary']['low']}<br>
        <strong>Total:</strong> {report['summary']['total']}
    </div>
    <h2>Findings</h2>
    <table>
        <tr><th>Risk</th><th>Source</th><th>Name</th><th>URL</th></tr>
        {findings_html}
    </table>
</body>
</html>"""


def build_criteria(args):
    """Build acceptance criteria from CLI args."""
    criteria = []

    if args.max_high is not None:
        criteria.append({'type': 'max_high', 'threshold': args.max_high})

    if args.max_medium is not None:
        criteria.append({'type': 'max_medium', 'threshold': args.max_medium})

    return criteria


if __name__ == '__main__':
    sys.exit(main())
