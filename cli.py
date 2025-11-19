#!/usr/bin/env python3
"""
CI/CD-friendly CLI for DAST Security Platform
Supports fail-fast mode and multiple output formats
"""
import argparse
import json
import sys
from pathlib import Path

from modules.acceptance_engine import AcceptanceEngine
from modules.docker_manager import DockerZAPManager
from modules.har_analyzer import HARAnalyzer
from modules.idor_detector import IDORDetector
from modules.reporter import Reporter
from modules.zap_scanner import ZAPScanner


def main():
    parser = argparse.ArgumentParser(
        description='DAST Security Platform - CI/CD CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with acceptance criteria
  %(prog)s scan traffic.har --max-high 0 --max-medium 5

  # IDOR detection
  %(prog)s idor --session-a user1.har --session-b user2.har

  # Export SARIF for GitHub Security
  %(prog)s scan traffic.har --format sarif --output results.sarif

  # Fail-fast mode (exit code 1 if criteria not met)
  %(prog)s scan traffic.har --fail-fast --max-high 0
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    scan_parser = subparsers.add_parser('scan', help='Run ZAP security scan')
    scan_parser.add_argument('har_file', help='HAR file to scan')
    scan_parser.add_argument('-c', '--config', help='Config YAML file')
    scan_parser.add_argument('-o', '--output', default='./output', help='Output directory')
    scan_parser.add_argument('--format', choices=['json', 'html', 'sarif', 'junit'],
                             default='json', help='Output format')
    scan_parser.add_argument('--max-high', type=int, help='Max high severity alerts')
    scan_parser.add_argument('--max-medium', type=int, help='Max medium severity alerts')
    scan_parser.add_argument('--fail-fast', action='store_true',
                             help='Exit with code 1 if acceptance criteria fail')
    scan_parser.add_argument('--no-docker', action='store_true',
                             help='Use existing ZAP instance')
    scan_parser.add_argument('--zap-url', default='http://localhost:8080',
                             help='ZAP URL if using existing instance')
    scan_parser.add_argument('--api-key', help='ZAP API key')

    idor_parser = subparsers.add_parser('idor', help='Run IDOR detection')
    idor_parser.add_argument('--session-a', required=True, help='HAR file for User A')
    idor_parser.add_argument('--session-b', required=True, help='HAR file for User B')
    idor_parser.add_argument('-o', '--output', default='./output', help='Output directory')
    idor_parser.add_argument('--workers', type=int, default=5, help='Parallel workers')
    idor_parser.add_argument('--fail-on-idor', action='store_true',
                             help='Exit with code 1 if IDOR found')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'scan':
        return run_scan(args)
    elif args.command == 'idor':
        return run_idor(args)


def run_scan(args):
    """Execute ZAP scan with acceptance criteria"""
    if not Path(args.har_file).exists():
        print(f"Error: HAR file not found: {args.har_file}", file=sys.stderr)
        return 1

    Path(args.output).mkdir(parents=True, exist_ok=True)

    config = load_config(args.config)

    print("[1/4] Analyzing HAR file...")
    analyzer = HARAnalyzer(args.har_file, config)
    har_data = analyzer.analyze()
    print(analyzer.get_summary())

    if len(har_data['urls']) == 0:
        print("Error: No URLs found in HAR", file=sys.stderr)
        return 1

    docker_manager = None
    zap_config = None

    try:
        if not args.no_docker:
            print("[2/4] Starting ZAP container...")
            docker_manager = DockerZAPManager(config)
            zap_config = docker_manager.start_zap()
        else:
            zap_config = {
                'zap_url': args.zap_url,
                'api_key': args.api_key or '',
                'port': 8080
            }

        print("[3/4] Executing scans...")
        scanner = ZAPScanner(zap_config, har_data, config)
        scanner.configure_context()
        scanner.configure_scan_policies()
        scanner.populate_site_tree()
        scan_results = scanner.execute_targeted_scans()

        alerts = scanner.get_alerts()

        print(f"[4/4] Generating reports...")
        reporter = Reporter(args.output)

        if args.format == 'json':
            output_file = reporter.save_json_report(alerts, analyzer.get_summary())
            print(f"Report saved: {output_file}")

        elif args.format == 'html':
            output_file = reporter.save_html_report(scanner.zap)
            print(f"Report saved: {output_file}")

        elif args.format == 'sarif':
            engine = AcceptanceEngine([])
            output_path = f"{args.output}/results.sarif"
            engine.export_sarif({'zap_alerts': alerts}, output_path)
            print(f"SARIF report saved: {output_path}")

        elif args.format == 'junit':
            criteria = build_criteria(args)
            engine = AcceptanceEngine(criteria)
            evaluation = engine.evaluate({'zap_alerts': alerts, 'idor_results': []})
            output_path = f"{args.output}/junit.xml"
            engine.export_junit_xml(evaluation, output_path)
            print(f"JUnit XML saved: {output_path}")

        if args.fail_fast:
            criteria = build_criteria(args)
            engine = AcceptanceEngine(criteria)
            evaluation = engine.evaluate({'zap_alerts': alerts, 'idor_results': []})

            print("\nAcceptance Criteria Evaluation:")
            for result in evaluation['results']:
                status = "✓" if result['passed'] else "✗"
                print(f"  {status} {result['criterion']}: {result['message']}")

            if not evaluation['passed']:
                print("\n❌ Security criteria not met!")
                return 1
            else:
                print("\n✅ All security criteria passed!")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1

    finally:
        if docker_manager:
            docker_manager.stop_zap()


def run_idor(args):
    """Execute IDOR detection"""
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
        print(f"  🚨 Vulnerable: {summary['vulnerable']}")
        print(f"  ✅ Protected: {summary['protected']}")
        print(f"  ⚠️  False positives: {summary['false_positives']}")

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
            print("\n❌ IDOR vulnerabilities detected!")
            return 1
        else:
            print("\n✅ IDOR check complete!")
            return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


def build_criteria(args):
    """Build acceptance criteria from CLI args"""
    criteria = []

    if args.max_high is not None:
        criteria.append({'type': 'max_high', 'threshold': args.max_high})

    if args.max_medium is not None:
        criteria.append({'type': 'max_medium', 'threshold': args.max_medium})

    return criteria


def load_config(config_path):
    """Load configuration from YAML file"""
    import yaml

    default_config = {
        'scope_domains': [],
        'exclude_domains': [
            'google-analytics.com',
            'googletagmanager.com',
            'facebook.com'
        ],
        'allowed_methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        'zap_port': 8080,
        'zap_image': 'ghcr.io/zaproxy/zaproxy:stable',
        'scan_fuzzable_urls': True,
        'scan_api_endpoints': True
    }

    if config_path and Path(config_path).exists():
        with open(config_path) as f:
            user_config = yaml.safe_load(f)
            default_config.update(user_config)

    return default_config


if __name__ == '__main__':
    sys.exit(main())
