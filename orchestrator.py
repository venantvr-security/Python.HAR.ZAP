#!/usr/bin/env python3
import sys
import argparse
import yaml
from pathlib import Path

from modules.har_analyzer import HARAnalyzer
from modules.docker_manager import DockerZAPManager
from modules.zap_scanner import ZAPScanner
from modules.reporter import Reporter


def load_config(config_path: str = None) -> dict:
    default_config = {
        'scope_domains': [],
        'exclude_domains': [
            'google-analytics.com',
            'googletagmanager.com',
            'facebook.com',
            'doubleclick.net',
            'cdn.jsdelivr.net',
            'fonts.googleapis.com',
            'ajax.googleapis.com'
        ],
        'allowed_methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        'zap_port': 8080,
        'zap_image': 'ghcr.io/zaproxy/zaproxy:stable',
        'scan_fuzzable_urls': True,
        'scan_api_endpoints': True,
        'max_scan_time': 300
    }

    if config_path and Path(config_path).exists():
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f)
            default_config.update(user_config)

    return default_config


def main():
    parser = argparse.ArgumentParser(
        description='Automated ZAP Security Scanner with HAR Intelligence'
    )
    parser.add_argument(
        'har_file',
        help='Path to HAR file'
    )
    parser.add_argument(
        '-c', '--config',
        help='Path to config YAML file',
        default=None
    )
    parser.add_argument(
        '-o', '--output',
        help='Output directory for reports',
        default='./output'
    )
    parser.add_argument(
        '--no-docker',
        action='store_true',
        help='Skip Docker and use existing ZAP instance'
    )
    parser.add_argument(
        '--zap-url',
        help='ZAP URL if using existing instance',
        default='http://localhost:8080'
    )
    parser.add_argument(
        '--api-key',
        help='API key if using existing instance',
        default=None
    )

    args = parser.parse_args()

    if not Path(args.har_file).exists():
        print(f"Error: HAR file not found: {args.har_file}")
        sys.exit(1)

    Path(args.output).mkdir(parents=True, exist_ok=True)

    config = load_config(args.config)

    print("="*80)
    print("ZAP AUTOMATED SECURITY SCANNER")
    print("="*80)

    print("\n[1/5] Analyzing HAR file...")
    analyzer = HARAnalyzer(args.har_file, config)
    har_data = analyzer.analyze()
    print(analyzer.get_summary())

    if len(har_data['urls']) == 0:
        print("Error: No URLs found in HAR file matching the criteria")
        sys.exit(1)

    docker_manager = None
    zap_config = None

    try:
        if not args.no_docker:
            print("\n[2/5] Starting ZAP in Docker...")
            docker_manager = DockerZAPManager(config)
            zap_config = docker_manager.start_zap()
        else:
            print("\n[2/5] Using existing ZAP instance...")
            zap_config = {
                'zap_url': args.zap_url,
                'api_key': args.api_key or '',
                'port': 8080
            }

        print("\n[3/5] Configuring ZAP scanner...")
        scanner = ZAPScanner(zap_config, har_data, config)
        scanner.configure_context()
        scanner.configure_scan_policies()
        scanner.populate_site_tree()

        print("\n[4/5] Executing targeted scans...")
        scan_results = scanner.execute_targeted_scans()
        print(f"[Scan] Completed {len(scan_results)} scan scenarios")

        print("\n[5/5] Generating reports...")
        alerts = scanner.get_alerts()

        reporter = Reporter(args.output)
        reporter.generate_console_report(alerts)
        reporter.save_json_report(alerts, analyzer.get_summary())
        reporter.save_html_report(scanner.zap, f"{args.output}/report_{reporter.timestamp}.html")
        reporter.save_critical_findings(alerts)

        print("\n" + "="*80)
        print("SCAN COMPLETE")
        print("="*80)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"\n[!] Error during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    finally:
        if docker_manager:
            docker_manager.stop_zap()


if __name__ == '__main__':
    main()
