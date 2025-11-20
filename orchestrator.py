#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

import yaml

from modules.adaptive_tuner import AdaptiveThresholdTuner
from modules.docker_manager import DockerZAPManager
from modules.har_analyzer import HARAnalyzer
from modules.meta_analyzer import MetaAnalyzer
from modules.reporter import Reporter
from modules.zap_passive_scanner import ZAPPassiveScanner
from modules.zap_scanner import ZAPScanner


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

    print("=" * 80)
    print("ZAP AUTOMATED SECURITY SCANNER")
    print("=" * 80)

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

        print("\n[3/9] Configuring ZAP scanner...")
        scanner = ZAPScanner(zap_config, har_data, config)
        scanner.configure_context()
        scanner.configure_scan_policies()

        # Get base target URL
        base_target = har_data['urls'][0] if har_data['urls'] else None
        if not base_target:
            print("Error: No base target URL")
            sys.exit(1)

        print("\n[4/9] Platform fingerprinting (Arachni-inspired)...")
        fingerprint = scanner.run_platform_fingerprinting(base_target)
        print(f"[Fingerprint] Detected {fingerprint['scanner_count']} technology categories")

        print("\n[5/9] Discovery phase (Spider + Ajax Spider)...")
        scanner.populate_site_tree()

        # Traditional spider
        spider_results = scanner.run_traditional_spider(base_target, max_duration=5)
        print(f"[Spider] Found {len(spider_results['discovered_urls'])} URLs")

        # Ajax spider for JS-heavy apps
        ajax_results = scanner.run_ajax_spider(base_target, max_duration=5)
        print(f"[Ajax Spider] Found {len(ajax_results['discovered_urls'])} URLs")

        print("\n[6/9] Passive scanning (ZAP native + custom)...")
        passive_scanner = ZAPPassiveScanner(scanner.zap, har_data)
        passive_issues = passive_scanner.scan_full(base_target)
        print(f"[Passive] Found {len(passive_issues)} issues")

        print("\n[7/9] Adaptive learning (Arachni trainer)...")
        adaptive_tuner = AdaptiveThresholdTuner(scanner.zap)
        adaptive_tuner.set_detected_technologies(fingerprint['technologies'])

        # Get initial alerts for tuning
        initial_alerts = scanner.get_alerts()
        adaptive_tuner.analyze_alerts(initial_alerts)
        adjusted = adaptive_tuner.adjust_scanners()
        print(f"[Adaptive] Adjusted {adjusted} scanners based on FP analysis")

        print("\n[8/9] Active scanning (targeted + custom scripts)...")
        # Load custom ZAP scripts
        try:
            script_dir = Path(__file__).parent / 'scripts' / 'active'
            if script_dir.exists():
                for script_file in script_dir.glob('*.js'):
                    scanner.zap.script.load(
                        scriptname=script_file.stem,
                        scripttype='active',
                        scriptengine='ECMAScript',
                        filename=str(script_file)
                    )
                    scanner.zap.script.enable(script_file.stem)
                    print(f"[Scripts] Loaded {script_file.name}")
        except Exception as e:
            print(f"[Scripts] Warning: Could not load scripts: {e}")

        scan_results = scanner.execute_targeted_scans()
        print(f"[Active Scan] Completed {len(scan_results)} scan scenarios")

        print("\n[9/9] Meta-analysis & reporting...")
        all_alerts = scanner.get_alerts()

        # Meta-analysis (Arachni meta-plugins)
        meta_analyzer = MetaAnalyzer(all_alerts)
        meta_report = meta_analyzer.generate_meta_report()

        # Deduplicate alerts
        deduplicated_alerts = meta_analyzer.deduplicate_alerts()

        reporter = Reporter(args.output)
        reporter.generate_console_report(deduplicated_alerts)

        # Enhanced report with Arachni-inspired features
        enhanced_summary = {
            'har_analysis': analyzer.get_summary(),
            'platform_fingerprint': fingerprint,
            'discovery': {
                'spider_urls': len(spider_results['discovered_urls']),
                'ajax_urls': len(ajax_results['discovered_urls'])
            },
            'passive_scan': {
                'issues_count': len(passive_issues),
                'zap_native': len([i for i in passive_issues if i.zap_plugin_id]),
                'custom': len([i for i in passive_issues if not i.zap_plugin_id])
            },
            'adaptive_learning': adaptive_tuner.get_summary(),
            'meta_analysis': meta_report
        }

        reporter.save_json_report(deduplicated_alerts, enhanced_summary)
        reporter.save_html_report(scanner.zap, f"{args.output}/report_{reporter.timestamp}.html")
        reporter.save_critical_findings(deduplicated_alerts)

        # Save meta-analysis separately
        import json

        with open(f"{args.output}/meta_analysis_{reporter.timestamp}.json", 'w') as f:
            json.dump(meta_report, f, indent=2)

        print(f"\n[Reports] Saved to {args.output}/")
        print(f"[Reports]   - Main report: report_{reporter.timestamp}.html")
        print(f"[Reports]   - Meta-analysis: meta_analysis_{reporter.timestamp}.json")
        print(f"[Reports]   - Critical findings: critical_findings_{reporter.timestamp}.json")

        print("\n" + "=" * 80)
        print("SCAN COMPLETE")
        print("=" * 80)

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
