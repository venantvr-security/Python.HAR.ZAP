"""
Adaptive Threshold Tuner - Arachni Trainer-inspired

Monitors scan results and dynamically adjusts ZAP scanner thresholds
to reduce false positives based on observed patterns.
"""
from collections import defaultdict
from typing import Dict, List

from zapv2 import ZAPv2


class AdaptiveThresholdTuner:
    """
    Arachni Trainer Pattern: Learn from application behavior during scan.

    Adjusts ZAP scanner thresholds based on:
    - False positive rates (high frequency + low confidence)
    - Technology-specific patterns
    - Response time anomalies
    """

    def __init__(self, zap_client: ZAPv2):
        self.zap = zap_client
        self.fp_tracker = defaultdict(int)  # scanner_id -> FP count
        self.scanner_performance = defaultdict(dict)  # scanner_id -> metrics
        self.technologies: Dict = {}  # Detected tech stack (category -> list of techs)
        self.baseline_response_time = None

    def set_detected_technologies(self, technologies: Dict):
        """Set detected technologies from fingerprinting"""
        self.technologies = technologies
        print(f"[Adaptive] Loaded {len(technologies)} technology categories")

    def analyze_alerts(self, alerts: List[Dict]):
        """
        Identify likely false positives and scanner performance.

        FP indicators:
        - High frequency (>10 instances) + Low confidence
        - Same parameter across many endpoints
        - Low-severity info disclosures
        """
        scanner_stats = defaultdict(lambda: {'total': 0, 'low_conf': 0, 'high_freq': 0})

        for alert in alerts:
            plugin_id = alert.get('pluginId', '')
            confidence = alert.get('confidence', '')
            risk = alert.get('risk', '')

            scanner_stats[plugin_id]['total'] += 1

            # Track low confidence alerts
            if confidence in ['Low', 'Tentative']:
                scanner_stats[plugin_id]['low_conf'] += 1

            # Track high-frequency low-severity
            if risk in ['Informational', 'Low'] and scanner_stats[plugin_id]['total'] > 10:
                scanner_stats[plugin_id]['high_freq'] += 1

        # Calculate FP likelihood
        for scanner_id, stats in scanner_stats.items():
            if stats['total'] > 0:
                low_conf_ratio = stats['low_conf'] / stats['total']

                # FP if >70% low confidence OR high frequency low-severity
                if low_conf_ratio > 0.7 or stats['high_freq'] > 5:
                    self.fp_tracker[scanner_id] += 1
                    print(f"[Adaptive] Scanner {scanner_id} flagged (low_conf: {low_conf_ratio:.2f})")

        self.scanner_performance = scanner_stats

    def adjust_scanners(self, aggressive: bool = False):
        """
        Adjust ZAP scanner thresholds based on FP analysis.

        Strategy:
        - Noisy scanners (FP count > 5): Raise threshold to HIGH
        - Tech-specific: Enable only relevant scanners
        - Aggressive mode: Keep all scanners at MEDIUM
        """
        adjusted = 0

        for scanner_id, fp_count in self.fp_tracker.items():
            if fp_count > 5 and not aggressive:
                try:
                    # Reduce sensitivity for noisy scanners
                    self.zap.ascan.set_scanner_alert_threshold(scanner_id, 'HIGH')
                    print(f"[Adaptive] Raised threshold for scanner {scanner_id} (FP: {fp_count})")
                    adjusted += 1
                except Exception as e:
                    print(f"[Adaptive] Could not adjust {scanner_id}: {e}")

        # Technology-specific tuning
        if self.technologies:
            self._tune_for_technologies()

        print(f"[Adaptive] Adjusted {adjusted} scanners")
        return adjusted

    def _tune_for_technologies(self):
        """Enable/disable scanners based on detected technologies"""
        tech_scanner_map = {
            'php': ['40009', '40135'],  # File inclusion, htaccess
            'java': ['40018', '90019'],  # SQL injection, Server-side injection
            'python': ['90020'],  # Remote OS command
            'asp': ['90033'],  # Loosely scoped cookie
            'mysql': ['40019'],  # MySQL-specific SQL injection
            'postgresql': ['40021'],  # PostgreSQL SQL injection
            'oracle': ['40022'],  # Oracle SQL injection
        }

        detected_tech_lower = [
            tech['name'].lower()
            for techs in self.technologies.values()
            for tech in techs
        ]

        for tech, scanner_ids in tech_scanner_map.items():
            if any(tech in dt for dt in detected_tech_lower):
                for scanner_id in scanner_ids:
                    try:
                        # Enable and prioritize relevant scanners
                        self.zap.ascan.set_scanner_alert_threshold(scanner_id, 'LOW')
                        self.zap.ascan.set_scanner_attack_strength(scanner_id, 'HIGH')
                        print(f"[Adaptive] Prioritized scanner {scanner_id} for {tech}")
                    except Exception:
                        pass

    def calculate_timing_baseline(self, sample_urls: List[str], count: int = 5):
        """
        Calculate baseline response time for timing attack detection.
        Arachni-inspired: Establish normal behavior before anomaly detection.
        """
        import time

        response_times = []

        for url in sample_urls[:count]:
            try:
                start = time.time()
                self.zap.core.access_url(url)
                elapsed = time.time() - start
                response_times.append(elapsed)
            except Exception:
                pass

        if response_times:
            self.baseline_response_time = sum(response_times) / len(response_times)
            print(f"[Adaptive] Baseline response time: {self.baseline_response_time:.2f}s")

        return self.baseline_response_time

    # noinspection PyMethodMayBeStatic
    def detect_timing_anomalies(self, alerts: List[Dict]) -> List[Dict]:
        """
        Flag timing-based alerts with inconsistent results.
        Arachni meta-plugin: Timing attack trustworthiness assessment.
        """
        timing_alerts = [
            a for a in alerts
            if 'timing' in a.get('alert', '').lower() or
               'blind' in a.get('alert', '').lower()
        ]

        suspicious = []

        for alert in timing_alerts:
            # Check if evidence shows consistent timing differences
            evidence = alert.get('evidence', '')

            # Simple heuristic: if evidence is empty or very short, likely FP
            if len(evidence) < 10:
                suspicious.append({
                    'alert': alert,
                    'reason': 'Insufficient timing evidence',
                    'confidence_adjustment': 'Reduce to Tentative'
                })

        if suspicious:
            print(f"[Adaptive] Found {len(suspicious)} suspicious timing alerts")

        return suspicious

    def get_summary(self) -> Dict:
        """Return tuning summary for reporting"""
        return {
            'false_positive_tracker': dict(self.fp_tracker),
            'scanner_performance': dict(self.scanner_performance),
            'technologies_count': len(self.technologies),
            'baseline_response_time': self.baseline_response_time,
            'total_adjustments': len(self.fp_tracker)
        }
