"""Tests for TimingAnalyzer.compute_verdict."""
from modules.timing_analysis import TimingAnalyzer, TimingStats


def _stats(samples):
    s = TimingStats(samples=samples)
    s.calculate()
    return s


class TestComputeVerdict:
    def test_too_few_samples(self):
        b = _stats([0.1, 0.2])
        p = _stats([5.0, 5.1])
        verdict, z, why = TimingAnalyzer.compute_verdict(b, p)
        assert verdict == "INCONCLUSIVE"
        assert "samples" in why.lower()

    def test_clear_vulnerability(self):
        b = _stats([0.10, 0.11, 0.12, 0.11, 0.10])
        p = _stats([5.0, 5.1, 5.2, 5.0, 5.1])
        verdict, z, why = TimingAnalyzer.compute_verdict(b, p)
        assert verdict == "LIKELY_VULNERABLE"
        assert z > 3.0
        assert "standard deviations" in why.lower()

    def test_moderate_signal_inconclusive(self):
        b = _stats([0.10, 0.20, 0.30, 0.25, 0.15])
        p = _stats([0.40, 0.50, 0.45, 0.42, 0.48])
        verdict, z, why = TimingAnalyzer.compute_verdict(b, p)
        assert verdict in ("INCONCLUSIVE", "LIKELY_VULNERABLE")
        if verdict == "INCONCLUSIVE":
            assert "moderate" in why.lower() or "threshold" in why.lower()

    def test_no_vulnerability(self):
        b = _stats([0.10, 0.11, 0.12, 0.10, 0.11])
        p = _stats([0.12, 0.11, 0.10, 0.13, 0.11])
        verdict, z, _ = TimingAnalyzer.compute_verdict(b, p)
        assert verdict == "NOT_VULNERABLE"
        assert abs(z) < 3.0

    def test_zero_baseline_variance_with_large_delta(self):
        b = _stats([0.10, 0.10, 0.10, 0.10, 0.10])
        p = _stats([5.0, 5.0, 5.0, 5.0, 5.0])
        verdict, z, why = TimingAnalyzer.compute_verdict(b, p)
        assert verdict == "LIKELY_VULNERABLE"
        assert "zero variance" in why.lower()

    def test_zero_baseline_variance_with_small_delta(self):
        b = _stats([0.10, 0.10, 0.10, 0.10, 0.10])
        p = _stats([0.10, 0.10, 0.10, 0.10, 0.10])
        verdict, _, _ = TimingAnalyzer.compute_verdict(b, p)
        assert verdict == "NOT_VULNERABLE"

    def test_custom_z_threshold(self):
        b = _stats([0.10, 0.11, 0.12, 0.11, 0.10])
        p = _stats([0.20, 0.21, 0.22, 0.21, 0.20])
        verdict_strict, _, _ = TimingAnalyzer.compute_verdict(b, p, z_threshold=50.0)
        verdict_loose, _, _ = TimingAnalyzer.compute_verdict(b, p, z_threshold=0.5)
        assert verdict_strict != "LIKELY_VULNERABLE"
        assert verdict_loose == "LIKELY_VULNERABLE"
