import unittest

from .decision_score_estimator import (
    DECISION_THRESHOLD, estimate_group_score, estimate_isolated_and_multidomain,
    normalized_entropy,
)

SYN_THRESHOLD = 76.82


class NormalizedEntropyTests(unittest.TestCase):
    def test_single_source_is_zero(self):
        self.assertEqual(normalized_entropy([345.69]), 0.0)

    def test_uniform_sources_is_one(self):
        self.assertAlmostEqual(normalized_entropy([10.0] * 6), 1.0, places=9)

    def test_skewed_sources_below_one(self):
        e = normalized_entropy([34.569, 34.569, 26.887, 26.887, 19.205, 19.205])
        self.assertTrue(0.9 < e < 1.0)


class SingleAttackerPathTests(unittest.TestCase):
    """Composition 1's control scenario: one source, one domain, k=4.75x threshold."""

    def test_k_4_75_crosses_decision_threshold(self):
        rate = 4.75 * SYN_THRESHOLD
        result = estimate_group_score([rate], ['enterprise'], SYN_THRESHOLD, 'syn_flood')
        self.assertAlmostEqual(result['score'], 4.75, places=6)
        self.assertAlmostEqual(result['confidence'], 0.475, places=6)
        self.assertEqual(result['weight'], 1.0)
        self.assertAlmostEqual(result['final_score'], 2.25625, places=5)
        self.assertTrue(result['decides'])

    def test_low_k_does_not_cross_decision_threshold(self):
        # score*confidence = score^2/10 >= 1.5 needs score >= sqrt(15) ~= 3.873
        rate = 1.5 * SYN_THRESHOLD
        result = estimate_group_score([rate], ['fixed'], SYN_THRESHOLD, 'syn_flood')
        self.assertFalse(result['decides'])

    def test_below_threshold_total_returns_none(self):
        result = estimate_group_score([0.3 * SYN_THRESHOLD], ['peering'], SYN_THRESHOLD, 'syn_flood')
        self.assertIsNone(result)


class DistributedPathTests(unittest.TestCase):
    def test_four_sources_never_reaches_distributed_path(self):
        # DIST_MIN_SOURCES=5: a 4-source group, however even, is scored as
        # single-attacker (or not at all if below threshold), never as
        # DDOS_DISTRIBUTED/MULTIDOMAIN_DISTRIBUTED_ATTACK.
        result = estimate_group_score([50.0] * 4, ['enterprise'], SYN_THRESHOLD, 'syn_flood')
        self.assertNotIn(result['attack_type'], ('DDOS_DISTRIBUTED', 'MULTIDOMAIN_DISTRIBUTED_ATTACK'))

    def test_six_sources_high_entropy_multidomain_saturates_confidence(self):
        sources = [34.569, 34.569, 26.887, 26.887, 19.205, 19.205]
        domains = ['enterprise', 'enterprise', 'fixed', 'fixed', 'mobile', 'mobile']
        result = estimate_group_score(sources, domains, SYN_THRESHOLD, 'syn_flood')
        self.assertEqual(result['attack_type'], 'MULTIDOMAIN_DISTRIBUTED_ATTACK')
        self.assertEqual(result['weight'], 1.4)
        self.assertAlmostEqual(result['confidence'], 1.0, places=6)  # entropy*1.3 saturates at 1.0
        self.assertTrue(result['decides'])

    def test_same_sources_single_domain_gets_ddos_distributed_not_multidomain(self):
        sources = [34.569, 34.569, 26.887, 26.887, 19.205, 19.205]
        domains = ['enterprise'] * 6
        result = estimate_group_score(sources, domains, SYN_THRESHOLD, 'syn_flood')
        self.assertEqual(result['attack_type'], 'DDOS_DISTRIBUTED')
        self.assertEqual(result['weight'], 1.3)


class IsolatedVsMultidomainTests(unittest.TestCase):
    """Composition 3's central hypothesis: isolated mode scores each
    domain's own (small, sub-threshold, low-entropy) group separately and
    never detects, while multidomain mode merges all six sources into one
    high-entropy, over-threshold, distributed group and does."""

    def test_composition_3_isolated_never_detects_multidomain_does(self):
        per_domain = {
            'enterprise': [34.569, 34.569],
            'fixed': [26.887, 26.887],
            'mobile': [19.205, 19.205],
        }
        result = estimate_isolated_and_multidomain(per_domain, SYN_THRESHOLD, 'syn_flood')
        for domain_result in result['isolated'].values():
            self.assertIsNone(domain_result)
        self.assertIsNotNone(result['multidomain'])
        self.assertTrue(result['multidomain']['decides'])
        self.assertEqual(result['multidomain']['attack_type'], 'MULTIDOMAIN_DISTRIBUTED_ATTACK')

    def test_composition_2_both_isolated_and_multidomain_detect(self):
        per_domain = {
            'enterprise': [4.5 * SYN_THRESHOLD],
            'fixed': [0.3 * SYN_THRESHOLD],
            'peering': [0.3 * SYN_THRESHOLD],
        }
        result = estimate_isolated_and_multidomain(per_domain, SYN_THRESHOLD, 'syn_flood')
        self.assertIsNotNone(result['isolated']['enterprise'])
        self.assertTrue(result['isolated']['enterprise']['decides'])
        self.assertIsNone(result['isolated']['fixed'])
        self.assertIsNone(result['isolated']['peering'])
        self.assertIsNotNone(result['multidomain'])
        self.assertTrue(result['multidomain']['decides'])
        self.assertEqual(result['multidomain']['attack_type'], 'SYN_FLOOD')  # only 3 sources, below DIST_MIN_SOURCES


if __name__ == '__main__':
    unittest.main()
