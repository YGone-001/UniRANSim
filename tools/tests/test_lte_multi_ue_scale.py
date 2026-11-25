import importlib.util
import pathlib
import unittest

HARNESS_PATH = pathlib.Path(__file__).resolve().parents[1] / "lte-multi-ue-scale.py"
spec = importlib.util.spec_from_file_location("lte_multi_ue_scale", HARNESS_PATH)
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class MemoryModelTests(unittest.TestCase):
    def test_default_estimate_is_three_megabytes_per_ue(self):
        self.assertEqual(harness.HOST_MEMORY_INCREMENT_MB_PER_UE, 3.0)

    def test_rss_is_a_separate_observation(self):
        self.assertEqual(harness.PROCESS_RSS_MIB_PER_UE, 8.6)
        self.assertNotEqual(harness.HOST_MEMORY_INCREMENT_MB_PER_UE,
                            harness.PROCESS_RSS_MIB_PER_UE)

    def test_hard_floor_is_512_mb(self):
        self.assertEqual(harness.MIN_MEM_AVAILABLE_MB, 512)

    def test_precheck_allows_one_ue(self):
        result = harness.precheck(1, 1024.0, 3.0)
        self.assertEqual(result["decision"], harness.ALLOW)

    def test_precheck_allows_eight_ues(self):
        self.assertEqual(harness.precheck(8, 1024.0, 3.0)["decision"], harness.ALLOW)

    def test_precheck_allows_64_ues(self):
        self.assertEqual(harness.precheck(64, 2048.0, 3.0)["decision"], harness.ALLOW)

    def test_precheck_allows_128_ues(self):
        self.assertEqual(harness.precheck(128, 2048.0, 3.0)["decision"], harness.ALLOW)

    def test_precheck_allows_256_ues(self):
        self.assertEqual(harness.precheck(256, 2048.0, 3.0)["decision"], harness.ALLOW)

    def test_precheck_allows_512_ues_at_the_measured_budget(self):
        result = harness.precheck(512, 4836.0, 3.0)
        self.assertEqual(result["decision"], harness.ALLOW)
        self.assertEqual(result["estimated_ue_memory_mb"], 1536.0)
        self.assertGreaterEqual(result["projected_after_mb"], harness.MIN_MEM_AVAILABLE_MB)

    def test_precheck_blocks_when_the_reserve_is_crossed(self):
        result = harness.precheck(512, 1500.0, 3.0)
        self.assertEqual(result["decision"], harness.BLOCKED_RESOURCE_LIMIT)
        self.assertLess(result["projected_after_mb"], harness.MIN_MEM_AVAILABLE_MB)

    def test_precheck_counts_current_ues(self):
        result = harness.precheck(512, 3000.0, 3.0, current=256)
        self.assertEqual(result["remaining"], 256)
        self.assertEqual(result["estimated_ue_memory_mb"], 768.0)


class BatchGateTests(unittest.TestCase):
    def gate(self, **overrides):
        values = dict(current=0, target=512, available_mb=4096.0, estimate=3.0, batch=16)
        values.update(overrides)
        return harness.batch_gate(**values)

    def test_allows_a_batch_above_the_floor(self):
        self.assertEqual(self.gate()["decision"], harness.ALLOW)

    def test_stops_at_the_memory_hard_floor(self):
        self.assertEqual(self.gate(available_mb=500.0)["decision"],
                         harness.STOP_MEMORY_HARD_FLOOR)

    def test_stops_before_a_batch_would_cross_the_floor(self):
        # 520 - 16*3 = 472 < 512, while the current value is above the floor.
        self.assertEqual(self.gate(available_mb=520.0)["decision"],
                         harness.STOP_MEMORY_HARD_FLOOR)

    def test_background_page_activity_alone_does_not_stop(self):
        # The 4->256 run stopped on this: SwapUsed was flat and PSI was zero.
        self.assertEqual(self.gate(swap_out_delta_mb=8.0)["decision"], harness.ALLOW)
        self.assertEqual(self.gate(swap_in_delta_mb=2.0)["decision"], harness.ALLOW)

    def test_material_swap_used_growth_stops(self):
        self.assertEqual(self.gate(swap_used_delta_mb=100.0)["decision"],
                         harness.STOP_SWAP_PRESSURE)
        self.assertEqual(self.gate(swap_in_delta_mb=70.0, swap_used_delta_mb=2.0)["decision"],
                         harness.STOP_SWAP_PRESSURE)

    def test_background_page_out_with_small_growth_does_not_stop(self):
        # The 172-UE run stopped here: 26 MB page-out, 37 MB SwapUsed growth,
        # PSI 2.0/0.18 and UE PSS flat at 1.79 MB/UE.
        self.assertEqual(self.gate(swap_in_delta_mb=0.2, swap_out_delta_mb=26.1,
                                   swap_used_delta_mb=36.7, psi_some_avg10=1.99,
                                   psi_full_avg10=0.18)["decision"], harness.ALLOW)

    def test_material_paging_with_swap_growth_stops(self):
        self.assertEqual(self.gate(swap_in_delta_mb=20.0, swap_out_delta_mb=50.0,
                                   swap_used_delta_mb=16.0)["decision"],
                         harness.STOP_SWAP_PRESSURE)

    def test_pauses_on_material_memory_psi(self):
        self.assertEqual(self.gate(psi_some_avg10=40.0)["decision"],
                         harness.PAUSE_RESOURCE_PRESSURE)
        self.assertEqual(self.gate(psi_full_avg10=6.0)["decision"],
                         harness.PAUSE_RESOURCE_PRESSURE)

    def test_a_transient_psi_spike_does_not_stop(self):
        # The 5->256 run stopped here with 4.8 GB free and flat swap.
        self.assertEqual(self.gate(psi_some_avg10=2.61, psi_full_avg10=1.36)["decision"],
                         harness.ALLOW)

    def test_pauses_when_the_remaining_fleet_would_cross_the_reserve(self):
        self.assertEqual(self.gate(current=256, target=512, available_mb=900.0,
                                   batch=4)["decision"],
                         harness.PAUSE_RESOURCE_PRESSURE)

    def test_stops_on_epc_health_failure(self):
        self.assertEqual(self.gate(epc_healthy=False)["decision"],
                         harness.STOP_EPC_HEALTH_FAILURE)

    def test_gate_reports_the_projection(self):
        result = self.gate(current=256, target=512, available_mb=4096.0, batch=16)
        self.assertEqual(result["projected_after_batch_mb"], 4048.0)
        self.assertEqual(result["remaining_after_batch"], 240)


class IncrementAndAccountingTests(unittest.TestCase):
    def test_measured_increment(self):
        self.assertAlmostEqual(harness.measured_increment(3772.0, 3053.0, 256), 2.80859375)

    def test_stage_increment_uses_the_whole_fleet(self):
        # The 32-UE stage measured ~3.2 MB/UE cumulatively while a single
        # batch swung to 17.6 MB/UE from page cache.
        self.assertAlmostEqual(harness.stage_increment(4660.0, 4558.0, 32), 3.1875)
        self.assertEqual(harness.stage_increment(4660.0, 4700.0, 32), 0.0)

    def test_calibrated_estimate_needs_three_clean_samples(self):
        self.assertEqual(harness.calibrated_estimate([12.0, 12.0], 3.0), 3.0)
        self.assertEqual(harness.calibrated_estimate([12.0, 12.0, 12.0], 3.0), 12.0)

    def test_calibrated_estimate_ignores_a_single_outlier(self):
        # One 32.6 MB/UE sample among 3.0 samples must not ratchet the fleet.
        self.assertAlmostEqual(harness.calibrated_estimate([3.0, 3.2, 32.64, 3.1], 3.0), 3.15)
        self.assertNotEqual(harness.calibrated_estimate([3.0, 3.2, 32.64, 3.1], 3.0),
                            harness.ESTIMATE_CAP_MB_PER_UE)

    def test_calibrated_estimate_raises_for_a_sustained_increment(self):
        self.assertAlmostEqual(harness.calibrated_estimate([4.0, 4.5, 5.0, 4.8], 3.0), 4.65)

    def test_calibrated_estimate_is_bounded(self):
        self.assertEqual(harness.calibrated_estimate([0.1, 0.2, 0.3], 3.0),
                         harness.HOST_MEMORY_INCREMENT_MB_PER_UE)
        self.assertEqual(harness.calibrated_estimate([50.0, 60.0, 70.0], 3.0),
                         harness.ESTIMATE_CAP_MB_PER_UE)

    def test_calibrated_estimate_uses_the_recent_window(self):
        samples = [20.0, 20.0, 20.0, 3.0, 3.0, 3.0, 3.0]
        self.assertEqual(harness.calibrated_estimate(samples, 20.0),
                         harness.HOST_MEMORY_INCREMENT_MB_PER_UE)

    def test_calibrated_estimate_adopts_one_large_fleet_sample(self):
        # A 128-UE cumulative sample is stable enough to stand alone; the
        # small-fleet samples are not, which is why the run gates on
        # ESTIMATE_MIN_FLEET before adopting any.
        self.assertEqual(harness.ESTIMATE_MIN_FLEET, 128)
        self.assertEqual(harness.calibrated_estimate([3.6], 3.0, min_samples=1), 3.6)

    def test_background_change_confounds_a_batch(self):
        self.assertTrue(harness.background_confounded(50.0, 100.0))
        self.assertFalse(harness.background_confounded(1.0, 100.0))

    def test_batch_classification_records_failures(self):
        result = harness.classify_batch([1, 2, 3], [1, 3])
        self.assertEqual(result["started"], [1, 3])
        self.assertEqual(result["failed"], [2])

    def test_duplicate_start_is_refused(self):
        with self.assertRaises(RuntimeError):
            harness.assert_new_start({1: object()}, 1)
        harness.assert_new_start({1: object()}, 2)

    def test_missing_processes_reports_exited_ues(self):
        self.assertEqual(harness.missing_processes([1, 2, 3], [1, 3]), [2])
        self.assertEqual(harness.missing_processes([1, 2], [1, 2]), [])

    def test_policy_route_needs_both_the_rule_and_the_route(self):
        rule = "10001:\tfrom 10.80.0.3 lookup 10001\n"
        route = "10.98.0.1 dev d10u0010 scope link\n"
        self.assertTrue(harness.policy_route_present(rule, route, "10001", "10.98.0.1"))
        self.assertFalse(harness.policy_route_present(rule, "", "10001", "10.98.0.1"))
        self.assertFalse(harness.policy_route_present("", route, "10001", "10.98.0.1"))

    def test_policy_route_rejects_a_different_priority_or_endpoint(self):
        rule = "100010:\tfrom 10.80.0.3 lookup 100010\n"
        route = "10.99.0.1 dev d10u0010 scope link\n"
        self.assertFalse(harness.policy_route_present(rule, route, "10001", "10.98.0.1"))

    def test_median_uses_stable_samples(self):
        self.assertEqual(harness.median([3.0, 1.0, 2.0]), 2.0)

    def test_parse_meminfo_and_swap(self):
        text = ("MemTotal: 8000000 kB\nMemAvailable: 4000000 kB\nMemFree: 1000000 kB\n"
                "Cached: 2000000 kB\nSwapTotal: 4000000 kB\nSwapFree: 1000000 kB\n")
        values = harness.memory_from_meminfo(harness.parse_meminfo(text))
        self.assertAlmostEqual(values["mem_available_mb"], 3906.25)
        self.assertAlmostEqual(values["swap_used_mb"], 2929.6875)

    def test_parse_vmstat_and_pressure(self):
        self.assertEqual(harness.parse_vmstat("pswpin 10\npswpout 20\n")["pswpout"], 20)
        pressure = harness.parse_pressure("some avg10=1.50 avg60=0.00 avg300=0.00 total=1\n"
                                          "full avg10=0.50 avg60=0.00 avg300=0.00 total=0\n")
        self.assertEqual(pressure["some_avg10"], 1.5)
        self.assertEqual(pressure["full_avg10"], 0.5)


if __name__ == "__main__":
    unittest.main()
