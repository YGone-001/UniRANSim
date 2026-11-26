import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

TOOL_PATH = pathlib.Path(__file__).resolve().parents[1] / "lte-paced-traffic.py"
spec = importlib.util.spec_from_file_location("lte_paced_traffic", TOOL_PATH)
paced = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paced)


class ScheduleTests(unittest.TestCase):
    def test_schedule_is_monotonic_at_the_requested_rate(self):
        offsets = paced.schedule_offsets_ns(100.0, 10)
        self.assertEqual(len(offsets), 10)
        self.assertEqual(offsets[0], 0)
        for a, b in zip(offsets, offsets[1:]):
            self.assertLess(a, b)
        self.assertAlmostEqual(offsets[-1] / 1e9, 0.09, places=9)

    def test_zero_rate_yields_a_single_burst(self):
        self.assertEqual(paced.schedule_offsets_ns(0.0, 4), [0, 0, 0, 0])

    def test_plan_counts_include_the_warmup(self):
        warm, measured, total = paced.plan_counts(100.0, 5000, 60000)
        self.assertEqual((warm, measured, total), (500, 6000, 6500))

    def test_per_ue_rate_divides_the_aggregate(self):
        self.assertAlmostEqual(paced.per_ue_rate(64, 6400.0), 100.0)
        with self.assertRaises(ValueError):
            paced.per_ue_rate(0, 100.0)


class PayloadTests(unittest.TestCase):
    def test_payload_round_trips_with_its_tag(self):
        wire = paced.payload_for(tag=7, seq=42, size=64)
        self.assertEqual(len(wire), 64)
        self.assertEqual(paced.parse_payload(wire), (42, 7))

    def test_a_wrong_tag_is_visible(self):
        wire = paced.payload_for(tag=7, seq=42, size=64)
        seq, tag = paced.parse_payload(wire)
        self.assertEqual(seq, 42)
        self.assertNotEqual(tag, 8)

    def test_corruption_is_refused(self):
        wire = bytearray(paced.payload_for(tag=7, seq=42, size=64))
        wire[20] ^= 0xFF
        self.assertIsNone(paced.parse_payload(bytes(wire)))

    def test_short_payload_is_refused(self):
        self.assertIsNone(paced.parse_payload(b"\x00" * 8))

    def test_fnv_is_stable(self):
        self.assertEqual(paced.fnv1a(b""), 2166136261)
        self.assertEqual(paced.fnv1a(b"a"), 0xE40C292C)


class MetricTests(unittest.TestCase):
    def test_nearest_rank_percentiles(self):
        values = list(range(1, 101))
        self.assertEqual(paced.percentile(values, 50), 50)
        self.assertEqual(paced.percentile(values, 95), 95)
        self.assertEqual(paced.percentile(values, 99), 99)
        self.assertIsNone(paced.percentile([], 95))

    def test_ips_are_read_from_the_ue_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            for index in (1, 2, 3):
                with open(os.path.join(directory, f"ue{index}.log"), "w") as handle:
                    handle.write(f"x IPv4=10.80.0.{index} tail\n")
            ips = paced.read_ips(directory, 3)
        self.assertEqual(ips, {1: "10.80.0.1", 2: "10.80.0.2", 3: "10.80.0.3"})


if __name__ == "__main__":
    unittest.main()
