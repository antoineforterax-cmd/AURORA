#!/usr/bin/env python3
"""Independent integer checks for the emission simulator (no mined blocks)."""
import unittest

from emission_sim import CAP, simulate_at_heights


def naive_supply(height: int, cap: int, denominator: int) -> dict[str, int]:
    remaining = cap
    treasury = 0
    cap_reached_at = 0
    for block in range(1, height + 1):
        issuance = min(remaining, max(1, remaining // denominator)) if remaining else 0
        remaining -= issuance
        treasury += issuance // 20
        if not remaining and not cap_reached_at:
            cap_reached_at = block
    issued = cap - remaining
    return {
        "height": height,
        "issued_units": issued,
        "treasury_units": treasury,
        "miner_units": issued - treasury,
        "remaining_units": remaining,
        "cap_reached_at": cap_reached_at,
    }


class EmissionScaleTests(unittest.TestCase):
    def test_interval_acceleration_matches_naive_on_small_models(self):
        for cap, denominator in ((51, 3), (100, 7), (2_117, 21), (10_000, 101)):
            heights = [0, 1, 2, 3, 7, 9, 21, 60, 250, 500, 1_000]
            accelerated = simulate_at_heights(
                heights, cap=cap, denominator=denominator
            )
            for height, snapshot in zip(heights, accelerated):
                with self.subTest(cap=cap, denominator=denominator, height=height):
                    self.assertEqual(snapshot, naive_supply(height, cap, denominator))

    def test_million_scale_exact_expected_supply(self):
        heights = [1, 10_000_000, 100_000_000, 500_000_000]
        first, ten_million, hundred_million, five_hundred_million = (
            simulate_at_heights(heights)
        )
        self.assertEqual(first["issued_units"], 500 * 100_000_000)
        self.assertEqual(first["treasury_units"], 25 * 100_000_000)
        self.assertEqual(ten_million["issued_units"], 49_997_730_014_361_895)
        self.assertEqual(ten_million["treasury_units"], 2_499_886_495_968_424)
        self.assertEqual(ten_million["cap_reached_at"], 0)
        self.assertEqual(hundred_million["issued_units"], CAP)
        self.assertEqual(hundred_million["remaining_units"], 0)
        self.assertEqual(hundred_million["cap_reached_at"], 26_212_491)
        self.assertEqual(hundred_million["treasury_units"], 2_499_999_988_792_316)
        self.assertEqual(hundred_million["issued_units"], five_hundred_million["issued_units"])
        self.assertEqual(hundred_million["treasury_units"], five_hundred_million["treasury_units"])
        self.assertEqual(hundred_million["cap_reached_at"], five_hundred_million["cap_reached_at"])
        for state in (first, ten_million, hundred_million, five_hundred_million):
            self.assertEqual(
                state["issued_units"],
                state["treasury_units"] + state["miner_units"],
            )
            self.assertLessEqual(state["issued_units"], CAP)
            self.assertGreaterEqual(state["remaining_units"], 0)

    def test_invalid_inputs_are_rejected(self):
        for kwargs in ({"cap": 0}, {"denominator": 0}, {"cap": -1}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    simulate_at_heights([1], **kwargs)
        with self.assertRaises(ValueError):
            simulate_at_heights([-1])


if __name__ == "__main__":
    unittest.main()
