#!/usr/bin/env python3
"""AURORA experimental issuance simulator, not consensus code.

Default output compares the current proportional schedule with historical tier
candidates. With --heights, fast-forward over intervals with the same integer
reward to inspect millions of conceptual blocks without creating a blockchain.
All amounts use integer atomic units. Time estimates are not forecasts.
"""

from argparse import ArgumentParser
from dataclasses import dataclass
from math import ceil

DECIMALS = 100_000_000
CAP_AUR = 500_000_000
CAP = CAP_AUR * DECIMALS
BLOCK_TARGET_SECONDS = 120
SECONDS_PER_YEAR = 365.2425 * 24 * 60 * 60


@dataclass(frozen=True)
class Tier:
    until_supply_aur: int
    reward_aur: int


CANDIDATES = {
    "slow_start_50": [
        Tier(5_000_000, 50),
        Tier(25_000_000, 30),
        Tier(75_000_000, 20),
        Tier(175_000_000, 10),
        Tier(CAP_AUR, 1),
    ],
    "balanced_100": [
        Tier(5_000_000, 100),
        Tier(25_000_000, 60),
        Tier(75_000_000, 30),
        Tier(175_000_000, 10),
        Tier(CAP_AUR, 1),
    ],
    "historical_fast_start_500": [
        Tier(5_000_000, 500),
        Tier(25_000_000, 100),
        Tier(75_000_000, 60),
        Tier(175_000_000, 30),
        Tier(350_000_000, 10),
        Tier(CAP_AUR, 1),
    ],
}


def validate_tiers(tiers: list[Tier]) -> None:
    previous_threshold = 0
    previous_reward = None
    for tier in tiers:
        if not previous_threshold < tier.until_supply_aur <= CAP_AUR:
            raise ValueError("Thresholds must strictly increase and not exceed cap")
        if tier.reward_aur <= 0:
            raise ValueError("Rewards must be positive")
        if previous_reward is not None and tier.reward_aur > previous_reward:
            raise ValueError("Rewards must not increase between tiers")
        previous_threshold = tier.until_supply_aur
        previous_reward = tier.reward_aur
    if not tiers or tiers[-1].until_supply_aur != CAP_AUR:
        raise ValueError("Last tier must end at the strict cap")


def years_for_blocks(blocks: int) -> float:
    return blocks * BLOCK_TARGET_SECONDS / SECONDS_PER_YEAR

def format_aur(units: int) -> str:
    whole, fraction = divmod(units, DECIMALS)
    return f"{whole}.{fraction:08d}"


def simulate(name: str, tiers: list[Tier]) -> dict[str, int | float | str]:
    validate_tiers(tiers)
    issued = 0
    blocks = 0
    treasury = 0
    miner_issuance = 0
    print(f"\n## {name}")
    print("threshold_AUR,reward_AUR,blocks_in_tier,elapsed_years,cumulative_issued_AUR,treasury_AUR,miner_issuance_AUR")

    for tier in tiers:
        threshold = tier.until_supply_aur * DECIMALS
        if issued >= threshold:
            continue
        reward = tier.reward_aur * DECIMALS
        # Supply is checked before each block. A block can cross a threshold;
        # the new tier applies to the following block.
        blocks_in_tier = min(ceil((threshold - issued) / reward), ceil((CAP - issued) / reward))
        if blocks_in_tier <= 0:
            continue
        gross = min(blocks_in_tier * reward, CAP - issued)
        # All candidate rewards and the cap are whole AUR, so 5% is exact
        # in atomic units. This calculation is equivalent to per-block floors.
        treasury_part = (gross // 20)
        miner_part = gross - treasury_part
        issued += gross
        blocks += blocks_in_tier
        treasury += treasury_part
        miner_issuance += miner_part
        print(
            f"{tier.until_supply_aur},{tier.reward_aur},{blocks_in_tier},"
            f"{years_for_blocks(blocks):.4f},{issued / DECIMALS:.8f},"
            f"{treasury / DECIMALS:.8f},{miner_issuance / DECIMALS:.8f}"
        )
        if issued >= CAP:
            break

    assert 0 <= issued <= CAP
    assert treasury + miner_issuance == issued
    print(
        f"TOTAL: issued={issued / DECIMALS:.8f} AUR, "
        f"treasury={treasury / DECIMALS:.8f} AUR, "
        f"miner_issuance={miner_issuance / DECIMALS:.8f} AUR, "
        f"blocks={blocks}, years={years_for_blocks(blocks):.4f}"
    )
    if issued < CAP:
        print(f"REMAINDER: {CAP_AUR - issued / DECIMALS:.8f} AUR not issued")
    print("NOTE: fixed target-time assumption; excludes fees, orphan blocks, "
          "hashrate, market value, and miner costs.")
    return {"name": name, "issued": issued, "blocks": blocks, "years": years_for_blocks(blocks)}



def simulate_proportional_remaining() -> dict[str, int | float | str]:
    """Simulate the current integer consensus rule at the 60-second testnet target."""
    denominator = 1_000_000
    target_seconds = 60
    issued = 0
    blocks = 0
    treasury = 0
    miner_issuance = 0
    milestones = [CAP // 2, CAP * 9 // 10, CAP - 1_000_000]
    reached: list[tuple[int, int]] = []
    first_reward = 0

    while issued < CAP:
        remaining = CAP - issued
        reward = min(remaining, max(1, remaining // denominator))
        if blocks == 0:
            first_reward = reward
        treasury_part = reward // 20
        issued += reward
        treasury += treasury_part
        miner_issuance += reward - treasury_part
        blocks += 1
        while milestones and issued >= milestones[0]:
            reached.append((milestones.pop(0), blocks))

    years = blocks * target_seconds / SECONDS_PER_YEAR
    print(f"\n## Current consensus: proportional remaining supply")
    print(f"first block reward: {format_aur(first_reward)} AUR")
    for supply, milestone_blocks in reached:
        print(
            f"reached {format_aur(supply)} issued AUR after "
            f"{milestone_blocks:,} blocks ({milestone_blocks * target_seconds / SECONDS_PER_YEAR:.2f} years)"
        )
    print(
        f"cap: {format_aur(issued)} AUR after {blocks:,} blocks "
        f"({years:.2f} years at 60 seconds/block)"
    )
    print(
        f"treasury={format_aur(treasury)} AUR; "
        f"miner issuance={format_aur(miner_issuance)} AUR"
    )
    assert issued == CAP
    assert treasury + miner_issuance == CAP
    return {"name": "proportional-remaining", "issued": issued, "blocks": blocks, "years": years}


def simulate_at_heights(
    heights: list[int],
    *,
    cap: int = CAP,
    denominator: int = 1_000_000,
) -> list[dict[str, int]]:
    """Exactly replay issuance in constant-reward intervals, not by mining.

    In a reward interval, floor(remaining / denominator) is constant. The
    first block that lowers this quotient is included in the interval.
    Treasury floor is applied PER BLOCK, not to the interval's aggregate.

    The result is exact integer arithmetic for the same reward recurrence as
    scheduled_issuance in reward.rs; it is not a P2P/storage stress test.
    """
    if cap <= 0 or denominator <= 0:
        raise ValueError("cap and denominator must be positive")
    if any(height < 0 for height in heights):
        raise ValueError("block heights must be non-negative")
    snapshots: dict[int, dict[str, int]] = {}
    remaining = cap
    blocks = 0
    treasury = 0
    cap_reached_at = 0
    for height in sorted(set(heights)):
        while blocks < height:
            if remaining == 0:
                blocks = height
                break
            reward = max(1, remaining // denominator)
            if reward == 1:
                # The one-unit floor persists until the cap is exhausted.
                batch = min(height - blocks, remaining)
            else:
                # Include the block that first crosses below this quotient.
                batch = min(
                    height - blocks, (remaining % denominator) // reward + 1
                )
            remaining -= batch * reward
            treasury += batch * (reward // 20)
            blocks += batch
            if remaining == 0 and cap_reached_at == 0:
                cap_reached_at = blocks
        issued = cap - remaining
        snapshots[height] = {
            "height": height,
            "issued_units": issued,
            "treasury_units": treasury,
            "miner_units": issued - treasury,
            "remaining_units": remaining,
            "cap_reached_at": cap_reached_at,
        }
    return [snapshots[height] for height in heights]


def print_height_simulation(heights: list[int]) -> None:
    print("height,issued_AUR,treasury_AUR,miner_AUR,remaining_AUR,cap_reached_at")
    for state in simulate_at_heights(heights):
        print(
            f"{state['height']},"
            f"{format_aur(state['issued_units'])},"
            f"{format_aur(state['treasury_units'])},"
            f"{format_aur(state['miner_units'])},"
            f"{format_aur(state['remaining_units'])},"
            f"{state['cap_reached_at'] or 'not_yet'}"
        )
    print(
        "NOTE: mathematical issuance recurrence only; no blocks mined,"
        " stored, signed, validated, or sent over TCP."
    )


def main() -> None:
    current = simulate_proportional_remaining()
    results = [simulate(name, tiers) for name, tiers in CANDIDATES.items()]
    print("\n## Comparison")
    for result in results:
        print(f"{result['name']}: {result['blocks']:,} blocks; {result['years']:.2f} years")


if __name__ == "__main__":
    parser = ArgumentParser(description="Research-only AURORA emission simulator")
    parser.add_argument(
        "--heights",
        nargs="+",
        type=int,
        metavar="BLOCKS",
        help="simulate issuance at selected block heights (e.g. 10000000 100000000 500000000)",
    )
    arguments = parser.parse_args()
    if arguments.heights:
        print_height_simulation(arguments.heights)
    else:
        main()
