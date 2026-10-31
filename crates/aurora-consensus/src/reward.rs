//! Experimental account-block issuance and fee distribution.
use std::fmt;

use aurora_core::{
    accounts::AccountId,
    amount::{Amount, AmountError, MAX_UNITS},
    state::{AccountLedger, StateError},
};

const CAP_UNITS: u64 = MAX_UNITS;
/// One part per million of unissued supply per block, rounded down to atomic units.
pub const EMISSION_DENOMINATOR: u64 = 1_000_000;
/// Consensus fingerprint domain for this consensus-critical emission recurrence.
pub const EMISSION_SCHEDULE_ID: &[u8] = b"proportional-remaining-1e6-v1";
/// A one-unit floor guarantees that the strict cap is eventually reachable.
pub const MIN_BLOCK_ISSUANCE_UNITS: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardParams {
    /// The network's fixed treasury account. Its identity is part of the chain configuration.
    pub treasury_account: AccountId,
    pub enabled: bool,
}

impl RewardParams {
    pub const fn disabled() -> Self {
        Self {
            treasury_account: AccountId([0; 32]),
            enabled: false,
        }
    }
    pub const fn experimental_testnet(treasury_account: AccountId) -> Self {
        Self {
            treasury_account,
            enabled: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewardError {
    MissingMiner,
    UnexpectedMiner,
    Amount(AmountError),
    State(StateError),
}
impl fmt::Display for RewardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RewardError {}
impl From<AmountError> for RewardError {
    fn from(e: AmountError) -> Self {
        Self::Amount(e)
    }
}
impl From<StateError> for RewardError {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}

/// Returns block issuance proportional to the gross supply still unissued.
/// The recurrence is deterministic integer arithmetic:
/// max(1 atomic unit, floor((cap - issued) / 1,000,000)), clipped to the exact remainder.
/// This starts at 500 AUR, decays smoothly with remaining supply, and eventually reaches the cap.
pub fn scheduled_issuance(issued: Amount) -> Amount {
    let remaining = CAP_UNITS.saturating_sub(issued.to_units());
    if remaining == 0 {
        return Amount::ZERO;
    }
    let proposed = (remaining / EMISSION_DENOMINATOR).max(MIN_BLOCK_ISSUANCE_UNITS);
    Amount::from_units(proposed.min(remaining)).expect("clipped reward is within amount cap")
}

/// Applies deterministic issuance and fees after transfers have been validated on `ledger`.
/// Five percent of issuance goes to treasury (floor); half of fees goes to miner (floor),
/// and the remainder is burned. Mutations are atomic.
pub fn apply_block_reward(
    ledger: &mut AccountLedger,
    miner: Option<AccountId>,
    total_fees: Amount,
    params: RewardParams,
) -> Result<(), RewardError> {
    if !params.enabled {
        return if miner.is_some() {
            Err(RewardError::UnexpectedMiner)
        } else {
            Ok(())
        };
    }
    let issuance = scheduled_issuance(ledger.total_issued());
    let miner_fees = Amount::from_units(total_fees.to_units() / 2)?;
    let has_payout = issuance != Amount::ZERO || miner_fees != Amount::ZERO;
    let miner = match (miner, has_payout) {
        (Some(miner), _) => miner,
        (None, true) => return Err(RewardError::MissingMiner),
        (None, false) => return Ok(()),
    };
    let treasury_issuance = Amount::from_units(issuance.to_units() / 20)?;
    let miner_issuance = Amount::from_units(issuance.to_units() - treasury_issuance.to_units())?;

    let mut candidate = ledger.clone();
    candidate.credit_issuance(miner, miner_issuance)?;
    candidate.credit_issuance(params.treasury_account, treasury_issuance)?;
    candidate.credit_fee_reward(miner, miner_fees)?;
    *ledger = candidate;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aurora_core::{amount::UNITS_PER_COIN, network::NetworkId};

    #[test]
    fn proportional_emission_starts_at_500_and_slows_with_remaining_supply() {
        let first = scheduled_issuance(Amount::ZERO).to_units();
        assert_eq!(first, 500 * UNITS_PER_COIN);
        assert_eq!(
            scheduled_issuance(Amount::from_units(first).unwrap()).to_units(),
            (CAP_UNITS - first) / EMISSION_DENOMINATOR
        );
        let half_issued = Amount::from_units(CAP_UNITS / 2).unwrap();
        assert_eq!(
            scheduled_issuance(half_issued).to_units(),
            (CAP_UNITS / 2) / EMISSION_DENOMINATOR
        );
        assert!(
            scheduled_issuance(half_issued).to_units()
                < scheduled_issuance(Amount::ZERO).to_units()
        );
    }

    #[test]
    fn proportional_emission_is_integer_bounded_and_reaches_the_strict_cap() {
        assert_eq!(
            scheduled_issuance(Amount::from_units(CAP_UNITS - 1).unwrap()).to_units(),
            MIN_BLOCK_ISSUANCE_UNITS
        );
        assert_eq!(
            scheduled_issuance(Amount::from_units(CAP_UNITS).unwrap()),
            Amount::ZERO
        );
    }

    #[test]
    fn emission_changes_smoothly_without_threshold_jumps() {
        let before = Amount::from_units(5_000_000 * UNITS_PER_COIN - 1).unwrap();
        let after = Amount::from_units(5_000_000 * UNITS_PER_COIN + 1).unwrap();
        assert!(scheduled_issuance(before).to_units() >= scheduled_issuance(after).to_units());
        assert!(scheduled_issuance(before).to_units() - scheduled_issuance(after).to_units() <= 1);
    }

    /// Cross-check the Python fast-forward vectors by actually applying the
    /// production reward function at every issuance step, without mining blocks.
    /// Only the post-cap milestones are skipped, because rewards are then zero.
    #[test]
    fn emission_million_height_vectors_match_the_real_reward_function() {
        let mut issued = 0u64;
        let mut treasury = 0u64;
        let mut height = 0u64;

        while issued < CAP_UNITS {
            let reward = scheduled_issuance(Amount::from_units(issued).unwrap()).to_units();
            assert!(reward > 0, "issuance stopped before reaching the cap");
            issued = issued.checked_add(reward).expect("gross supply overflow");
            treasury = treasury
                .checked_add(reward / 20)
                .expect("treasury overflow");
            height += 1;
            assert!(issued <= CAP_UNITS, "issuance exceeded cap");
            assert!(
                height <= 30_000_000,
                "emission unexpectedly failed to converge"
            );

            if height == 10_000_000 {
                assert_eq!(issued, 49_997_730_014_361_895);
                assert_eq!(treasury, 2_499_886_495_968_424);
            }
        }

        assert_eq!(height, 26_212_491);
        assert_eq!(issued, CAP_UNITS);
        assert_eq!(treasury, 2_499_999_988_792_316);
        assert_eq!(issued - treasury, 47_500_000_011_207_684);
        // These are arithmetic checkpoints, not 100M or 500M stored blocks:
        // no additional issuance occurs at either future height.
        for future_height in [100_000_000u64, 500_000_000] {
            assert!(future_height > height);
            assert_eq!(
                scheduled_issuance(Amount::from_units(issued).unwrap()),
                Amount::ZERO
            );
        }
    }

    #[test]
    fn fee_split_rounds_miner_down_and_burns_remainder() {
        let miner = AccountId([1; 32]);
        let treasury = AccountId([2; 32]);
        let mut ledger = AccountLedger::new(NetworkId::Regtest);
        let fees = Amount::from_units(5).unwrap();
        apply_block_reward(
            &mut ledger,
            Some(miner),
            fees,
            RewardParams::experimental_testnet(treasury),
        )
        .unwrap();
        assert_eq!(
            ledger.account(miner).balance.to_units(),
            475 * UNITS_PER_COIN + 2
        );
        assert_eq!(
            ledger.account(treasury).balance.to_units(),
            25 * UNITS_PER_COIN
        );
        assert_eq!(ledger.total_issued().to_units(), 500 * UNITS_PER_COIN);
        assert_eq!(
            ledger.account(miner).balance.to_units() + ledger.account(treasury).balance.to_units(),
            500 * UNITS_PER_COIN + 2
        );
    }
}
