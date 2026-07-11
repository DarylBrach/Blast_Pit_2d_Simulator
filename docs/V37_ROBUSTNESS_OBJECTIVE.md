# v37 Robustness Objective

- Challenge reward multiplier: 2.0 for water, recovery, and fire-contact terms.
- Early-extinction terminal penalty: 0.75 once per affected episode.
- CVaR alpha: worst 25% of episode returns.
- CVaR blend: 60%; expected-return contribution: 40%.
- Challenge selection weight: 60%.
- PPO rollout ratio: 3 challenge to 1 standard.

The critic context is pre-action and contains no future information. The actor ABI remains the v35 19-sensor contract.
