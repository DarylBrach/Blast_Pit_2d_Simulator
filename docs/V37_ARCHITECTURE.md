# v37 Architecture

The v35 environment remains authoritative. v36 provides actor-compatible archive policies. v37 migrates their actors into a new `robust-policy-v37` schema with a critic width of 24: 19 local sensors plus hydration mean, low-water fraction, near-fire fraction, population ratio, and recovery-opportunity rate.

Each candidate receives one standard and three water/fire challenge PPO episodes. Candidate selection uses 40% standard and 60% challenge expected fitness, blended with 60% lower-tail CVaR and an extinction penalty. Bootstrap parents are the protected v36 HoF plus challenge-ranked archive specialists.
