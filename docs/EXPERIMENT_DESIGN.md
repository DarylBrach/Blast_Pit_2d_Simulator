# Experiment Design

Each generation evaluates every candidate on common standard and water/fire challenge seeds. Standard and challenge samples are aggregated independently and combined at fixed 70/30 weight. Trial counts therefore change precision, not suite importance.

The top three selection candidates are evaluated on a fixed development-confirmation suite. Repeated use can adapt the Hall of Fame to those seeds, so this is not described as untouched validation. A terminal audit suite remains inaccessible to selection and development confirmation. Its deterministic seeds are workflow holdouts rather than cryptographic secrets.

RNG domains for environment and lineage are separated. Candidates see common seeds within a generation. Worker results are restored to canonical task order before aggregation. The simulation senses all creatures from a pre-action snapshot and then applies actions in creature-ID order, preserving deterministic resource contention.
