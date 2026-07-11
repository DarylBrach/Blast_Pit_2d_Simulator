# Fitness Policy v35

All components are finite and constrained to `[0,1]`. Total fitness is a weighted sum: survival .30, food .10, water .12, damage avoidance .14, useful-work efficiency .08, reproduction .08, offspring survival .08, exploration .02, hydration/recovery .08.

Survival combines founder persistence, lineage trial persistence, population integral, and terminal population. Food, water, reproduction, and exploration use `x/(x+k)` smooth saturation. Damage avoidance decays with fire-contact share of lineage alive-time. Efficiency measures useful outcomes relative to total energy rather than rewarding motion. Offspring survival divides survived frames by possible frames accumulated after each birth, including time after an offspring dies. Hydration rewards time below the low-water threshold and penalizes severe-thirst exposure, preventing deliberate recovery cycling from dominating fitness.

Selection robustly combines median, worst trial, and minimum survival inside each suite before applying fixed suite weights.
