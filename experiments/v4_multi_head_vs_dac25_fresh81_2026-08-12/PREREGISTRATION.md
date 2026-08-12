# V4 fresh-81 multi-head versus DAC25-inspired preregistration

This comparison is frozen before either arm is executed.  It uses the
`paper_fresh_stratified_81` profile in `source_manifest.json`; all 13 cases in
the earlier diagnostic `smoke_extended` profile are excluded.  Selection uses
only immutable dataset metadata and SHA-256 ranking, never a prior repair
status, runtime, patch, or QoR result.

## Cohort

- 81 unique GT-ready cases: 48 core, 12 held-out OOD, 12 shared-trigger, and
  all 9 remaining N=5 stress cases.
- Trojan-count strata N=1/2/3/5: 16/28/28/9.
- Size strata small/medium/large-OOD: 52/17/12.
- Topology strata disjoint/shared-trigger: 69/12.
- The manifest records the exact selection rule, selected-ID digest, source
  indices, experiment-matrix digest, and all input artifact identities.

## Frozen arms

1. `multi-head-z3-pb-formal`
   - binary SHA-256
     `534b5eb47e069e0a947efd5d2a8daa1b3605ebc0c85d950f1d7814d9f605342f`;
   - Z3-PB formal timeout/rounds/batch = 10000 ms / 5 / 5;
   - multi-head enabled, with at most 20 SAT-driven rebuilds per head.
2. `dac25-inspired-k2`
   - binary SHA-256
     `ddaced4a3d969f341ec69da7fa2475a1ea3bdc7310513972a2f30e621048da2c`;
   - selector timeout 30000 ms, candidate limit 32, maximum target-set
     cardinality 2, at most 4 feasible sets, RunECO timeout 60 seconds.

Both arms use one job, a 300-second outer case timeout, a 60-second external
CEC timeout, ABC SHA-256
`627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3`,
and `show` SHA-256
`4517349556e40cf3468dc37802a4ceb8430df53c0447a2e36cf889f4fd9a4082`.
They run sequentially to avoid CPU and memory contention.

## Outcomes and analysis

- Primary outcome: count and rate of external-ABC-CEC-equivalent patches over
  all 81 scheduled cases.
- Secondary: status transition table and success stratified by circuit, N,
  trigger size, topology, phase, and size class.
- Runtime comparisons use paired cases and disclose timeout censoring.
- AIG AND count and topological level are compared only on paired CEC-PASS
  cases; they are not mapped cell area or physical delay.
- All PASS artifacts are replayed with the pinned ABC before publication.

The DAC arm is our exact, public-information **DAC'25-inspired baseline**, not
the unavailable author implementation.  A later higher-cardinality or grouped
DAC extension must be reported as a separate arm and cannot replace this
frozen K=2 baseline after outcomes are observed.
