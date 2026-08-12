# V4 DAC25-inspired comparison provenance

This experiment uses the exact 13-case `smoke_extended` profile from the V4
manifest. The manifest SHA-256 is
`a85a6a75260a9ff659d91ec4bc50a432e1343979418e94a24c581448fbacee82`.
Golden and Trojan inputs were compared by size and SHA-256 across the formal
and DAC worktrees before analysis.

The DAC arm was executed from clean commit
`d77339e5ef9a3bad2d8f2a4a693f585404e9002b` with:

- binary SHA-256 `ddaced4a3d969f341ec69da7fa2475a1ea3bdc7310513972a2f30e621048da2c`;
- runner SHA-256 `b8e947e6d09cee55e5b662da46fe8b44f64525e88b8867a5b27620491a12f769`;
- selector timeout 30,000 ms, candidate limit 32, maximum target-set size 2,
  maximum retained feasible sets 4, and per-`runeco` timeout 60 seconds;
- outer main timeout 300 seconds, external CEC timeout 60 seconds, and one job.

The pinned ABC SHA-256 for patch synthesis, final CEC, independent CEC replay,
and normalized AIG measurement is
`627ee77136889096c2d8aa11ef9adffb666504867f29508180ac10fc596093e3`.

The Z3 arm used frozen binary SHA-256
`2bebfa7eadefbcbda545d255dbd26bfa2da85a7adeb0097bffd9d36a61668b41`.
Its records identify source commit
`2d7dcc8cd9cfefe7aa60f07e3cc97ef09b89c0b3` with `dirty=True`. The
executable identity is fixed, but the dirty source state is a provenance
limitation and is not presented as a clean-source reproduction.

The runner CSV snapshots were mechanically normalized from CRLF to LF for a
clean Git representation; parsing and field values are unchanged. The source
CSV hashes before normalization were `844e4d1e...bb2fb0` (DAC),
`9bf44381...e7fc3` (Z3 shard 1), and `088e4ed3...14dc6` (Z3 shard 2).

Tracked snapshot identities:

| Source | SHA-256 |
|---|---|
| `raw/dac/results.csv` | `99b0b74ea61e764729390d4dd41d4bf5630d8ba71cb43f914345f31e1792e82e` |
| `raw/dac/run_context.json` | `b3d8846b984a41b2690b2ae94fefe279cd37838252d36cf6cb316ed1d6c77495` |
| `raw/z3_on_01/results.csv` | `da2ec3960eb741d2b3a02c95221223890b69337491d9bdb93589c1ad3176ca61` |
| `raw/z3_on_01/run_context.json` | `c65a6e787d17f71e12a7c499564269f5df7bb650c92187eb1fdeb11890bb4404` |
| `raw/z3_on_02/results.csv` | `f00642f79d8ccd4cd6cd9949ba8940502bdac993a573cb18e478d5e77d55677e` |
| `raw/z3_on_02/run_context.json` | `390f149e02ec5f6dafc7bea5adb931c5be096cb1cd00cdce1e160d59948ab593` |
| `raw/z3_union/results.csv` | `f51a3ce49b84b984da10caf19198601e422cfd2307ffd9c46afac3da2da0ecd0` |
| `raw/source_manifest.json` | `a85a6a75260a9ff659d91ec4bc50a432e1343979418e94a24c581448fbacee82` |

The analyzer independently replayed CEC for all five recorded PASS artifacts,
audited 79 recorded artifact identities without mismatch, and measured QoR
only after every relevant netlist was read and strashed by the pinned ABC.
The large netlists, patched artifacts, and per-run logs remain in ignored
`validation/` storage; reproducing the CEC and AIG replay requires those
artifacts. The tracked snapshots are sufficient to audit the selected cohort,
commands, treatment configuration, statuses, and derived CSV inputs.
