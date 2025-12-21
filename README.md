# Hardware Trojan Silence

This repository provides a small C++ circuit toolkit that can:
- Parse ISCAS-style `.bench` files into an internal circuit model
- Simulate and patch a trojaned circuit based on mismatching patterns
- Write circuits back to `.bench`
- Run ABC-based synthesis via EQN and compare area/level

## Build

Build all tools (each `src/*.cpp` becomes a binary under `bin/`):

```bash
make -C src
```

Clean build outputs:

```bash
make -C src clean
```

Outputs:
- `bin/` contains the executables
- `build/` contains object files

## Binaries

### `bin/main`

Compare golden vs trojan circuits, generate random patterns, apply fixes, and optionally write the patched trojan.

```bash
bin/main <golden_bench> <trojan_bench> [output_bench]
```

Notes:
- Uses OpenMP; control threads via `OMP_NUM_THREADS`.
- The default pattern count is large (see `src/main.cpp`).

### `bin/show`

Print area and level for a circuit.

```bash
bin/show <bench>
```

Example output:
```
area 3518 delay 43
```

### `bin/synthesis`

Run ABC optimization, parse EQN back into a circuit, and write a `.bench`.

```bash
bin/synthesis <input_bench> <output_bench> [--flow name]
bin/synthesis <input_bench> <output_bench> --list
```

Flows (built-in):
- `resyn2` (general purpose)
- `area` (rewrite/refactor focused)
- `delay` (more balance passes)

The tool prints:
```
original area level
<area> <level>
synth area level
<area> <level>
```

It also writes `output_bench.eqn` as an intermediate file.

## ABC setup

Make sure `abc` is available in `PATH`, or set `ABC_BIN`:

```bash
export ABC_BIN=/path/to/abc
```

Example:
```bash
bin/synthesis test.bench out.bench --flow resyn2
```

## Examples

Show circuit stats:
```bash
bin/show benchmarks/c7552.bench
```

Patch a trojaned circuit and save result:
```bash
bin/main benchmarks/c7552.bench trojaned_bench/c7552_trojan4.bench out.bench
```

Run synthesis with the area flow:
```bash
bin/synthesis out.bench out_opt.bench --flow area
```
