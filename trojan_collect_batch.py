import argparse
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Optional

from tqdm import tqdm


CONTAINER_BENCHMARKS = "/data/benchmarks"
CONTAINER_TROJANS = "/data/trojaned_bench"
CONTAINER_OUT = "/out"
DEFAULT_DOCKER_IMAGE = "ht-collect"
DEFAULT_DOCKER_BIN = "docker"
SUBDIR_ALLOWLIST = ["c880", "c2670", "c3540", "c5315", "c6288", "c7552"]


def _iter_bench_files(root: Path) -> list[Path]:
    if root.is_file():
        if root.suffix != ".bench":
            raise ValueError(f"Input file is not a .bench: {root}")
        return [root]
    if not root.exists():
        raise FileNotFoundError(f"Input path not found: {root}")
    return sorted(root.rglob("*.bench"))


def _build_bench_map(original_root: Path) -> dict[str, list[Path]]:
    bench_map: dict[str, list[Path]] = {}
    for path in original_root.rglob("*.bench"):
        bench_map.setdefault(path.stem, []).append(path)
    return bench_map


def _filter_trojan_files_by_subdir(
    trojan_files: list[Path], trojan_root: Path, allowlist: list[str]
) -> list[Path]:
    if not allowlist or trojan_root.is_file():
        return trojan_files
    allowed = set(allowlist)
    filtered: list[Path] = []
    for path in trojan_files:
        rel = path.relative_to(trojan_root)
        if len(rel.parts) >= 2 and rel.parts[0] in allowed:
            filtered.append(path)
    return filtered


def _unique_names(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            result.append(item)
            seen.add(item)
    return result


def _resolve_original_bench(trojan_path: Path, bench_map: dict[str, list[Path]]) -> Path:
    candidates = []
    parent_name = trojan_path.parent.name
    if parent_name:
        candidates.append(parent_name)
    stem = trojan_path.stem
    if "_trojan" in stem:
        candidates.append(stem.split("_trojan")[0])
    candidates.append(stem)
    for name in _unique_names(candidates):
        if name in bench_map:
            paths = bench_map[name]
            if len(paths) == 1:
                return paths[0]
            paths_str = ", ".join(path.as_posix() for path in paths)
            raise ValueError(f"Ambiguous original bench for '{name}': {paths_str}")
    tried = ", ".join(_unique_names(candidates))
    raise FileNotFoundError(
        f"No original .bench found for {trojan_path.as_posix()}. Tried: {tried}"
    )


def _container_path(host_path: Path, host_root: Path, container_root: str) -> str:
    rel = host_path.relative_to(host_root).as_posix()
    if rel == ".":
        return container_root
    return f"{container_root}/{rel}"


def _parse_rounds(
    raw: Optional[str], start_round: Optional[int], end_round: Optional[int]
) -> Optional[list[int]]:
    if raw:
        items = [item.strip() for item in raw.split(",")]
        rounds = [int(item) for item in items if item]
        if not rounds:
            raise ValueError("rounds is empty")
        return rounds
    if start_round is None and end_round is None:
        return None
    if start_round is None:
        start_round = 0
    if end_round is None:
        end_round = start_round
    if end_round < start_round:
        raise ValueError("end-round must be >= start-round")
    return list(range(start_round, end_round + 1))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch run ht-collect in Docker for all .bench files."
    )
    parser.add_argument(
        "--benchmarks_root",
        default="benchmarks",
        help="Host dir (or file) with golden .bench files mounted to /data/benchmarks.",
    )
    parser.add_argument(
        "--trojan_root",
        default="trojaned_bench",
        help="Host dir (or .bench file) to scan for trojaned benches.",
    )
    parser.add_argument(
        "--output_root",
        default="log",
        help="Host dir for JSON outputs; subdirs mirror trojan_root.",
    )
    parser.add_argument(
        "--rounds",
        default="",
        help="Comma-separated round list (e.g. 0,1,2). If empty, no --round is passed.",
    )
    parser.add_argument("--start-round", type=int, default=None)
    parser.add_argument("--end-round", type=int, default=None)
    parser.add_argument("--cpu", type=int, default=None)
    parser.add_argument("--docker_image", default=DEFAULT_DOCKER_IMAGE)
    parser.add_argument("--docker_bin", default=DEFAULT_DOCKER_BIN)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    rounds = _parse_rounds(args.rounds, args.start_round, args.end_round)

    trojan_path = Path(args.trojan_root).expanduser().resolve()
    trojan_files = _iter_bench_files(trojan_path)
    trojan_files = _filter_trojan_files_by_subdir(
        trojan_files, trojan_path, SUBDIR_ALLOWLIST
    )
    if not trojan_files:
        print(f"No .bench files found under {trojan_path.as_posix()}")
        return

    trojan_mount_root = trojan_path.parent if trojan_path.is_file() else trojan_path

    original_path = Path(args.benchmarks_root).expanduser().resolve()
    if not original_path.exists():
        raise FileNotFoundError(f"benchmarks_root not found: {original_path}")

    if original_path.is_file():
        if len(trojan_files) != 1:
            raise ValueError(
                "benchmarks_root is a file but multiple trojan benches were found."
            )
        original_mount_root = original_path.parent
        bench_map = {original_path.stem: [original_path]}
        fixed_original = original_path
    else:
        original_mount_root = original_path
        bench_map = _build_bench_map(original_mount_root)
        fixed_original = None

    if not bench_map:
        raise FileNotFoundError(
            f"No .bench files found under {original_mount_root.as_posix()}"
        )

    output_root = Path(args.output_root).expanduser().resolve()
    if output_root.exists() and output_root.is_file():
        raise ValueError(f"output_root must be a directory: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)

    job_rounds = rounds if rounds is not None else [None]
    total_jobs = len(trojan_files) * len(job_rounds)
    with tqdm(total=total_jobs, unit="bench") as pbar:
        for round_value in job_rounds:
            for trojan_file in trojan_files:
                rel_path = trojan_file.relative_to(trojan_mount_root)
                rel_dir = rel_path.parent
                if round_value is None:
                    label = rel_path.as_posix()
                else:
                    label = f"r{round_value} {rel_path.as_posix()}"
                pbar.set_description(label)

                if fixed_original is not None:
                    original_file = fixed_original
                else:
                    original_file = _resolve_original_bench(trojan_file, bench_map)

                output_dir_host = output_root / rel_dir
                output_dir_host.mkdir(parents=True, exist_ok=True)

                if rel_dir == Path("."):
                    output_dir_container = CONTAINER_OUT
                else:
                    output_dir_container = f"{CONTAINER_OUT}/{rel_dir.as_posix()}"
                cmd = [
                    args.docker_bin,
                    "run",
                    "--rm",
                    "-v",
                    f"{original_mount_root}:{CONTAINER_BENCHMARKS}",
                    "-v",
                    f"{trojan_mount_root}:{CONTAINER_TROJANS}",
                    "-v",
                    f"{output_root}:{CONTAINER_OUT}",
                    args.docker_image,
                    "--original_design",
                    _container_path(original_file, original_mount_root, CONTAINER_BENCHMARKS),
                    "--benchmark_trojan",
                    _container_path(trojan_file, trojan_mount_root, CONTAINER_TROJANS),
                    "--output_dir",
                    output_dir_container,
                ]
                if round_value is not None:
                    cmd += ["--round", str(round_value)]
                if args.cpu:
                    cmd += ["--cpu", str(args.cpu)]

                if args.dry_run:
                    print(" ".join(shlex.quote(str(part)) for part in cmd))
                    pbar.update(1)
                    continue

                if args.verbose:
                    result = subprocess.run(cmd)
                    if result.returncode != 0:
                        pbar.close()
                        print(f"Failed: {trojan_file.as_posix()}")
                        return
                else:
                    result = subprocess.run(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    if result.returncode != 0:
                        pbar.close()
                        print(f"Failed: {trojan_file.as_posix()}")
                        if result.stdout:
                            print(result.stdout)
                        if result.stderr:
                            print(result.stderr, file=sys.stderr)
                        return

                pbar.update(1)


if __name__ == "__main__":
    main()
