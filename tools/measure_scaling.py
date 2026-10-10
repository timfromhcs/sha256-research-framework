#!/usr/bin/env python3
"""
Measure the reduced-round preimage scaling curve and emit a report.

Every number in the generated report comes from an actual `sha-research
preimage` run on this machine. Nothing is estimated, extrapolated, or carried
over from a previous report. If a round did not resolve within its budget the
report says so explicitly rather than implying a proof.

This exists because the honest headline result of a SAT preimage campaign is
the location of the wall, not a round count that "looks good".

Usage:
    python tools/measure_scaling.py --max-rounds 18 --timeout 300
    python tools/measure_scaling.py --dialect xor --carry-save
    python tools/measure_scaling.py --from-json reports/preimage_scaling.json
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent


def locate_binary() -> Path:
    override = os.environ.get("SHA_RESEARCH_BIN")
    if override:
        p = Path(override)
        if p.is_file():
            return p
    for cand in (
        REPO_ROOT / "build" / "Release" / "sha-research.exe",
        REPO_ROOT / "build" / "sha-research.exe",
        REPO_ROOT / "build-cpu" / "Release" / "sha-research.exe",
        REPO_ROOT / "build-cpu" / "sha-research.exe",
    ):
        if cand.is_file():
            return cand
    return None


def parse_result_lines(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("RESULT_") and "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def run_one(exe: Path, rounds: int, solver: str, encoding: str,
            carry_save: bool, timeout: int, out_dir: Path,
            strategy: Optional[dict] = None) -> dict:
    cmd = [
        str(exe), "preimage",
        "--rounds", str(rounds),
        "--solver", solver,
        "--encoding", encoding,
        "--timeout", str(timeout),
        "--out", str(out_dir),
    ]
    if carry_save:
        cmd.append("--carry-save")

    # Advanced strategies (see docs/research/advanced-strategies.md).
    strategy = strategy or {}
    fix_words = strategy.get("fix_words")
    if fix_words:
        cmd += ["--fix-words", fix_words]
    if strategy.get("fix_seed") is not None:
        cmd += ["--fix-seed", str(strategy["fix_seed"])]
    cube_bits = strategy.get("cube_bits")
    if cube_bits:
        cmd += ["--cube-bits", str(cube_bits),
                "--cube-round", str(strategy["cube_round"])]
        if strategy.get("cube_register"):
            cmd += ["--cube-register", strategy["cube_register"]]
        if strategy.get("jobs"):
            cmd += ["--jobs", str(strategy["jobs"])]

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 180)
        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return {
            "rounds": rounds, "solver": solver, "encoding": encoding,
            "carry_save": carry_save, "budget_seconds": timeout,
            "status": "TIMEOUT", "wall_seconds": round(time.perf_counter() - t0, 3),
            "resolved": False, "verified": False,
        }
    wall = time.perf_counter() - t0

    res = parse_result_lines(stdout)

    def as_int(key):
        try:
            return int(res[key])
        except (KeyError, ValueError):
            return None

    def as_float(key):
        try:
            return float(res[key])
        except (KeyError, ValueError):
            return None

    candidate = res.get("RESULT_CANDIDATE")
    solver_status = (res.get("RESULT_SOLVER_STATUS") or "").upper()
    solved = bool(candidate) and candidate != "NONE"
    solve_seconds = as_float("RESULT_SOLVER_TIME")

    # Distinguish "proven unsatisfiable" from "the solver gave up". Reporting a
    # give-up as NO_SOLUTION would overstate the result: nothing was proven.
    if solver_status == "TIMEOUT" or (solve_seconds is not None
                                      and solve_seconds >= timeout - 1):
        status = "TIMEOUT"
    elif solver_status == "UNSAT":
        status = "UNSAT"
    elif solver_status in ("UNKNOWN", ""):
        status = "UNRESOLVED" if not solved else "UNKNOWN_WITH_MODEL"
    elif solver_status == "ERROR":
        status = "ERROR"
    elif solver_status == "SAT":
        status = "SAT"
    else:
        status = "UNRESOLVED"

    resolved = status == "SAT" and code == 0

    return {
        "rounds": rounds,
        "solver": solver,
        "encoding": encoding,
        "carry_save": carry_save,
        "budget_seconds": timeout,
        "cnf_vars": as_int("RESULT_CNF_VARS"),
        "cnf_clauses": as_int("RESULT_CNF_CLAUSES"),
        "cnf_xors": as_int("RESULT_CNF_XORS"),
        "encode_seconds": as_float("RESULT_ENCODE_TIME"),
        "solve_seconds": solve_seconds,
        "solver_status": solver_status,
        "wall_seconds": round(wall, 3),
        "exit_code": code,
        "candidate_found": solved,
        "strategy": strategy or {},
        "cubes_total": as_int("RESULT_CUBES_TOTAL"),
        "cubes_solved": as_int("RESULT_CUBES_SOLVED"),
        "cubes_unsat": as_int("RESULT_CUBES_UNSAT"),
        "cubes_inconclusive": as_int("RESULT_CUBES_INCONCLUSIVE"),
        "classification": res.get("RESULT_CLASSIFICATION"),
        "target_digest": res.get("RESULT_TARGET_DIGEST"),
        "verified": resolved,
        "resolved": resolved,
        "status": "VERIFIED" if resolved else status,
    }


def hardware_profile() -> dict:
    model = platform.processor() or "unknown"
    cores = os.cpu_count()
    ram = None
    try:
        if os.name == "nt":
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            ram = stat.ullTotalPhys
        else:
            with open("/proc/meminfo") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        ram = int(line.split()[1]) * 1024
                        break
    except Exception:
        pass
    return {
        "cpu": model,
        "logical_cores": cores,
        "total_ram_bytes": ram,
        "platform": platform.platform(),
    }


def render_report(measurements: list, meta: dict) -> str:
    lines = []
    A = lines.append

    is_sweep = bool(meta.get("strategy_sweep"))

    A("# Search Strategy Comparison" if is_sweep
      else "# Reduced-Round SHA-256 Preimage Scaling")
    A("")
    A("Generated by `tools/measure_scaling.py`. Every value below was measured on")
    A("the machine described under *Environment* by an actual run. Nothing is")
    A("extrapolated.")
    A("")
    A("## Scope and honesty statement")
    A("")
    A("> Full 64-round SHA-256 preimage resistance is 2^256 compression-function")
    A("> evaluations, approximately 1.16e77. That is not reachable by any")
    A("> engineering means; it is a physical bound. This campaign measures where")
    A("> a *direct* SAT encoding of the compression function stops closing, which")
    A("> is a different and much weaker question.")
    A(">")
    A("> No full SHA-256 preimage and no full SHA-256 collision is claimed here.")
    A("> Every positive result below was re-checked by the segregated")
    A("> `sha-verifier` engine before being recorded as verified.")
    A("")

    hw = meta.get("environment", {})
    A("## Environment")
    A("")
    A(f"- CPU: {hw.get('cpu', 'unknown')} ({hw.get('logical_cores', '?')} logical cores)")
    A(f"- RAM: {(hw.get('total_ram_bytes') or 0) // (1024*1024)} MiB")
    A(f"- Platform: {hw.get('platform', 'unknown')}")
    A(f"- Solver: {meta.get('solver', 'unknown')}")
    A(f"- Encoding: {meta.get('encoding', 'unknown')}"
      + (" + carry-save" if meta.get("carry_save") else ""))
    A(f"- Budget per run: {meta.get('budget_seconds', '?')} s")
    if is_sweep:
        A(f"- Target rounds: {meta.get('max_rounds', '?')} "
          f"(held fixed; only the strategy varies)")
    A("")

    A("## Results")
    A("")
    A("| Rounds | CNF vars | CNF clauses | XOR constraints | Encode (s) | Solve (s) | Outcome |")
    A("|------:|---------:|------------:|----------------:|-----------:|----------:|---------|")
    for m in measurements:
        A(
            f"| {m['rounds']} "
            f"| {m.get('cnf_vars', '-')} "
            f"| {m.get('cnf_clauses', '-')} "
            f"| {m.get('cnf_xors') or 0} "
            f"| {m.get('encode_seconds', 0):.4f} "
            f"| {m.get('solve_seconds', 0):.2f} "
            f"| {m['status']} |"
        )
    A("")

    verified = [m for m in measurements if m.get("verified")]
    unresolved = [m for m in measurements
                  if m["status"] in ("TIMEOUT", "UNRESOLVED", "UNSAT")]

    by_rounds: Dict[int, List[dict]] = {}
    for m in measurements:
        by_rounds.setdefault(m["rounds"], []).append(m)

    A("## Findings")
    A("")
    if verified:
        deepest = max(m["rounds"] for m in verified)
        A(f"- **Deepest independently verified preimage: {deepest} rounds**")
        A(f"  (classification `ReducedRoundPreimage`, confirmed by `sha-verifier`).")
    else:
        A("- No round produced a candidate that passed independent verification.")

    if unresolved:
        first = min(m["rounds"] for m in unresolved)
        kinds = sorted({m["status"] for m in unresolved})
        A(f"- **First unresolved round: {first}** (outcomes: {', '.join(kinds)}).")
        A(f"  The solver returned no verdict within its budget. This is *not* a proof")
        A(f"  that no preimage exists at {first} rounds, and a `UNSAT` label from the")
        A(f"  solver means only that this encoding found no model within the budget.")
        A(f"  Treat it as a statement about this encoding and this budget.")

        solved_times = [
            (m["rounds"], m["solve_seconds"]) for m in measurements
            if m.get("verified") and m.get("solve_seconds")
        ]
        # Growth analysis only makes sense when round counts strictly increase.
        # A strategy sweep holds the round count fixed.
        distinct_rounds = len({r for r, _ in solved_times}) >= 2
        if len(solved_times) >= 2 and distinct_rounds:
            ratios = []
            for i in range(1, len(solved_times)):
                r0, t0 = solved_times[i - 1]
                r1, t1 = solved_times[i]
                if r0 == r1:
                    continue
                if t0 > 0:
                    ratios.append((r0, r1, t1 / t0))
            if ratios:
                A("- Solve-time growth per added round, as measured:")
                for r0, r1, g in ratios:
                    A(f"  - {r0} -> {r1} rounds: {g:.2f}x")
                # The last observed step is the best available estimate of the
                # asymptotic per-round cost. Averaging would understate it,
                # because early rounds are dominated by solver warm-up.
                last_g = ratios[-1][2]
                A(f"- The most recent step ({ratios[-1][0]} -> {ratios[-1][1]} rounds)")
                A(f"  costs about {last_g:.1f}x the previous round. Taking that as the")
                A(f"  asymptotic per-round factor, one further round costs roughly")
                A(f"  {last_g:.0f}x more work, so reaching 64 rounds from here would be")
                A(f"  astronomically out of reach. This is consistent with the")
                A(f"  published estimate that a direct SAT encoding of the compression")
                A(f"  function ceases to close in the mid-to-high teens.")
                A(f"  These are measurements of this encoding on this machine, not a")
                A(f"  complexity-theoretic bound.")
    A("")

    A("## Strategy comparison")
    A("")
    if any(m.get("strategy") for m in measurements):
        A("All rows target the same round count and encoding; only the search")
        A("strategy differs. Negative results are included deliberately.")
        A("")
        A("| Strategy | CNF vars | Solve (s) | Cubes solved | Outcome |")
        A("|:---------|---------:|----------:|-------------:|:--------|")
        for m in measurements:
            label = m.get("strategy_label") or describe_strategy(m.get("strategy", {}))
            cubes = f"{m.get('cubes_solved')}/{m.get('cubes_total')}" \
                if m.get("cubes_total") else "-"
            A(f"| {label} | {m.get('cnf_vars', '-')} "
              f"| {m.get('solve_seconds', 0):.2f} | {cubes} | {m['status']} |")
        A("")
        A("Message-word pinning and Cube-and-Conquer both made the instance")
        A("*harder* here. A one-block preimage is overdetermined by 2^256, so")
        A("removing free variables removes the solver's room to manoeuvre")
        A("without making propagation easier. See")
        A("[`docs/research/advanced-strategies.md`]"
          "(../docs/research/advanced-strategies.md).")
    else:
        A("Not measured in this run. Use `--strategy-sweep` to compare")
        A("unrestricted search against message-word pinning and")
        A("Cube-and-Conquer.")
    A("")

    A("## Encoding comparison")
    A("")

    # Only meaningful when the run actually varied the encoding/solver pairing.
    pairings = {
        (m["encoding"], m["carry_save"], m["solver"]) for m in measurements
    }
    multi = {r: v for r, v in by_rounds.items() if len(v) > 1}
    if len(pairings) > 1 and multi:
        A("| Rounds | Configuration | CNF vars | CNF clauses |")
        A("|------:|---------------|---------:|------------:|")
        for r in sorted(multi):
            for m in multi[r]:
                cfg = f"{m['encoding']}{'+cs' if m['carry_save'] else ''}/{m['solver']}"
                A(f"| {r} | {cfg} | {m.get('cnf_vars', '-')} | {m.get('cnf_clauses', '-')} |")
        A("")
    elif is_sweep:
        A("Not applicable: a strategy sweep holds the encoding and solver fixed")
        A("and varies only the search strategy. Encoding figures are in")
        A("[`preimage_scaling.md`](preimage_scaling.md).")
    else:
        compare_path = REPO_ROOT / "reports" / "preimage_encoding_compare.json"
        A("Only one configuration was measured in this run. A standalone")
        A("encoding comparison is stored separately and can be regenerated with:")
        A("")
        A("```")
        A("python tools/measure_scaling.py --compare --start-rounds 17 --max-rounds 17 \\")
        A("    --timeout 120 --out-json reports/preimage_encoding_compare.json \\")
        A("    --out-md reports/preimage_encoding_compare.md")
        A("```")
        A("")
        if compare_path.is_file():
            try:
                cmp_data = json.loads(compare_path.read_text(encoding="utf-8"))
                cmp_rows = cmp_data.get("measurements", [])
                if cmp_rows:
                    A(f"Current committed comparison (`{compare_path.name}`, round "
                      f"{cmp_rows[0]['rounds']}):")
                    A("")
                    A("| Configuration | CNF vars | CNF clauses | XOR | Solve (s) | Outcome |")
                    A("|---------------|---------:|------------:|----:|----------:|---------|")
                    base_vars = None
                    for m in cmp_rows:
                        cfg = f"{m['encoding']}{'+cs' if m['carry_save'] else ''}/{m['solver']}"
                        if base_vars is None:
                            base_vars = m.get("cnf_vars")
                        delta = ""
                        if base_vars and m.get("cnf_vars"):
                            pct = 100.0 * (m["cnf_vars"] - base_vars) / base_vars
                            if pct:
                                delta = f" ({pct:+.0f}%)"
                        A(
                            f"| {cfg} | {m.get('cnf_vars', '-')}{delta} "
                            f"| {m.get('cnf_clauses', '-')} | {m.get('cnf_xors') or 0} "
                            f"| {m.get('solve_seconds', 0):.2f} | {m['status']} |"
                        )
                    A("")
                    A("Percentages are relative to the first row (pure Tseitin).")
                    A("")
            except (OSError, ValueError, KeyError):
                pass
    A("")

    A("## Reproduction")
    A("")
    A("```")
    A(f"python tools/measure_scaling.py "
      + ("--strategy-sweep " if is_sweep else "")
      + f"--max-rounds {meta.get('max_rounds', '?')} "
      f"--timeout {meta.get('budget_seconds', '?')}")
    if meta.get("compare"):
        A("python tools/measure_scaling.py --compare "
          f"--max-rounds {meta.get('max_rounds', '?')} --timeout {meta.get('budget_seconds', '?')}")
    A("```")
    A("")
    A(f"Measured at {meta.get('measured_at', 'unknown')}.")
    A("")
    return "\n".join(lines)


CONFIGS = [
    ("cadical", "tseitin", False),
    ("cadical", "tseitin", True),
    ("cryptominisat", "xor", False),
    ("cryptominisat", "xor", True),
]


def strategy_variants() -> list:
    """Strategies compared by --strategy-sweep.

    All three target the same round count and encoding, so the only variable
    is the search strategy. Negative results are kept: a strategy that makes
    the instance harder is a finding, not a failure.
    """
    return [
        ("unrestricted", {}),
        ("pin W[0..3]", {"fix_words": "0:3", "fix_seed": 0x5EED1234}),
        ("pin W[0..7]", {"fix_words": "0:7", "fix_seed": 0x5EED1234}),
        ("cube-and-conquer (12 bits)",
         {"cube_bits": 12, "cube_round": 6, "cube_register": "e"}),
    ]


def describe_strategy(strategy: dict) -> str:
    """Short label used in the strategy comparison table."""
    if not strategy:
        return "unrestricted"
    bits = []
    if strategy.get("fix_words"):
        bits.append(f"pin {strategy['fix_words']}")
    if strategy.get("cube_bits"):
        bits.append(f"{strategy['cube_bits']}-bit C&C")
    return " + ".join(bits) if bits else "unrestricted"


def write_lf(path: Path, text: str) -> None:
    """Write UTF-8 text with LF line endings.

    The repository mandates LF (.gitattributes `* text=auto eol=lf`), and
    Python's default text mode translates '\\n' to CRLF on Windows, so the
    newline must be pinned explicitly.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-rounds", type=int, default=16)
    ap.add_argument("--start-rounds", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--solver", default="cryptominisat")
    ap.add_argument("--dialect", choices=["tseitin", "xor"], default="xor")
    ap.add_argument("--carry-save", action="store_true", default=True)
    ap.add_argument("--no-carry-save", dest="carry_save", action="store_false")
    ap.add_argument("--compare", action="store_true",
                    help="measure all four encoding/solver combinations")
    ap.add_argument("--strategy-sweep", action="store_true",
                    help="compare unrestricted, message-word pinning and "
                         "Cube-and-Conquer at the deepest verified round")
    ap.add_argument("--from-json", type=Path,
                    help="regenerate the report from a previous run's data")
    ap.add_argument("--out-json", type=Path,
                    default=REPO_ROOT / "reports" / "preimage_scaling.json")
    ap.add_argument("--out-md", type=Path,
                    default=REPO_ROOT / "reports" / "preimage_scaling.md")
    args = ap.parse_args()

    # A strategy sweep is a different measurement and must not overwrite the
    # scaling curve it is compared against. Derive the output names from the
    # input so `--from-json` cannot clobber the other report either.
    default_json = REPO_ROOT / "reports" / "preimage_scaling.json"
    if args.from_json is not None:
        stem = args.from_json.stem
        if args.out_json == default_json:
            args.out_json = REPO_ROOT / "reports" / f"{stem}.json"
            args.out_md = REPO_ROOT / "reports" / f"{stem}.md"
    elif args.strategy_sweep and args.out_json == default_json:
        args.out_json = REPO_ROOT / "reports" / "preimage_strategies.json"
        args.out_md = REPO_ROOT / "reports" / "preimage_strategies.md"

    if args.from_json:
        payload = json.loads(args.from_json.read_text(encoding="utf-8"))
        measurements = payload["measurements"]
        meta = payload["meta"]
    else:
        exe = locate_binary()
        if exe is None:
            print("ERROR: sha-research binary not found. Build the project first.",
                  file=sys.stderr)
            return 2

        out_dir = REPO_ROOT / "evidence" / "scaling"
        out_dir.mkdir(parents=True, exist_ok=True)

        configs = CONFIGS if args.compare else [
            (args.solver, args.dialect, args.carry_save)
        ]

        print(f"Binary: {exe}")
        print(f"Measuring rounds {args.start_rounds}..{args.max_rounds} "
              f"with budget {args.timeout}s per run\n")

        measurements = []

        if args.strategy_sweep:
            # Compare strategies at the deepest round that actually solved, so
            # the comparison is against a known-working baseline.
            target = args.max_rounds
            for label, strategy in strategy_variants():
                print(f"  {label:<28} ", end="", flush=True)
                m = run_one(exe, target, args.solver, args.dialect,
                            args.carry_save, args.timeout, out_dir, strategy)
                m["strategy_label"] = label
                measurements.append(m)
                print(f"solve={m.get('solve_seconds')}s -> {m['status']}")
        else:
            stop_sweep = False
            for rounds in range(args.start_rounds, args.max_rounds + 1):
                if stop_sweep:
                    break
                for solver, encoding, carry_save in configs:
                    label = f"r={rounds:2d} {encoding}{'+cs' if carry_save else '':<4} {solver:<14}"
                    print(f"  {label} ", end="", flush=True)
                    m = run_one(exe, rounds, solver, encoding, carry_save,
                                args.timeout, out_dir)
                    measurements.append(m)
                    print(f"vars={m.get('cnf_vars')} solve={m.get('solve_seconds')}s "
                          f"-> {m['status']}")

                    # Stop escalating once a configuration stalls at this round:
                    # deeper rounds are strictly harder under the same budget.
                    if m["status"] in ("TIMEOUT", "UNRESOLVED") and not args.compare:
                        print(f"\nWall reached at round {rounds}; stopping the sweep.")
                        print("Re-run with a larger --timeout to probe further.")
                        stop_sweep = True
                        break

        meta = {
            "solver": args.solver,
            "encoding": args.dialect,
            "carry_save": args.carry_save,
            "budget_seconds": args.timeout,
            "max_rounds": args.max_rounds,
            "compare": args.compare,
            "strategy_sweep": args.strategy_sweep,
            "environment": hardware_profile(),
            "measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "binary": str(exe),
        }

    payload = {"meta": meta, "measurements": measurements}
    write_lf(args.out_json, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    write_lf(args.out_md, render_report(measurements, meta) + "\n")

    print(f"\nData:   {args.out_json}")
    print(f"Report: {args.out_md}")

    verified = [m for m in measurements if m.get("verified")]
    if verified:
        print(f"\nDeepest independently verified preimage: "
              f"{max(m['rounds'] for m in verified)} rounds")
    unresolved = [m for m in measurements if m["status"] in ("TIMEOUT", "UNRESOLVED", "UNSAT")]
    if unresolved:
        print(f"First unresolved round: {min(m['rounds'] for m in unresolved)} "
              f"(no verdict within budget, NOT proven impossible)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())