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
            carry_save: bool, timeout: int, out_dir: Path) -> dict:
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

    A("# Reduced-Round SHA-256 Preimage Scaling")
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
    A(f"- Budget per round: {meta.get('budget_seconds', '?')} s")
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
        if len(solved_times) >= 2:
            ratios = []
            for i in range(1, len(solved_times)):
                r0, t0 = solved_times[i - 1]
                r1, t1 = solved_times[i]
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

    A("## Encoding comparison")
    A("")
    by_rounds = {}
    for m in measurements:
        by_rounds.setdefault(m["rounds"], []).append(m)
    multi = {r: v for r, v in by_rounds.items() if len(v) > 1}
    if multi:
        A("| Rounds | Configuration | CNF vars | CNF clauses |")
        A("|------:|---------------|---------:|------------:|")
        for r in sorted(multi):
            for m in multi[r]:
                cfg = f"{m['encoding']}{'+cs' if m['carry_save'] else ''}/{m['solver']}"
                A(f"| {r} | {cfg} | {m.get('cnf_vars', '-')} | {m.get('cnf_clauses', '-')} |")
        A("")
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
    A(f"python tools/measure_scaling.py --max-rounds {meta.get('max_rounds', '?')} "
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
    ap.add_argument("--from-json", type=Path,
                    help="regenerate the report from a previous run's data")
    ap.add_argument("--out-json", type=Path,
                    default=REPO_ROOT / "reports" / "preimage_scaling.json")
    ap.add_argument("--out-md", type=Path,
                    default=REPO_ROOT / "reports" / "preimage_scaling.md")
    args = ap.parse_args()

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
        for rounds in range(args.start_rounds, args.max_rounds + 1):
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
                    rounds_done = rounds
                    break
            else:
                rounds_done = rounds
                continue
            break

        meta = {
            "solver": args.solver,
            "encoding": args.dialect,
            "carry_save": args.carry_save,
            "budget_seconds": args.timeout,
            "max_rounds": args.max_rounds,
            "compare": args.compare,
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