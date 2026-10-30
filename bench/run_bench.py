#!/usr/bin/env python3
"""SLiMe 파서 벤치마크: C++ Parser vs wireshark_parser(train.py + tshark).

각 케이스를 warmup 1회 + N회 실행하고, 프로세스 트리 전체의
wall time / CPU(user+sys) / 최대 RSS 합계를 측정한다.
"""
import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CPP_BIN = ROOT / "Parser" / "build" / "parser"
TRAIN_PY = ROOT / "wireshark_parser" / "train.py"
TSHARK = ROOT / "wireshark" / "build" / "run" / "tshark"
def process_table():
    """{pid: (ppid, rss_bytes)}. /proc 없는 macOS에서도 동작하도록 ps 사용."""
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,rss="],
                         capture_output=True, text=True, check=True).stdout
    table = {}
    for line in out.splitlines():
        pid, ppid, rss_kb = map(int, line.split())
        table[pid] = (ppid, rss_kb * 1024)
    return table


def tree_rss(root_pid):
    """root_pid와 모든 자손의 RSS 합계(bytes)."""
    table = process_table()
    kids = {}
    for pid, (ppid, _) in table.items():
        kids.setdefault(ppid, []).append(pid)
    stack, total = [root_pid], 0
    while stack:
        pid = stack.pop()
        if pid in table:
            total += table[pid][1]
        stack.extend(kids.get(pid, []))
    return total


def run_once(cmd, cwd, env=None, interval=0.02):
    before = os.times()
    t0 = time.perf_counter()
    # stderr를 PIPE로 받으면 폴링 중 아무도 읽지 않아 64KB에서 자식이 write()에 막힌다(deadlock).
    with tempfile.TemporaryFile() as errf:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env,
                                stdout=subprocess.DEVNULL, stderr=errf)
        peak = 0
        while proc.poll() is None:
            peak = max(peak, tree_rss(proc.pid))
            time.sleep(interval)
        wall = time.perf_counter() - t0
        after = os.times()
        errf.seek(0)
        err = errf.read().decode(errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"exit {proc.returncode}: {' '.join(map(str, cmd))}\n{err[-2000:]}")
    cpu = (after.children_user - before.children_user) + (after.children_system - before.children_system)
    return {"wall": wall, "cpu": cpu, "rss_mb": peak / 2**20, "stderr": err}


def count_packets(pcap):
    out = subprocess.run([str(TSHARK), "-r", str(pcap), "-T", "fields", "-e", "frame.number"],
                         capture_output=True, text=True, check=True).stdout
    return len(out.split())


def csv_rows(outdir):
    rows = 0
    for f in Path(outdir).glob("*.csv"):
        with open(f, "rb") as fh:
            rows += sum(1 for _ in fh) - 1
    return rows


def tshark_fields():
    src = (ROOT / "wireshark_parser" / "parser_common.py").read_text()
    return re.findall(r'"-e",\s*"([^"]+)"', src)


def cases(pcap, outbase, threads, runs, ws_runs):
    for t in threads:
        out = outbase / f"cpp_t{t}"
        yield (f"cpp (threads={t})", out, runs,
               [str(CPP_BIN), "-p", str(pcap), "-o", str(out), "--threads", str(t)],
               ROOT / "Parser")
    out = outbase / "wireshark"
    yield ("wireshark (train.py)", out, ws_runs,
           [sys.executable, str(TRAIN_PY), "-i", str(pcap), "-o", str(out), "-t", str(TSHARK)],
           ROOT / "wireshark_parser")
    # tshark 단독 비용(파이썬 파싱 제외) 분리용: train.py와 같은 -e 필드/옵션 사용
    yield ("tshark only (-T json)", None, ws_runs,
           ["sh", "-c", f"{TSHARK} -r {pcap} -T json {' '.join('-e ' + f for f in tshark_fields())} -l > /dev/null"],
           ROOT)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", type=Path)
    ap.add_argument("-n", "--runs", type=int, default=5)
    ap.add_argument("--ws-runs", type=int, default=1, help="wireshark/tshark 케이스 반복 수")
    ap.add_argument("--threads", default="1,2,4")
    ap.add_argument("-o", "--out", type=Path, default=ROOT / "results")
    args = ap.parse_args()

    pcap = args.pcap.resolve()
    threads = [int(x) for x in args.threads.split(",")]
    outbase = args.out / pcap.stem
    outbase.mkdir(parents=True, exist_ok=True)
    npkt = count_packets(pcap)
    print(f"# {pcap.name}: {npkt} packets, {pcap.stat().st_size / 2**20:.1f} MiB, runs={args.runs}")

    summary = {"pcap": pcap.name, "packets": npkt, "size_bytes": pcap.stat().st_size,
               "runs": args.runs, "cases": []}
    for name, out, runs, cmd, cwd in cases(pcap, outbase, threads, args.runs, args.ws_runs):
        samples = []
        warmup = 1 if runs > 1 else 0
        for i in range(runs + warmup):
            if out:
                shutil.rmtree(out, ignore_errors=True)
            r = run_once(cmd, cwd)
            if i >= warmup:
                samples.append(r)
        wall = statistics.median(s["wall"] for s in samples)
        res = {
            "name": name,
            "runs": runs,
            "wall_median": wall,
            "wall_min": min(s["wall"] for s in samples),
            "wall_max": max(s["wall"] for s in samples),
            "cpu_median": statistics.median(s["cpu"] for s in samples),
            "rss_mb_max": max(s["rss_mb"] for s in samples),
            "pps": npkt / wall,
            "csv_rows": csv_rows(out) if out else None,
            "output_dir": str(out) if out else None,
        }
        summary["cases"].append(res)
        print(f"{name:24s} wall {wall:7.2f}s  ({res['wall_min']:.2f}-{res['wall_max']:.2f})  "
              f"cpu {res['cpu_median']:7.2f}s  rss {res['rss_mb_max']:7.1f}MiB  "
              f"{res['pps']:9.0f} pps  rows {res['csv_rows']}", flush=True)

    (outbase / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
