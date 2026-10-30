#!/usr/bin/env python3
"""두 파서의 CSV 출력을 순서와 무관하게 비교한다.

timestamp 기준으로 두 파일을 스트리밍 병합하고, 같은 timestamp 그룹 안에서
(protocol, 5-tuple, seq, ack)가 같은 행끼리 짝지어 필드별 불일치를 센다.
assets 파일이 없으면 비는 자산 매핑 필드는 기본으로 제외한다.
"""
import argparse
import collections
import csv
import itertools
import json
import sys

PAIR_KEY = ("protocol", "sip", "sp", "dip", "dp", "sq", "ak")
DEFAULT_SKIP = ("src_asset", "dst_asset")


def groups(path, ts_order):
    """timestamp가 같은 연속 행을 묶어 (ts, rows)로 반환한다."""
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.reader(f)
        header = next(r)
        yield header
        last = ""
        for ts, rows in itertools.groupby(r, key=lambda row: row[0]):
            if ts < last:
                ts_order["out_of_order"] += 1
            last = ts
            yield ts, list(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a", help="기준 CSV (예: C++)")
    ap.add_argument("b", help="비교 CSV (예: wireshark)")
    ap.add_argument("--keep-description", action="store_true")
    ap.add_argument("--examples", type=int, default=3)
    ap.add_argument("--json", help="결과 JSON 저장 경로")
    args = ap.parse_args()

    oa, ob = collections.Counter(), collections.Counter()
    ga, gb = groups(args.a, oa), groups(args.b, ob)
    ha, hb = next(ga), next(gb)
    common = [h for h in ha if h in hb]
    skip = set(DEFAULT_SKIP)
    if not args.keep_description:
        skip |= {h for h in common if h.endswith(".description")}
    cols = [h for h in common if h not in skip]
    ia = {h: i for i, h in enumerate(ha)}
    ib = {h: i for i, h in enumerate(hb)}
    key_a = lambda row: tuple(row[ia[k]] for k in PAIR_KEY)
    key_b = lambda row: tuple(row[ib[k]] for k in PAIR_KEY)

    st = collections.Counter()
    field_diff = collections.Counter()
    proto_a, proto_b = collections.Counter(), collections.Counter()
    proto_pair = collections.Counter()  # 같은 패킷인데 protocol 분류가 다른 경우
    examples = collections.defaultdict(list)

    def compare_group(rows_a, rows_b):
        for row in rows_a:
            proto_a[row[ia["protocol"]]] += 1
        for row in rows_b:
            proto_b[row[ib["protocol"]]] += 1
        pool = collections.defaultdict(list)
        for row in rows_b:
            pool[key_b(row)].append(row)
        unmatched_a = []
        for row in rows_a:
            cand = pool.get(key_a(row))
            if not cand:
                unmatched_a.append(row)
                continue
            # 후보 중 불일치 필드가 가장 적은 행과 짝짓기 (multi-row 대응)
            best = min(range(len(cand)), key=lambda j: sum(
                row[ia[c]] != cand[j][ib[c]] for c in cols))
            other = cand.pop(best)
            st["paired"] += 1
            diffs = [c for c in cols if row[ia[c]] != other[ib[c]]]
            if diffs:
                st["paired_with_diff"] += 1
            else:
                st["identical"] += 1
            for c in diffs:
                field_diff[c] += 1
                if len(examples[c]) < args.examples:
                    examples[c].append({"ts": row[0], "proto": row[ia["protocol"]],
                                        "a": row[ia[c]], "b": other[ib[c]]})
        rest_b = [row for rows in pool.values() for row in rows]
        # 키가 달라 못 짝지은 행: 5-tuple만으로 다시 짝지어 protocol/seq 차이 확인
        loose = collections.defaultdict(list)
        for row in rest_b:
            loose[tuple(row[ib[k]] for k in PAIR_KEY[1:5])].append(row)
        for row in unmatched_a:
            cand = loose.get(tuple(row[ia[k]] for k in PAIR_KEY[1:5]))
            if cand:
                other = cand.pop(0)
                rest_b.remove(other)
                st["loose_paired"] += 1
                proto_pair[(row[ia["protocol"]], other[ib["protocol"]])] += 1
            else:
                st["only_a"] += 1
        st["only_b"] += len(rest_b)

    na = next(ga, None)
    nb = next(gb, None)
    while na or nb:
        if nb is None or (na and na[0] < nb[0]):
            compare_group(na[1], [])
            na = next(ga, None)
        elif na is None or nb[0] < na[0]:
            compare_group([], nb[1])
            nb = next(gb, None)
        else:
            compare_group(na[1], nb[1])
            na, nb = next(ga, None), next(gb, None)

    rows_a, rows_b = sum(proto_a.values()), sum(proto_b.values())
    res = {
        "rows_a": rows_a, "rows_b": rows_b,
        "compared_columns": len(cols), "skipped_columns": sorted(skip & set(common)),
        "identical": st["identical"], "paired_with_diff": st["paired_with_diff"],
        "loose_paired": st["loose_paired"], "only_a": st["only_a"], "only_b": st["only_b"],
        "identical_rate": st["identical"] / max(rows_a, 1),
        "out_of_order_groups": {"a": oa["out_of_order"], "b": ob["out_of_order"]},
        "protocol_a": dict(proto_a.most_common()), "protocol_b": dict(proto_b.most_common()),
        "protocol_mismatch": {f"{a} -> {b}": n for (a, b), n in proto_pair.most_common()},
        "field_diff": dict(field_diff.most_common()),
        "examples": {c: examples[c] for c, _ in field_diff.most_common()},
    }
    if args.json:
        with open(args.json, "w") as f:
            json.dump(res, f, indent=2, ensure_ascii=False)
    json.dump({k: v for k, v in res.items() if k != "examples"}, sys.stdout, indent=2, ensure_ascii=False)
    print()
    for c, ex in res["examples"].items():
        print(f"[{c}] {field_diff[c]}건, 예: {ex}")


if __name__ == "__main__":
    main()
