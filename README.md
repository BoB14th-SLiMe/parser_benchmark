# parser_benchmark

SLiMe의 두 패킷 파서를 같은 PCAP으로 돌려 속도·메모리·출력 정합성을 비교하는 벤치마크입니다.

- [Parser](https://github.com/BoB14th-SLiMe/Parser) — C++ 파서
- [wireshark_parser](https://github.com/BoB14th-SLiMe/wireshark_parser) — tshark(XGT dissector 내장) + Python(`train.py`)

최신 결과와 분석은 [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md)를 참고하세요.

## 디렉토리 구성

```
parser_benchmark/
├── bench/
│   ├── run_bench.py          # 벤치마크 실행
│   └── compare_outputs.py    # 두 파서 CSV 출력 비교
├── results/<pcap 이름>/       # summary.json, compare_*.json (파서 출력 CSV는 커밋하지 않음)
├── BENCHMARK_REPORT.md
├── Parser/                   # (clone) C++ 파서
├── wireshark_parser/         # (clone) Python 파서
├── wireshark/                # (clone) Wireshark 4.4.2 + packet-xgt.c
└── pcap/                     # (로컬 전용) 입력 PCAP
```

`run_bench.py`는 위 경로를 기준으로 바이너리를 찾습니다.

- `Parser/build/parser`
- `wireshark_parser/train.py`
- `wireshark/build/run/tshark`

## 준비

```bash
git clone https://github.com/BoB14th-SLiMe/parser_benchmark.git
cd parser_benchmark
git clone https://github.com/BoB14th-SLiMe/Parser.git
git clone https://github.com/BoB14th-SLiMe/wireshark_parser.git
```

### C++ Parser 빌드

```bash
# Linux
cmake -S Parser -B Parser/build -DCMAKE_BUILD_TYPE=Release && cmake --build Parser/build -j

# macOS (Homebrew libpcap이 keg-only라 경로 지정 필요)
PKG_CONFIG_PATH=/opt/homebrew/opt/libpcap/lib/pkgconfig \
cmake -S Parser -B Parser/build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXE_LINKER_FLAGS="-L/opt/homebrew/opt/libpcap/lib -L/opt/homebrew/lib"
cmake --build Parser/build -j
```

### tshark 빌드 (XGT dissector 내장)

`wireshark_parser/setup_wireshark.sh`를 실행하거나, tshark만 빌드합니다. 시스템에 설치된 tshark에는 XGT dissector가 없어 사용할 수 없습니다.

```bash
# macOS는 Homebrew bison/flex 필요
export PATH="/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/flex/bin:$PATH"
cmake -S wireshark -B wireshark/build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_wireshark=OFF -DBUILD_stratoshark=OFF -DBUILD_logray=OFF
ninja -C wireshark/build tshark
wireshark/build/run/tshark -G protocols | grep -i xgt   # 확인
```

## 실행

```bash
python3 bench/run_bench.py pcap/capture.pcap -n 5
```

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `-n`, `--runs` | 5 | C++ 케이스 반복 횟수 (warmup 1회 별도) |
| `--ws-runs` | 1 | wireshark/tshark 케이스 반복 횟수 |
| `--threads` | `1,2,4` | C++ `--threads` 값 목록 |
| `-o`, `--out` | `results/` | 결과 디렉토리 |

측정 케이스: C++ (스레드별), `train.py`, tshark 단독(`train.py`와 같은 `-e` 필드로 `-T json`).
각 케이스의 wall time, 자식 CPU 시간, 프로세스 트리 최대 RSS, 처리량, CSV 행 수를 `results/<pcap>/summary.json`에 저장합니다.

출력 비교:

```bash
python3 bench/compare_outputs.py results/capture/cpp_t1/output_all.csv results/capture/wireshark/output_all.csv \
    --json results/capture/compare_cpp_t1_vs_wireshark.json
```

## 주의사항

- **메모리**: C++ 파서는 롤링 없이 실행하면 입력 크기에 비례해 메모리를 사용합니다(약 194만 패킷에 8~9 GiB). 16 GB 이하 머신에서는 큰 PCAP으로 돌리기 전에 메모리를 확인하세요.
- **측정 환경**: 다른 앱을 종료하고, 부팅 직후라면 load average가 내려간 뒤 실행하세요. 메모리 압박 상태에서는 macOS가 메모리를 압축해 RSS가 실제보다 작게 측정됩니다.
- **정합성 비교**: C++ `--threads` ≥ 2는 XGT/Modbus 요청-응답 매칭이 깨지므로 정확성 비교는 `cpp_t1` 출력으로 하세요.
- **PCAP과 파서 출력은 커밋하지 마세요.** 실제 OT 트래픽(IP, MAC, PLC 주소)이 포함되어 있습니다.
