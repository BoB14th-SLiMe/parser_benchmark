# SLiMe 파서 벤치마크 통합 보고서

- 작성일: 2026-10-30
- 비교 대상: **C++ Parser** (`Parser/`) vs **wireshark_parser** (`train.py` + XGT 디섹터 내장 tshark)
- 입력: `pcap/capture.pcap` — 1,938,179 패킷, 181.2 MiB

## 1. 요약

| 항목 | C++ (threads=1) | wireshark (train.py) | 비교 |
|---|---|---|---|
| 처리 시간 | 18.97s | 458.57s | C++이 **약 24배** 빠름 |
| 처리량 | 102,158 pps | 4,227 pps | |
| 최대 메모리(RSS) | 9,139 MiB | 1,143 MiB | C++이 **약 8배** 더 사용 |
| 출력 행 수 | 2,772,932 | 2,772,932 | 동일 |
| 출력 내용 일치율 | — | — | **94.2%** |

핵심 결론:

1. **속도**는 C++이 압도적이다. wireshark 쪽 시간의 약 86%는 tshark가 아니라 Python의 JSON 파싱이다.
2. **메모리**는 C++이 입력 크기에 비례해 무한히 증가한다. 기존 VM의 OOM 원인은 tshark가 아니라 C++ 파서다.
3. **멀티스레드 C++(threads≥2)은 출력이 틀린다.** XGT/Modbus 요청-응답 매칭이 깨진다. 정확한 비교 기준은 threads=1이다.

## 2. 테스트 환경

| 항목 | 값 |
|---|---|
| 머신 | Apple M3 Pro (11코어), 18 GB RAM |
| OS | macOS 26.6.2 |
| 컴파일러 | Apple clang 21.0.0 |
| C++ Parser | Release, `-O3 -march=native`, libpcap 1.10.6 (Homebrew) |
| tshark | Wireshark 4.4.2 + `packet-xgt.c` 내장, RelWithDebInfo, tshark 단독 빌드 |
| Python | 3.12.12 |
| 측정 조건 | 재부팅 직후, 다른 앱 종료, load average < 3 확인 후 시작 |

측정 방법 (`bench/run_bench.py`):

- C++: warmup 1회 + 5회 측정, 중앙값 보고. wireshark/tshark: 1회 측정.
- wall time, 자식 프로세스 CPU(user+sys), 프로세스 트리 전체 RSS 최대치(20ms 간격 샘플링).
- 각 실행 전 출력 디렉토리 삭제.

## 3. 성능 결과

| 케이스 | wall 중앙값 (min–max) | CPU | 최대 RSS | 처리량 |
|---|---|---|---|---|
| C++ threads=1 | 18.97s (18.55–19.11) | 23.10s | 9,138.8 MiB | 102,158 pps |
| C++ threads=2 | 15.79s (15.62–17.10) | 23.07s | 8,037.4 MiB | 122,750 pps |
| C++ threads=4 | 14.99s (14.95–15.02) | 26.32s | 8,027.7 MiB | 129,337 pps |
| wireshark (train.py) | 458.57s | 645.12s | 1,143.4 MiB | 4,227 pps |
| tshark 단독 (`-T json`) | 65.64s | 82.48s | 1,126.2 MiB | 29,529 pps |

### 3.1 wireshark 쪽 시간 분해

- tshark 단독: 65.6s (전체의 약 14%)
- Python 파싱(`train.py`의 JSON 디코딩 + 행 생성 + CSV/JSONL 쓰기): 약 393s (약 86%)

wireshark 경로를 개선하려면 tshark보다 Python 쪽(`-T json` 대신 `-T fields`/`-T ek`, 혹은 디코딩 방식 변경)이 우선 대상이다.

### 3.2 C++ 스레드 확장성

- 1 → 2 스레드: 17% 단축, CPU 총량은 동일.
- 2 → 4 스레드: 5% 단축에 그치고 CPU 총량은 증가.
- 워커 이외의 단일 경로(pcap 읽기 + 큐 투입 스레드, 종료 시 정렬·파일 쓰기)가 병목으로 추정된다. **프로파일링으로 확인하지는 않았다.**
- 단, 4장에서 보듯 threads≥2는 출력이 정확하지 않으므로 이 수치는 참고용이다.

## 4. 출력 정합성

비교 도구: `bench/compare_outputs.py` (timestamp 그룹 내 protocol + 5-tuple + seq/ack로 행을 짝지어 필드 비교. 자산 매핑 필드와 `*.description`은 제외)

### 4.1 C++ threads=1 vs wireshark

| 항목 | 값 |
|---|---|
| 비교 컬럼 | 55 |
| 완전 일치 행 | 2,613,229 (94.2%) |
| 필드 차이 행 | 158,913 |
| 한쪽에만 있는 행 | 713 / 713 |

차이 내역:

1. **`modbus.translated_addr` (158,913행)** — 구현 정책 차이.
   - C++ (`ModbusParser.cpp:242`): `modbus.addr`가 있으면 요청/응답 모두 변환 주소(예: `400064`)를 채운다.
   - Python (`parser_common.py:757`): 응답에만 채운다.
   - 어느 쪽이 의도된 동작인지 결정 필요.
2. **프로토콜 분류 (713행)** — C++은 `unknown` 713행, wireshark는 같은 패킷을 `unknown` 353 + `udp` 205 + `dns` 155로 분류. 이 중 77행은 같은 패킷이 C++에서 `udp`, wireshark에서 `dns`로 분류됨. C++ DNS/UDP 판별 조건이 tshark보다 좁다.

프로토콜별 행 수 (xgt_fen 1,620,234 / modbus 529,709 / tcp 307,036 / s7comm 296,245 / arp 12,728)는 양쪽이 정확히 같다.

### 4.2 C++ threads=4 vs wireshark — 일치율 74.9%

| 필드 | 차이 행 |
|---|---|
| `xgt_fen.vars` | 533,277 |
| `xgt_fen.translated_addr` | 533,277 |
| `modbus.translated_addr` | 161,921 |
| `modbus.regs.addr` | 3,008 |

### 4.3 C++ 스레드 수에 따른 출력 불일치

C++ 출력끼리 정렬 후 비교한 결과 스레드 수에 따라 내용이 달라진다.

| 비교 | 다른 행 (양쪽 합) | 프로토콜 |
|---|---|---|
| threads=1 vs 2 | 788,792 | |
| threads=1 vs 4 | 1,072,570 | xgt_fen 1,066,554 / modbus 6,016 |

예시 (같은 XGT 응답 패킷):

```
threads=1: ...,0x0000,%DB001196,2,,D598,
threads=4: ...,0x0000,,2,,,
```

**원인 (소스 기준):** 모든 워커가 하나의 큐(`m_packet_queue`)에서 임의의 패킷을 가져가는데, 요청 정보를 저장하는 프로토콜 파서 인스턴스는 워커별로 따로 있다(`m_worker_parsers`). 같은 세션의 요청과 응답이 다른 워커로 가면 응답이 요청 정보를 찾지 못해 `vars`/`translated_addr`가 비거나 레지스터 주소가 틀어진다.

**수정 방향:** 5-tuple(양방향 정규화) 해시로 워커를 고정 배정해 같은 세션은 항상 같은 워커가 처리하도록 한다.

## 5. 메모리 / OOM 분석

C++ 파서의 RSS는 1만 패킷에서 71 MiB, 194만 패킷에서 8~9 GiB로 입력에 비례해 증가한다. 원인은 두 가지다.

1. **전체 출력 버퍼링** — `UnifiedWriter::addRecord` (`UnifiedWriter.cpp:93`)가 모든 레코드를 `m_time_slots`에 보관하고, 롤링이 없으면(`-r 0`, 벤치 기본값) 종료 시 `flush()`에서 한 번에 정렬·기록한다. 레코드당 47개 문자열 필드 × 277만 행이 상주한다.
2. **무제한 패킷 큐** — 리더가 `m_packet_queue`(`PacketParser.cpp:449`)에 backpressure 없이 넣는다. 파싱보다 읽기가 빠르면 패킷 사본이 큐에 쌓인다. threads=1에서 RSS가 가장 큰(9.1 GiB) 것도 이 때문으로 보인다.

참고: 재부팅 전(다른 앱 실행 중) 측정에서는 RSS가 5.1 GiB로 나왔지만, 이는 macOS가 메모리를 압축/스왑해 RSS에서 빠진 값이다. 실제 요구량은 8~10 GiB다.

**수정 방향:** 큐 상한(bounded queue) 도입, 시간 슬롯 단위 또는 레코드 수 기준 주기적 flush.

tshark 단독은 같은 입력에서 최대 1.1 GiB로 안정적이었다.

## 6. 작업 내역

### 6.1 macOS 빌드

VM(Linux aarch64)에서 가져온 빌드 산출물은 실행 불가하여 보존(`Parser/build-linux`, `wireshark/build-linux`)하고 재빌드했다.

C++ Parser — Homebrew libpcap이 keg-only이고 `CMakeLists.txt`가 라이브러리 경로 없이 이름만 링크하므로 다음 옵션이 필요하다:

```sh
PKG_CONFIG_PATH=/opt/homebrew/opt/libpcap/lib/pkgconfig \
cmake -S Parser -B Parser/build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXE_LINKER_FLAGS="-L/opt/homebrew/opt/libpcap/lib -L/opt/homebrew/lib"
cmake --build Parser/build -j
```

tshark — XGT 디섹터가 `epan/dissectors`에 내장되어 있어 시스템 Wireshark를 쓸 수 없다:

```sh
export PATH="/opt/homebrew/opt/bison/bin:/opt/homebrew/opt/flex/bin:$PATH"
cmake -S wireshark -B wireshark/build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_wireshark=OFF -DBUILD_stratoshark=OFF -DBUILD_logray=OFF
ninja -C wireshark/build -j8 tshark
```

### 6.2 `bench/run_bench.py` 수정

1. **RSS 측정 이식성** — `/proc` 기반 → `ps -A -o pid=,ppid=,rss=` 기반 (Linux/macOS 공통).
2. **deadlock 수정** — 자식 stderr를 `PIPE`로 받고 종료 시까지 읽지 않아, `train.py`가 logging 출력으로 64KB 파이프 버퍼를 채우면 `write()`에서 멈추고 tshark도 연쇄적으로 멈췄다(첫 실행에서 19분 정지). stderr를 임시 파일로 받도록 변경.

파서 소스(`Parser/`, `wireshark_parser/`)는 수정하지 않았다.

## 7. 후속 과제

| 우선순위 | 항목 | 대상 |
|---|---|---|
| 높음 | 세션 해시 기반 워커 배정 (threads≥2 정합성) | `PacketParser.cpp` |
| 높음 | bounded queue + 주기적 flush (메모리 상한) | `PacketParser.cpp`, `UnifiedWriter.cpp` |
| 중간 | `modbus.translated_addr` 요청 행 처리 정책 통일 | `ModbusParser.cpp` / `parser_common.py` |
| 중간 | DNS/UDP 분류 조건 tshark와 정렬 | C++ `DnsParser` / `UdpSessionParser` |
| 낮음 | C++ 멀티스레드 병목 프로파일링 | — |
| 낮음 | `-r` 롤링 옵션 적용 시 메모리/속도 재측정 | 벤치 |

## 8. 결과 파일

| 파일 | 내용 |
|---|---|
| `results/capture/summary.json` | 벤치 수치 원본 |
| `results-capture.log` | 벤치 실행 로그 |
| `results/capture/compare_cpp_t1_vs_wireshark.json` | threads=1 vs wireshark 비교 |
| `results/capture/compare_cpp_t4_vs_wireshark.json` | threads=4 vs wireshark 비교 |
| `results/capture/{cpp_t1,cpp_t2,cpp_t4,wireshark}/output_all.{csv,jsonl}` | 각 파서 출력 |
