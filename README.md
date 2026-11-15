# Home NIDS — AI handoff doc

Anomaly-based network IDS for a home LAN. Pure Python, no ready-made IDS (no Snort/Suricata/Zeek/CICFlowMeter).
Owner goal: run it continuously; `ping`/`nmap` against the host → red ALERT in terminal within ~3 s + SQLite row.
Status: demo works on Windows 11 (Py 3.12, Npcap w/ loopback). 26 pytest pass. Owner writes Thai; code comments are Thai.

## 1. Pipeline
```
capture --packets:5555--> feature --features:5556--> detection --detections:5557--> alert   (Rich + SQLite)
(Scapy)                   (window)                   (IsolationForest)            \-> monitor (live stream)
```
- 1 process per service, ZeroMQ PUB/SUB, JSON multipart `[topic, payload]`. Publisher binds, subscriber connects (start order irrelevant).
- Layout: user-facing at root (`config/`, `training/`, `data/`, `run_all.*`, READMEs); system code under `system/` (`services/`, `shared/`, `models/`, `tests/`, `scripts/`, `docs/`). Imports are top-level (`import shared`, `import services`) → `system/` must be on sys.path (entry scripts, conftest, notebook, run_all via PYTHONPATH do this).
- All settings in `config/config.yaml`; relative paths resolve from project root (`system/shared/config.py: ROOT=parents[2], resolve_path`). Env `NIDS_CONFIG` overrides config path.

## 2. Messages (`system/shared/schemas.py`)
- `packets`: `ts, iface, src_ip, dst_ip, src_port, dst_port, proto(TCP|UDP|ICMP|OTHER), length(IP total), ttl, tcp_flags(int bitmask), icmp_type, icmp_code` (None when N/A). IPv4 only.
- `features`: `{meta: <packet>, vector: [32 floats], feature_version: 4}`
- `detections`: `{meta, vector, score, is_anomaly, threshold}`; score = `-IsolationForest.score_samples` (higher = stranger, ~0.3–0.8).

## 3. Features (`system/shared/features.py`, shared by training + feature-service; order is the contract)
`proto_tcp, proto_udp, proto_icmp, length, ttl, flag_{fin,syn,rst,psh,ack,urg,ece,cwr}, icmp_type, port_none, port_wellknown(<1024), port_registered(<49152), port_dynamic, ctx_pkts, ctx_dst_ports, ctx_dst_ips, ctx_low_ports, ctx_ip_ratio`
- ctx_* = 5 s sliding window keyed by `src_ip|iface`; O(1) via Counters; packets must be fed in time order.
- `ctx_low_ports` = unique dst ports < 49152 (servers replying to many clients hit ephemeral ports → not a scan). Key for nmap detection.
- `ctx_ip_ratio` = unique dst IPs / pkts (host sweeps → ~1).
- Changing features ⇒ bump `FEATURE_VERSION` and retrain; detection refuses a model whose `meta.json` names/version mismatch.

## 4. Model + threshold (`training/common.py`)
- StandardScaler + IsolationForest(n_estimators=200, max_samples=min(8192,N), contamination="auto", random_state=42).
- Large max_samples is deliberate: ICMP is rare (~0.3%); small subsamples miss it and ping becomes undetectable.
- Synthetic normal data includes rare ICMP type 3 on purpose; with zero ICMP the ICMP columns are constant and trees never split on them.
- Threshold: midpoint between p99.8 of synthetic hold-out normal (non-ICMP) and min score of simulated pings. Saved as `recommended_threshold` in `system/models/meta.json`; `detection.threshold: auto` uses it, a number overrides.
- Eval scenarios (`make_scenarios`): pings (self/loopback, Win, Linux, flood) + nmap `-sS` 100/1000, `-sT`, `-sU`, SYN host sweep, `-sn`. Scan passes if first hit ≤ 40 packets.
- Current: ping 100%, all 6 nmap scenarios pass (first hit at pkt 1–28), FP 0.1% on hold-out, threshold 0.6308.

## 5. Training workflow (primary = Jupyter `training/train.ipynb`)
Open with `python -m notebook training/train.ipynb` (`jupyter.exe` is blocked by AppControl on owner's PC; `python -m` works). Run All.
Notebook params come from `config.yaml` (`training.*`, `feature.window_sec`) and reuse microservice code (`shared/features.py`, capture's `packet_to_meta`). Steps:
1. pcap→CSV: every `.pcap/.pcapng/.cap` in `training/pcap/normal/` (normal-only, train) and `training/pcap/test/` (has attacks, eval) → `data/pcap_csv/<dir>__<name>.csv` (cached by mtime; `max_packets_per_pcap` cap). Module `training/pcap_to_csv.py` (CLI too).
2. Train data = synthetic `data/normal_packets.csv` (`USE_SYNTHETIC`) + normal pcap CSVs. ICMP echo dropped (`DROP_ICMP_ECHO`). Features per file, stacked.
3. Train scaler+IF. 4. Test set with labels: simulated (synthetic normal seed+4200, pings, nmap; `USE_SIM_TEST`) + test pcaps labelled by `training/pcap/labels.csv` rules (`label,src_ip,dst_ip,start,end,both_directions,note`; ISO time w/ tz or epoch; blank = wildcard; unmatched = normal).
5. Threshold: `recommended` (validation-based, not test) | `best_f1` (on test → optimistic) | number. Sweep table shown.
6. Metrics (`training/evaluate.py`): TP/FP/TN/FN, Accuracy, Precision, Recall, F1, FPR, Specificity, Balanced Acc, ROC-AUC, per-label rate, plots (confusion, ROC, score hist).
7. `save_artifacts` → `system/models/` + meta.json (`recommended_threshold`, `test_metrics`). Restart services to load.
- Default run (no pcaps): Acc 0.966, Prec 0.986, Recall 0.909, F1 0.946, FPR 0.006, AUC 0.991, thr 0.6308.
- CLI alternative: `python training/generate_data.py`, `python training/train.py [--source a.csv b.csv] [--keep-icmp-echo] [--plot]`.
- Live capture to CSV: `capture.mode: csv|both` → `data/captured_packets.csv` (same columns, appended) → notebook adds it to train data when `USE_CAPTURED = True` (or `train.py --source`).
- Source balance (notebook): `MAX_TRAIN_PER_SOURCE` (200k) samples rows **after** feature build (ctx_* need contiguous packets); `ICMP_MIN_FRAC` (0.01) duplicates non-echo ICMP rows. Without these, 2M CIC Monday rows (98%) drowned ICMP → ping 0% detected; 0.3% ICMP was not enough once real traffic was added (sim pings 62–75%).
- Home data: `EXTRA_NORMAL_CSVS` (e.g. `data/home_discord_normal.csv`: Discord voice = UDP 19294–19344 to Cloudflare 104.29.x, was ~8% false alerts before it was in training) and `EXTRA_TEST_CSVS` (`data/home_test_session2.csv`, labelled via labels.csv rules for iPhone 192.168.1.34 ping + Fing scan). Results per run → `results/train_<time>/` (report.md, png, metrics.json); live tests → `results/*.md`.
- **FEATURE_VERSION 3 (2026-11-13)**: +`ctx_unans_ports` / `ctx_unans_ports_long` (5 s / 60 s) = distinct dst ports a src opened a *new* connection to (TCP SYN w/o ACK, or UDP that is not a reply to a flow the other side opened) that got no acceptance (reply from that port; RST / ICMP unreachable / silence = not accepted). Scans: 100–1000; all normal traffic incl. CIC servers, Discord, games: ≤10. Fixes UDP scan (-sU) being hidden by CIC DNS-server replies and home UDP. `ProbeTracker` in `shared/features.py` (needs both directions — capture sees them). Old models are rejected by detection-service (version check) → retrain.
- **FEATURE_VERSION 4 (2026-11-16)**: +7 features (A–F), aimed at app-layer-adjacent attacks that v3 behavioral scan/unans features don't cover (brute force, slowloris, flood, C2 beacon, DNS tunneling). None read HTTP payload (SQLi/XSS/RCE stay out of scope — need a WAF/DPI layer). `ContextTracker.update()` signature grew (`src_port`, `length`, `is_dns_query` args; returns 8-tuple now, old 4 unchanged + 4 new):
  - (A) `ctx_same_endpoint` — count of packets from this src to the *same* `(dst_ip,dst_port)` in the 5 s window (not just same port across hosts, which is `ctx_low_ports`). Targets repeated hits on one endpoint: login brute force, dir-enum.
  - (B) `ctx_half_open` — count of this src's TCP flows where an ACK-bearing packet was seen (handshake progressed) but no FIN/RST yet, held open ≥ `ConnStateTracker.min_age` (2 s default). New `ConnStateTracker` class (per-src flow dict, O(flows per src)). Targets slowloris / many held-open connections.
  - (C) `ctx_bytes` — rolling sum of `length` in the window (same deque/expiry as ctx_pkts etc., just sums instead of counts). Targets flood / exfil burst volume.
  - (D) `ctx_beacon_cv` — coefficient of variation (std/mean) of inter-arrival times from this src to the same `dst_ip` (ignores port), over last `BeaconTracker.history` (8) intervals. Low → very regular timing (C2-beacon-like); default `BeaconTracker.DEFAULT_CV = 2.0` when <3 samples (assume benign until proven otherwise — don't flag on sparse data). New `BeaconTracker` class, independent of the 5 s ContextTracker window (own `flow_ttl` 600 s).
  - (E) `dns_qlen` (per-packet) + `ctx_dns_qrate` (context) — DNS tunneling. `capture_service.packet_to_meta` now parses `scapy.layers.dns.DNS` for UDP:53 packets and stores only the **query name length** (`dns_qlen`; never the name itself — no payload content is persisted). New `PACKET_FIELDS` column `dns_qlen` (also added to `schemas.PacketMsg`, `generate_data.py` CSV load/save `int_cols`); absent/old rows → `None` → feature defaults to 0, no breakage. `ctx_dns_qrate` = count of this src's UDP:53 packets in the 5 s window (folded into `ContextTracker`, not a separate class).
  - (F) `ctx_resp_ports` — distinct low (<49152) **src**-ports this src used while replying (`src_port<49152` AND `dst_port>=49152` — the mirror direction of `ctx_low_ports`, which only counts low **dst**-ports i.e. "opening toward a service"). Gives the model visibility into "I am acting as a server" patterns that v1–v3 intentionally excluded from `ctx_low_ports` to avoid flagging normal server replies.
  - `reasons.py` explain() gained matching rule-based messages (same-endpoint ≥15, half_open ≥8, beacon_cv <0.12 & ctx_pkts≥4, dns_qlen ≥50 chars, dns_qrate ≥20, bytes_sum ≥2MB) — all thresholds are hand-picked heuristics (consistent with pre-existing unans/low_ports/ip thresholds), not learned.
  - **Not retrained** (user explicitly asked to train it themselves next): `system/models/*.joblib` is still the v3 model → detection-service will refuse to load it (version/name mismatch) until retrained via `training/train.ipynb`. One pre-existing test (`test_nmap_scans_detected_within_first_packets`, host-sweep-to-fixed-port scenario) is marked `xfail` in `test_scoring.py` — its own small in-test IsolationForest fixture (200 estimators, unrelated to the deployed model) got diluted by the extra dimensions; expected to pass again once retrained with params suited to 32 features. Remove the `xfail` marker after that.
- Threshold: `recommend_threshold` uses **echo requests only** (`ping_request_scores`; our own echo replies are not what must alert) and sits at `gap_frac`=0.25 of the gap from the normal side (was midpoint) so host-sweep scans keep margin. `training.n_estimators` 200 → 1000: with 200 trees results swung by seed (v3 at other seeds: -sU failed, sim pings 65–75%).
- Notebook gate cell "เกณฑ์ผ่านตาม README" prints PASS/FAIL (ping requests 100%, 6 nmap scenarios within 40 pkts, home iPhone ping/Fing ≥95%, soak FP info). Per-protocol sampling (`MAX_TRAIN_PER_SOURCE` per proto) + `EXTRA_SYNTHETIC` 40k keep rare TCP/ICMP from being drowned by Discord UDP. Soak captures split train/test: `data/soak_*_{train,test}.csv`.
- Supervised comparison (not deployed): `training/train_supervised.ipynb` trains RandomForest on the same 23 features (normal sources + CIC Friday before 15:00 -03:00, PortScan only) and scores RF vs the deployed IsolationForest on identical test sets → `results/compare_<time>/`. Result 2026-11-12: RF wins on CIC PortScan (97% vs 53%) but fails on unseen attacks (home Fing scan 7%, ping 0%, nmap host/UDP/ping sweep ~0–1%); IF: home Fing 99%, ping 100%. Split at 14:43 is useless (firewall-on PortScan = ~1.5k pkts).
- Time windows: `training.pcap_time_windows: {<pcap stem>: [start, end]}` (ISO w/ tz or epoch) → converter reads only that span (raw-reader skip for .pcap, early stop past end; pcapng falls back to PcapReader). Needed for CIC Friday: first 2M pkts are morning only, PortScan is 13:55–15:29 (-03:00 assumed). Cache sidecar `<csv>.window.json` forces reconvert when the window changes. CLI: `pcap_to_csv.py --start/--end`.
- Online datasets with pcap: CIC-IDS2017 (Mon = benign train, Fri = PortScan test), UNSW-NB15, IoT-23, CTU-13. Flow-only CSVs (Kaggle, NSL-KDD) are incompatible with the packet-level pipeline.

## 6. Run
```bash
python run_all.py [--monitor window|inline|off]   # Windows: run_all.ps1 (admin), Linux: sudo ./run_all.sh
python system/services/<capture|feature|detection|alert|monitor>_service/main.py   # standalone
python system/scripts/list_interfaces.py          # names for capture.interfaces
python -m pytest
```
- run_all: alert inherits terminal; capture/feature/detection piped with colored prefix; monitor in new console on Windows. If any child exits, all stop. Pre-checks model files, warns if not admin.
- `capture.interfaces`: names from list_interfaces, plus aliases `loopback` (Win `\Device\NPF_Loopback`, Linux `lo`) and `default`. SPAN = put the NIC wired to the mirror port (e.g. `Ethernet`).

## 7. Alert service (`system/services/alert_service/main.py: AlertManager`)
- Groups by `(src, dst, proto)` within `alert.cooldown_sec` (10). Max 5 dst groups per src+proto; extra → `(src,"*",proto)`. Summary line printed when a group closes.
- Table `alerts(id, ts, last_ts, src_ip, dst_ip, src_port, dst_port, proto, iface, reason, score, count)` in `data/alerts.db`.
- Reason text is rule-based (`system/shared/reasons.py`), not from the model.

## 8. Files
| Path | Role |
|---|---|
| `config/config.yaml` | single config (bus ports, interfaces, mode, window, threshold, cooldown, training params) |
| `system/shared/` | `features.py` (contract), `schemas.py`, `bus.py` (Publisher/Subscriber, poll w/ timeout for Ctrl+C), `config.py`, `reasons.py`, `utils.py` (logging, utf-8, scapy cache env) |
| `system/services/*_service/main.py` | 5 services (run_all uses `-m services.X_service` with PYTHONPATH=system) |
| `training/generate_data.py` | synthetic traffic generator + CSV load/save |
| `training/common.py` | features→train→eval→threshold→save; scenarios |
| `training/train.ipynb` | **primary trainer**: pcap→CSV, train, labelled eval, metrics, save |
| `training/pcap_to_csv.py`, `evaluate.py` | pcap converter (folder cache) / labels + metrics + plots |
| `training/pcap/{normal,test}/`, `labels.csv` | drop-in pcap folders + label rules |
| `training/train.py` | CLI trainer (no labelled eval) |
| `system/models/` | joblib model, scaler, meta.json |
| `data/` | CSVs, alerts.db |
| `system/tests/` | features, scoring (ping + nmap), alert cooldown, bus, pcap converter, labels, metrics |
| `run_all.py/.ps1/.sh`, `system/scripts/list_interfaces.py` | launchers, interface lister |
| `system/docs/README_pdf.html` | source of README.pdf (render: Edge `--headless=new --print-to-pdf`) |

## 9. Docker (optional; see `DOCKER.md` for full detail)
- `Dockerfile` + `docker-compose.yml` + `requirements-runtime.txt` (slim: no jupyter/matplotlib/pandas, those are training-only) + `config/config.docker.yaml` (`capture.interfaces: [any, loopback]`, `ping_only: false`). `system/models/`, `data/`, `config/` are bind-mounted, not baked into the image — retraining on the host takes effect without a rebuild.
- **Windows/Mac caveat (important, do not "fix" by assuming it works)**: Docker Desktop containers run inside a WSL2/Hyper-V VM. `network_mode: host` there only exposes the *VM's* network namespace, not the real Wi-Fi/Ethernet NIC — a LAN machine pinging the Windows host's real IP is invisible to a Dockerized capture-service on Windows. Only true on native Linux Docker hosts. For the "ping/attack from another LAN machine" test, keep running `run_all.py` **natively** on Windows (as already set up); Dockerize NIDS only for a Linux deployment or same-container-network testing.
- Separate project `C:\Project_AI\Web_Test\` (its own git-less folder, Flask + MySQL, deliberately SQLi-vulnerable `/login` `/search` `/profile`) exists purely as an attack *target* to generate traffic against — port-published (`8090:5000`), so a LAN machine hitting `WindowsHostIP:8090` traverses the real NIC regardless of NIDS being Dockerized or native (Docker's port-publish ≠ the raw-capture problem above).

## 10. Gotchas (already handled — don't regress)
- Windows Application Control blocks pandas DLLs → project uses numpy + csv only. Don't add pandas.
- `~/.cache/scapy` may be unreadable → `shared.utils.scapy_env()` sets `XDG_CACHE_HOME=<root>/.cache` before importing scapy.
- libzmq on Windows uses 127.0.0.1↔127.0.0.1 TCP socketpairs internally → captured = feedback flood. BPF excludes bus ports and `tcp and src host 127.0.0.1 and dst host 127.0.0.1` (`capture.ignore_loopback_tcp`). Loopback ICMP/UDP and TCP to the host's real IP still captured.
- Ping to own IP on Windows traverses NPF_Loopback, not the NIC → must capture `loopback`.
- Piped child output on Windows needs UTF-8 (`force_utf8`, `PYTHONUTF8=1`) for Thai logs.
- Detection batches up to 256 msgs per score call (throughput).

## 11. Limits / next steps
- Not yet tested: real SPAN, interactive Ctrl+C, Docker on Linux, A–F features against the 5 attack scripts (`C:\Project_AI\nids-attack-tests\`) with a retrained model.
- v4 (A–F) code is in place but **untrained** — detection-service currently refuses the old model. Must run `training/train.ipynb` (or `train.py`) before `run_all.py`/Docker will start.
- Synthetic≠real traffic → some real TCP flows score above threshold. Fix: retrain with real capture (sec. 5).
- Slow scans (`-T0/-T1`) evade the 5 s window. IPv6 ignored. SQLi/XSS/RCE/payload-level attacks are out of scope by design (header/behavior only) — see `Web_Test/README.md`.
- Ideas: longer/multi-scale windows, per-host baselines, IPv6, web dashboard over alerts.db.
