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
- `features`: `{meta: <packet>, vector: [23 floats], feature_version: 2}`
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
- Live capture to CSV: `capture.mode: csv|both` → `data/captured_packets.csv` (same columns) → feed via `train.py --source` or convert/copy into the notebook flow.
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

## 9. Gotchas (already handled — don't regress)
- Windows Application Control blocks pandas DLLs → project uses numpy + csv only. Don't add pandas.
- `~/.cache/scapy` may be unreadable → `shared.utils.scapy_env()` sets `XDG_CACHE_HOME=<root>/.cache` before importing scapy.
- libzmq on Windows uses 127.0.0.1↔127.0.0.1 TCP socketpairs internally → captured = feedback flood. BPF excludes bus ports and `tcp and src host 127.0.0.1 and dst host 127.0.0.1` (`capture.ignore_loopback_tcp`). Loopback ICMP/UDP and TCP to the host's real IP still captured.
- Ping to own IP on Windows traverses NPF_Loopback, not the NIC → must capture `loopback`.
- Piped child output on Windows needs UTF-8 (`force_utf8`, `PYTHONUTF8=1`) for Thai logs.
- Detection batches up to 256 msgs per score call (throughput).

## 10. Limits / next steps
- Not yet tested: real nmap binary, ping from another LAN host, real SPAN, interactive Ctrl+C.
- Synthetic≠real traffic → some real TCP flows score above threshold. Fix: retrain with real capture (sec. 5).
- Slow scans (`-T0/-T1`) evade the 5 s window. IPv6 ignored.
- Ideas: longer/multi-scale windows, per-host baselines, IPv6, web dashboard over alerts.db.
