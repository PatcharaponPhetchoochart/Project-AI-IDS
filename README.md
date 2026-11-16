# Home NIDS — AI handoff doc

Anomaly-based network IDS for a home LAN. Pure Python, no ready-made IDS (no Snort/Suricata/Zeek/CICFlowMeter).
Owner goal: run it continuously; `ping`/`nmap` against the host → red ALERT in terminal within ~3 s + SQLite row.
Status: demo works on Windows 11 (Py 3.12, Npcap w/ loopback). 35/37 pytest pass (1 known marginal fail, 1 pre-existing xfail — see sec. 5/11). Owner writes Thai; code comments are Thai.

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
- `features`: `{meta: <packet>, vector: [40 floats], feature_version: 5}`
- `detections`: `{meta, vector, score, is_anomaly, threshold}`; score = `-IsolationForest.score_samples` (higher = stranger, ~0.3–0.8).

## 3. Features (`system/shared/features.py`, shared by training + feature-service; order is the contract)
`proto_tcp, proto_udp, proto_icmp, length, ttl, flag_{fin,syn,rst,psh,ack,urg,ece,cwr}, icmp_type, port_none, port_wellknown(<1024), port_registered(<49152), port_dynamic, ctx_pkts, ctx_dst_ports, ctx_dst_ips, ctx_low_ports, ctx_ip_ratio`
(this is the v1 base list only — v3/v4/v5 additions are documented as dated deltas in sec. 5; full current 40-name list = `shared.features.FEATURE_NAMES`, or `system/models/meta.json["feature_names"]` for whatever's actually deployed)
- ctx_* = 5 s sliding window keyed by `src_ip|iface`; O(1) via Counters; packets must be fed in time order.
- `ctx_low_ports` = unique dst ports < 49152 (servers replying to many clients hit ephemeral ports → not a scan). Key for nmap detection.
- `ctx_ip_ratio` = unique dst IPs / pkts (host sweeps → ~1).
- Changing features ⇒ bump `FEATURE_VERSION` and retrain; detection refuses a model whose `meta.json` names/version mismatch.

## 4. Model + threshold (`training/pipeline/common.py`)
- StandardScaler + IsolationForest(n_estimators=200, max_samples=min(8192,N), contamination="auto", random_state=42).
- Large max_samples is deliberate: ICMP is rare (~0.3%); small subsamples miss it and ping becomes undetectable.
- Synthetic normal data includes rare ICMP type 3 on purpose; with zero ICMP the ICMP columns are constant and trees never split on them.
- Threshold: midpoint between p99.8 of synthetic hold-out normal (non-ICMP) and min score of simulated pings. Saved as `recommended_threshold` in `system/models/meta.json`; `detection.threshold: auto` uses it, a number overrides.
- Eval scenarios (`make_scenarios`): pings (self/loopback, Win, Linux, flood) + nmap `-sS` 100/1000, `-sT`, `-sU`, SYN host sweep, `-sn`. Scan passes if first hit ≤ 40 packets.
- Stale baseline (pre-v4, kept for reference): ping 100%, all 6 nmap scenarios pass (first hit at pkt 1–28), FP 0.1% on hold-out, threshold 0.6308.
- **Currently deployed** (`system/models/meta.json`, trained 2026-11-16 15:07 via notebook on synthetic + real capture `captured_full_v5.csv`, capped `MAX_TRAIN_PER_SOURCE=200k`): feature_version 5, threshold 0.66902, FPR 0.00125 (good), but **Recall only 0.5877** on the simulated ping+nmap test set (down from 0.909 in the v3-era run above) — real capture data is one narrow activity (sustained HTTPS/QUIC to a handful of hosts) and dominates the training mix even after capping, pushing the "normal" score band up and burying weaker attack signals. Not yet fixed — see sec. 11.

## 5. Training workflow (primary = Jupyter `training/train.ipynb`)
Open with `python -m notebook training/train.ipynb` (`jupyter.exe` is blocked by AppControl on owner's PC; `python -m` works). Run All.
Notebook params come from `config.yaml` (`training.*`, `feature.window_sec`) and reuse microservice code (`shared/features.py`, capture's `packet_to_meta`). Steps:
1. pcap→CSV: every `.pcap/.pcapng/.cap` in `training/pcap/normal/` (normal-only, train) and `training/pcap/test/` (has attacks, eval) → `data/pcap_csv/<dir>__<name>.csv` (cached by mtime; `max_packets_per_pcap` cap). Module `training/pipeline/pcap_to_csv.py` (CLI too).
2. Train data = synthetic `data/normal_packets.csv` (`USE_SYNTHETIC`) + normal pcap CSVs. ICMP echo dropped (`DROP_ICMP_ECHO`). Features per file, stacked.
3. Train scaler+IF. 4. Test set with labels: simulated (synthetic normal seed+4200, pings, nmap; `USE_SIM_TEST`) + test pcaps labelled by `training/pcap/labels.csv` rules (`label,src_ip,dst_ip,start,end,both_directions,note`; ISO time w/ tz or epoch; blank = wildcard; unmatched = normal).
5. Threshold: `recommended` (validation-based, not test) | `best_f1` (on test → optimistic) | number. Sweep table shown.
6. Metrics (`training/pipeline/evaluate.py`): TP/FP/TN/FN, Accuracy, Precision, Recall, F1, FPR, Specificity, Balanced Acc, ROC-AUC, per-label rate, plots (confusion, ROC, score hist).
7. `save_artifacts` → `system/models/` + meta.json (`recommended_threshold`, `test_metrics`). Restart services to load.
- Default run (no pcaps): Acc 0.966, Prec 0.986, Recall 0.909, F1 0.946, FPR 0.006, AUC 0.991, thr 0.6308.
- CLI alternative: `python training/pipeline/generate_data.py`, `python training/train.py [--source a.csv b.csv] [--keep-icmp-echo] [--plot]`.
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
  - Retrained same day by owner via `training/train.ipynb` (synthetic only) — worked fine at the time (32 features, v4). Superseded by v5 below.
- **FEATURE_VERSION 5 (2026-11-16, same day, later)**: +8 features (G–I), extracted from full-packet `.pcap` capture (new `capture.save_pcap`/`capture.pcap_path` config, `PcapWriter` in `capture_service/main.py` — writes raw packets alongside the existing CSV/ZMQ, lets you re-extract new fields later without re-sniffing). Motivation: v4's false-positive flood on heavy real HTTPS/QUIC traffic (features A/B/C fire on legitimate long-lived connections to CDNs) — tries to give the model header-level signal to tell "real OS/browser stack" from "scripted/scanned" even when volume looks similar.
  - (G) `tcp_window`, `tcp_mss`, `tcp_wscale`, `tcp_sack_ok`, `tcp_ts_present` — TCP handshake fingerprint. MSS/WScale/SAckOK are SYN/SYN-ACK-only per spec (`None` elsewhere, by design); `tcp_window`/`tcp_ts_present` present on every TCP packet. Real OS/browser stacks set these consistently; scan tools/hand-rolled scripts often don't.
  - (H) `dns_qtype`, `dns_rcode` — complements existing `dns_qlen`. `qtype` from `dns.qd.qtype` (query or response, both carry the question); `rcode` only set when `dns.qr==1` (response) — query packets leave it `None`.
  - (I) `tls_sni_known` — reads the TLS ClientHello's SNI extension (plaintext part of the handshake, unlike the encrypted application data after) via a hand-rolled parser (`capture_service.extract_tls_sni`, ~40 lines, no `scapy.layers.tls`) and checks it against a small hardcoded allow-list of common CDN/cloud suffixes (`KNOWN_GOOD_TLS_SUFFIXES`). **TCP:443 only** — QUIC/UDP:443's Initial packets are encrypted with a different (decryptable-but-not-implemented) scheme, so this does *not* help the QUIC noise case that motivated it. Stores only a 0/1 "known or not", never the hostname (same privacy stance as `dns_qlen` not storing the query name).
  - All new raw fields added to `PACKET_FIELDS`; feature values appended via new `header_detail_features()` **after** the existing block in `FeatureExtractor.extract()` — do not insert new per-packet features anywhere but the end, or every index after the insertion point silently misaligns with `FEATURE_NAMES` (hit this exact bug while building v5; every `ctx_*` test failed with nonsense values until the fix).
  - `training/pipeline/generate_data.py`'s synthetic generator updated to emit plausible non-zero values for all of G–I (per-`LAN_CLIENTS` TCP fingerprint tuple, `SERVER_TCP_FP` constant, DNS qtype/rcode mix, `tls_sni_known` on the first TCP:443 request packet of a session) — without this, synthetic "normal" would sit at 0 on every new dimension while real traffic doesn't, which the model would read as "real traffic is the odd one out."
  - Two bugs found/fixed in `training/pipeline/pcap_to_csv.py` while converting the first real `.pcap` through this: (1) it lazily `import`s `scapy.layers.dns` *inside* the per-packet loop, after `conf.layers.filter([...])` already ran — scapy registers new classes (e.g. `DNSCompressedPacket`) into the live `conf.layers` list at import time, and `unfilter()` later `KeyError`s looking up a backup for a class that didn't exist when the snapshot was taken. Fixed by importing `scapy.layers.dns` (and now `DNS`) *before* `conf.layers.filter(...)`. (2) even after that fix, `DNS` itself wasn't in the `filter()` allow-list, so `pkt.getlayer(DNS)` silently returned `None` for every packet — `dns_qlen`/`dns_qtype`/`dns_rcode` were empty for 100% of rows (this means the original v4 `dns_qlen` was *also* silently broken for any pcap put through this converter, not just v5 — nobody had DNS-heavy pcap data to notice). Fixed by adding `DNS` to the `conf.layers.filter([Ether, IP, TCP, UDP, ICMP, DNS])` list.
  - `test_every_ping_flagged_at_recommended_threshold` in `test_scoring.py` now fails by a hair (min ping score 0.63377 vs threshold 0.63445) — adding 8 more mostly-zero dimensions slightly dilutes Isolation Forest's average path length for the dimensions that used to carry the ping signal (same "dilution" mechanism as the pre-existing `xfail` test, just not large enough to need an `xfail` marker — flagged, not fixed, since it's a synthetic-data sensitivity issue the owner said they'd handle via retraining with real data, not a code bug).
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
| `training/pipeline/generate_data.py` | synthetic traffic generator + CSV load/save |
| `training/pipeline/common.py` | features→train→eval→threshold→save (pure training logic only) |
| `training/pipeline/scenarios.py` | simulated ping/nmap test packets + `scan_report` — test-only, split out of `common.py` so train logic and attack-simulation code don't live in the same file; `run_training()` imports from here just to report pass/fail, not to train on |
| `training/train.ipynb` | **primary trainer**: pcap→CSV, train, labelled eval, metrics, save |
| `training/pipeline/pcap_to_csv.py`, `evaluate.py` | pcap converter (folder cache) / labels + metrics + plots |
| `training/pcap/{normal,test}/`, `labels.csv` | drop-in pcap folders + label rules |
| `training/train.py` | CLI trainer (no labelled eval); also writes `results/train_<time>/report.md`+`metrics.json`+plot now (added 2026-11-16, matches what the notebook already did) |
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
- `training/pipeline/pcap_to_csv.py`'s `conf.layers.filter([...])` speed optimization: any scapy layer module used inside the per-packet loop (currently just `scapy.layers.dns`) must be imported **before** `filter()` runs, and the layer class itself must be **in** the filter's allow-list, or dissection into it silently returns `None` for every packet. See sec. 5 (v5 entry) for the two-part bug this caused.
- `conf.layers.filter()`/`unfilter()` snapshot scapy's global class registry at call time — any `scapy.layers.*` module imported *between* `filter()` and `unfilter()` corrupts the restore (`KeyError` on a class the snapshot never saw). Import every scapy submodule you'll touch before calling `filter()`.

## 11. Limits / next steps (updated 2026-11-16 — read this first before touching training)

**Handed off to a second contributor (Thitiwat) at this point.** Owner's own real capture of this
session (`data/captured_full.pcap` + `data/captured_full_v5.csv`, ~281k packets, ~2 hours) and the
`results/train_20261116_150526/` report were packaged and sent separately (data is gitignored, doesn't
travel via git) — ask the owner for that if picking this up fresh.

**#1 priority — training data diversity, not more code.** The real capture above is one narrow activity
(near-continuous HTTPS/QUIC to a handful of hosts from one Claude Code session) repeated ~281k times.
Training on it directly (`train.py --source normal_packets.csv captured_full_v5.csv`, no cap) pushed
threshold to 0.7335 and collapsed detection to ~0% on ping and most nmap scenarios — the "normal" score
band simply absorbed everything, real attacks included. Routing it through the notebook's
`MAX_TRAIN_PER_SOURCE=200k` cap got FPR back down (0.00125) but Recall is still only 0.5877 (see sec. 4).
**Don't just add more volume of the same activity** — the earlier `soak_active1`/`soak_night1` approach
(Thitiwat, 2026-11-12/13, `results/soak_test_v3.md`) covering Discord voice + gaming + idle overnight is
the right shape; those raw files no longer exist on disk, only the write-up does. A fresh multi-day,
multi-activity capture (ideally across more than one device on the LAN) is the actual blocker, not a
feature or threshold tweak.

**No real labeled test data exists.** `training/pcap/test/` and the `home_*_test.csv`/`soak_*_test.csv`
files referenced in `train.ipynb`'s `EXTRA_TEST_CSVS` are all gone — every confusion-matrix/ROC-AUC number
currently produced (sec. 4, `results/train_20261116_150526/metrics.json`) comes **only** from the
simulated ping+nmap scenarios (`USE_SIM_TEST`), not from any real attack traffic. If a real attack test
set shows up (CIC pcaps, or a fresh soak capture with deliberate nmap/ping runs at known times), label it
via `training/pcap/labels.csv` rules and point `EXTRA_TEST_CSVS`/`TEST_DIR` at it.

**v5's TLS SNI feature (sec. 5, feature I) does not address the false-positive case it was built for** —
it only reads TCP:443 ClientHello, but the heaviest false-positive traffic seen this session was QUIC
(UDP:443) to Google/Cloudflare/Anthropic, whose Initial packets are encrypted with a scheme this project
doesn't implement. If QUIC noise is still the main complaint, this needs a different feature (a
"destination familiarity" counter — how often this src has talked to this dst historically — was
discussed but not built) rather than more TLS parsing.

**Small, concrete fixes still open:**
- `test_every_ping_flagged_at_recommended_threshold` fails by 0.0007 (sec. 5, v5 entry) — synthetic-data
  sensitivity from adding 8 dimensions, not a logic bug; likely resolves once retrained on more diverse
  real data, or needs the same kind of per-protocol/per-source balancing `MAX_TRAIN_PER_SOURCE` already
  does for the notebook, but for `train.py`'s simpler path too.
- Not yet tested: real SPAN, interactive Ctrl+C, Docker on Linux, A–F/G–I features against the 5 attack
  scripts (`C:\Project_AI\nids-attack-tests\`) with a model trained on real + diverse data.
- Slow scans (`-T0/-T1`) evade the 5 s window. IPv6 ignored. SQLi/XSS/RCE/payload-level attacks are out of
  scope by design (header/behavior only) — see `Web_Test/README.md`.
- Ideas: longer/multi-scale windows, per-host/per-destination baselines, IPv6, web dashboard over
  alerts.db.
