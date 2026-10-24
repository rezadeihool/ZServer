# ZVPN server diagnostics and auto-tuning update

This update extends `zvpn_server.c` while preserving the existing ZVPN v1 16-byte frame header and packet-batch format. It does not require an Android client protocol change.

## What's new

- **Process CPU and memory:** dashboard and benchmark show process CPU as a percentage of one logical core, current resident memory (RSS/working set), and peak RSS/working set. `100%` CPU means one fully occupied core; multithreaded use can exceed 100%. These are process measurements, not total host CPU or total machine RAM.
- **`--min-batch BYTES`:** minimum server-to-client batch size for *attempting Zstandard*. Batches smaller than the threshold are sent raw. Default `0` attempts compression for all batch sizes. Alias: `--min-compress-batch`.
- **`--min-batch-wait-ms MS`:** optionally wait for under-minimum batches to fill. When the batch is smaller than `--min-batch` at the normal `--flush-ms` deadline, this extends its total age limit up to `MS`, giving packets more time to reach the minimum. If the batch reaches the minimum, normal `--flush-ms` behavior resumes; if it never reaches the minimum, it is force-flushed at the maximum wait. This is bounded buffering, not an indefinite wait. Default `0` disables it. It requires `--min-batch > 0`, `MS > --flush-ms`, and `--min-batch <= --batch-size`. It only controls server-to-client batching and increases latency for sparse traffic when active.
- **Better benchmark/diagnostics:** upload and download are reported separately; metrics include original/encoded/saved payload bytes, weighted savings, average batch size, compressed-batch share, compression/decompression time, batch-size distribution, CPU/RSS, skipped-small-batch count, and likely-cause messages. Press `I` for a diagnostic log; `S` logs stats and diagnostics.
- **Automatic live benchmark:** `--auto-benchmark 120` tests eight server-to-client profiles over 120 seconds total (about 15 seconds/profile). It varies outgoing batch target, flush timeout, Zstandard level, and minimum compression threshold. It waits for an active client and traffic, disables verbose packet logging during measurements, reports per-profile results, then applies the best *valid tested profile* live and prints suggested startup arguments.

## Build on Linux

Requirements on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential cmake libzstd-dev
```

From this folder:

```bash
./build-linux.sh
```

Or build directly:

```bash
cmake -S . -B build/linux -DCMAKE_BUILD_TYPE=Release
cmake --build build/linux --parallel
```

The result is `build/linux/zvpn-server`.

## Example launch

```bash
sudo ./build/linux/zvpn-server \
  --bind 0.0.0.0 --port 61130 --tun-name zvpn0 --mtu 1360 \
  --batch-size 4194304 --flush-ms 250 --compression-level 3 \
  --min-batch 16384 --min-batch-wait-ms 1500 --auto-benchmark 120
```

In that example, batches smaller than 16 KiB may wait up to 1.5 seconds total to reach 16 KiB. Because the example's default flush delay is 250 ms, packets in low-volume flows may be delayed longer than usual. For latency-sensitive use, leave `--min-batch-wait-ms 0` or choose a much smaller cap.

The server must have permission to create/configure the TUN interface and networking. The `--mtu 1360` value is an example for an uplink whose physical MTU is 1400; adjust it to the network and keep the Android VPN MTU consistent. Do not expose the unauthenticated ZVPN v1 listener to untrusted networks without a secure authenticated transport.

## Interactive controls

- `M`: benchmark and diagnostics page
- `A`: run an automatic search (120 seconds by default unless set with `--auto-benchmark`)
- `I`: write diagnosis to log
- `S`: log stats and diagnosis
- `T`: cycle minimum Zstd threshold through available values
- `+` / `-`: increase/decrease server-to-client Zstd level
- `[` / `]`: decrease/increase flush age by 25 ms
- `C`: toggle server-to-client compression
- `R`: reset counters
- `V`: toggle verbose packet-metadata logging
- `Q`: stop server

Changing compression settings via interactive controls affects **server-to-client/download** compression. Android client-to-server/upload compression is performed by the Android client and cannot be configured by the server source.

## Interpreting measurements correctly

- Savings are weighted payload-level savings: `(original - encoded) / original`. They exclude ZVPN framing, outer TCP/IP headers, retransmissions, and actual physical NIC overhead. Use host NIC counters and a matched compression-on/off workload to validate real network-data savings.
- TLS/HTTPS and QUIC application payloads are encrypted and usually offer little additional Zstandard compression. A bigger batch or higher compression level cannot restore plaintext redundancy hidden by encryption.
- The auto search is a **live, sequential comparison**, not a deterministic replay. If the content or traffic rate changes during the two minutes, later profiles may be advantaged or disadvantaged. It selects the best among eight tested profiles, not a mathematically exhaustive global optimum. Keep a continuous, representative workload running; rerun the winning profile against the same content before accepting it.
- Auto-tuning requires server-to-client compression to be enabled and a startup batch ceiling of at least 128 KiB. A candidate is ignored unless it sends at least 128 KiB across at least four download batches. Increase `--auto-benchmark` duration for low-throughput connections.
- The minimum-size setting skips compression on smaller batches; it can save CPU, but may reduce byte savings. Keep `--min-batch 0` if maximum compression attempts are desired. `--min-batch-wait-ms` is useful only when `--min-batch` is nonzero and is set above the flush timeout. It may increase latency, and if the traffic rate is too low the batch still flushes raw when the waiting cap is reached.

## Windows

The CMake project links `psapi` for process memory measurements. Use the provided `build-windows.ps1` under an MSYS2 UCRT64 setup as before. Windows compilation was not executed in this Linux environment, so verify it with that script on the target Windows toolchain. Wintun remains a separate runtime dependency.
