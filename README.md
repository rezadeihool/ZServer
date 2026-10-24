<div align="center">

# ZVPN Server
### A cross-platform C server for the ZVPN v1 packet tunnel

**TCP transport · TUN/Wintun · Zstandard compression · Live diagnostics · Automatic tuning**

[Getting Started](#-getting-started) · [Command-line options](#-all-command-line-options) · [Benchmarking](#-benchmarking-and-auto-tuning) · [Troubleshooting](#-troubleshooting)

</div>

---

> [!CAUTION]
> **Security warning: ZVPN v1 does not provide authentication or encryption.** The server accepts a TCP connection and carries VPN packets over that connection, but the protocol itself does not protect traffic or prove a client's identity. Do not expose this listener directly to an untrusted network or the public Internet unless you protect it with a separately configured, authenticated secure transport compatible with your client. `--allow-client` is only an IP address filter; it is **not** authentication or encryption.

## Contents

- [What this server does](#-what-this-server-does)
- [Features](#-features)
- [Requirements](#-requirements)
- [Build on Linux](#-build-on-linux)
- [Build on Windows](#-build-on-windows)
- [Build on macOS](#-build-on-macos)
- [Getting started](#-getting-started)
- [All command-line options](#-all-command-line-options)
- [Batching, compression, and waiting](#-batching-compression-and-waiting)
- [Benchmarking and auto-tuning](#-benchmarking-and-auto-tuning)
- [Interactive console controls](#-interactive-console-controls)
- [Understanding the statistics](#-understanding-the-statistics)
- [Networking and MTU](#-networking-and-mtu)
- [Troubleshooting](#-troubleshooting)
- [Known limitations](#-known-limitations)

---

## 🌐 What this server does

ZVPN Server is a C implementation of the server side of the ZVPN v1 protocol. It connects the Android ZVPN client to an operating-system tunnel interface and routes IPv4 packets between the client and the Internet.

At a high level:

```text
Android app
    │
    │  ZVPN packets over a TCP connection
    │  (a batch may be Zstandard-compressed)
    ▼
ZVPN Server
    ├── receives a batch
    ├── decompresses it when needed
    ├── validates and writes individual IP packets to the TUN interface
    │
    ├── reads packets returning from the TUN interface
    ├── routes each packet to the client that owns its destination VPN IP
    ├── groups packets into batches
    ├── optionally compresses each batch with Zstandard
    └── sends the batch over that client's TCP connection
    ▼
Android app
```

### The protocol in simple terms

A ZVPN v1 frame has a 16-byte header followed by a batch payload. The payload contains repeated packet records: a 4-byte packet length followed by the raw IP packet. A header flag indicates whether that payload is Zstandard-compressed.

This README describes the server source in this repository. The server and Android client must agree on the ZVPN v1 framing and Zstandard behavior. The command-line options below do not create a new protocol version.

## ✨ Features

- **C implementation** with Linux TUN support, Windows Wintun support, and macOS `utun` support.
- **Zstandard compression** for server-to-client traffic, with raw-payload fallback when compression is not smaller.
- **Configurable batching** by target/maximum size and flush age.
- **Minimum compression threshold** to skip compression attempts on very small batches.
- **Bounded minimum-size waiting** to give small batches extra time to collect packets.
- **Live benchmark and diagnosis** with separate upload/download measurements, batch sizes, CPU, and memory usage.
- **Eight-profile live auto-tuning** for server-to-client compression settings.
- **Interactive terminal UI** with statistics, diagnostics, client management, compression controls, and logs.
- **Automatic IPv4 forwarding/NAT setup** on Linux and Windows by default, when run with the required privileges.
- **Client allowlisting** by the remote peer's numeric IP address.

## 🧰 Requirements

### Linux (Debian/Ubuntu)

- A C compiler such as GCC or Clang
- CMake 3.18 or newer
- Zstandard development headers and library (`zstd.h`, `libzstd`)
- Root/appropriate capabilities for TUN setup and network configuration
- `iproute2` and `iptables` for the automatic Linux IPv4 network setup

Install the usual build dependencies:

```bash
sudo apt update
sudo apt install -y build-essential cmake libzstd-dev iproute2 iptables
```

### Windows

- 64-bit Windows
- PowerShell
- [MSYS2](https://www.msys2.org/) with the **UCRT64** environment and its GCC, CMake, Ninja, and Zstandard packages
- The correct architecture of `wintun.dll`, supplied separately
- An elevated Administrator terminal for TUN/network setup

The `build-windows.ps1` script installs/checks the MSYS2 UCRT64 packages unless `-SkipDependencyInstall` is used. Wintun is a runtime dependency and may need to be placed beside the executable manually.

### macOS

- Xcode Command Line Tools
- CMake and Zstandard installed for the active toolchain
- Appropriate permissions to create/use `utun`
- Manual routing, forwarding, NAT, and firewall configuration

**Important platform distinction:** automatic network setup is enabled by default on Linux and Windows, but disabled by default on macOS. This build does not automatically configure macOS forwarding/NAT/firewall rules.

---

## 🐧 Build on Linux

From the directory containing `CMakeLists.txt` and `zvpn_server.c`:

```bash
chmod +x build-linux.sh
./build-linux.sh
```

The script checks for CMake, the selected C compiler, and linkable Zstandard development files, then builds the program. The default output path is:

```text
build/linux/zvpn-server
```

### Build manually with CMake

```bash
cmake -S . -B build/linux -DCMAKE_BUILD_TYPE=Release
cmake --build build/linux --parallel
```

To select Clang instead of the default C compiler:

```bash
CC=clang BUILD_TYPE=Release ./build-linux.sh
```

To change the build directory:

```bash
BUILD_DIR="$PWD/build/my-linux-build" ./build-linux.sh
```

Confirm the executable and available options:

```bash
./build/linux/zvpn-server --help
```

---

## 🪟 Build on Windows

Open **PowerShell** in the project directory. Run the build script:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build-windows.ps1
```

By default, the script looks for MSYS2 at `C:\msys64`, checks/installs the required UCRT64 packages, configures CMake/Ninja, builds the program, and places distribution files in:

```text
dist\windows-x64\
```

The distribution directory may include the executable and common MSYS2 runtime DLLs. **Wintun is not bundled automatically unless a `wintun.dll` is found in the project tree.** Make sure that the DLL is trusted and matches the executable architecture.

### Windows build-script arguments

| Script argument | Meaning | Example |
|---|---|---|
| `-MsysRoot <path>` | Use an MSYS2 installation somewhere other than `C:\msys64`. | `./build-windows.ps1 -MsysRoot 'D:\msys64'` |
| `-BuildType Release` | Build an optimized release executable. `Debug` may be useful when debugging. | `./build-windows.ps1 -BuildType Release` |
| `-SkipDependencyInstall` | Do not run `pacman` to install/check packages. Use this only when dependencies are already installed. | `./build-windows.ps1 -SkipDependencyInstall` |

Run the finished program from an **Administrator PowerShell** when creating/configuring the tunnel:

```powershell
cd .\dist\windows-x64
.\zvpn-server.exe --help
.\zvpn-server.exe --verbose
```

If Windows reports a missing DLL, check that the required Zstandard/MSYS2 runtime DLLs and `wintun.dll` are beside the executable or otherwise available to the process.

---

## 🍎 Build on macOS

Install the compiler tools and dependencies using your normal macOS package manager, then build with CMake. For example, with Homebrew:

```bash
xcode-select --install
brew install cmake libzstd
cmake -S . -B build/macos -DCMAKE_BUILD_TYPE=Release
cmake --build build/macos --parallel
```

The expected output is `build/macos/zvpn-server`. macOS network setup is **not automated** by this source; you must configure the `utun` routing and any forwarding/NAT/firewall rules appropriate for your system. Review the startup log before trying client traffic.

---

## 🚀 Getting started

### 1. Start with a simple configuration

Linux example:

```bash
sudo ./build/linux/zvpn-server \
  --bind 0.0.0.0 \
  --port 61130 \
  --tun-name zvpn0 \
  --verbose
```

This uses the defaults for MTU, batching, and compression while printing detailed logs. If the program is attached to a terminal, the interactive UI is normally enabled. To use plain logs instead, add `--no-tui`.

### 2. Connect the Android client

Configure the client to connect to the server's reachable IP address and TCP port. The server's default listening port is `61130`. Confirm that firewalls/security groups allow the port **only from the networks or clients you intend to trust**. Remember that the protocol itself has no authentication or encryption.

### 3. Confirm that a client was accepted

Look for log messages indicating the TCP connection was accepted and an inner VPN IPv4 address was assigned. By default the server uses `10.0.0.2/24` on its side and the client subnet `10.0.0.0/24`; the Android client must use a unique client address in that subnet, not the server's address.

### 4. Run a steady test

Browse or download the same material for a few minutes, then press **`S`** to log a statistics snapshot and diagnosis or **`I`** to log just the diagnostic report. For a meaningful result, keep the workload steady and examine upload and download separately.

### 5. Try auto-tuning

After confirming a connected client is moving traffic, use:

```bash
sudo ./build/linux/zvpn-server \
  --bind 0.0.0.0 --port 61130 --tun-name zvpn0 \
  --batch-size 4194304 --flush-ms 250 --compression-level 3 \
  --auto-benchmark 120
```

The auto-tuner runs eight profiles over approximately two minutes of measured traffic. It needs an active client and real server-to-client traffic. See [Benchmarking and auto-tuning](#-benchmarking-and-auto-tuning) before trusting the result.

---

## ⚙️ All command-line options

Run `./zvpn-server --help` for the help text compiled into the executable. Options that take values require the value immediately after the option name; options described as switches do not need `true`/`false` after them.

### Listener and client access

| Option | Default | What it does | Example |
|---|---|---|---|
| `--bind ADDRESS` | `0.0.0.0` | Address on which the server listens. `0.0.0.0` means all local IPv4 interfaces. | `--bind 127.0.0.1` listens only on loopback. |
| `--port PORT` | `61130` | TCP listening port. Valid values: `1`–`65535`. The client must use the same port. | `--port 61131` |
| `--allow-client IP` | Any peer IP | Accepts only a remote peer whose numeric IPv4 or IPv6 address matches this value. This is an IP filter, **not** client authentication. | `--allow-client 203.0.113.25` |

For a private test on the same machine, `--bind 127.0.0.1` avoids listening on other IPv4 interfaces. A remote Android device usually needs a reachable server address and a suitable bind/firewall configuration. Do not use that as a reason to expose unauthenticated ZVPN v1 to the public Internet.

### Tunnel and IPv4 network

| Option | Default | What it does | Example |
|---|---|---|---|
| `--tun-name NAME` | Linux/macOS: `zvpn0`; Windows: `ZVPN` | Name of the TUN/utun/Wintun interface. | `--tun-name zvpn0` |
| `--wintun-dll PATH` | `wintun.dll` | Path to the Wintun DLL on Windows. Ignored on other platforms. | `--wintun-dll C:\ZVPN\wintun.dll` |
| `--tun-ipv4 CIDR` | `10.0.0.2/24` | Server-side IPv4 address and prefix for the tunnel interface. | `--tun-ipv4 10.8.0.1/24` |
| `--client-subnet CIDR` | `10.0.0.0/24` | IPv4 subnet used for client tunnel addresses. It must be consistent with the server tunnel address/prefix. | `--client-subnet 10.8.0.0/24` |
| `--mtu N` | `1500` | MTU applied to the tunnel interface where the platform setup supports it. Valid values: `576`–`9000`. The client tunnel MTU and the route's real path MTU matter too. | `--mtu 1360` |
| `--auto-network` | On Linux/Windows; off on macOS | Turn on automatic network setup. On Linux/Windows this is already the default, so the flag is mainly useful when making the intent explicit. | `--auto-network` |
| `--no-auto-network` | Off | Disable automatic IPv4 forwarding/NAT/firewall/interface configuration. You must configure the relevant networking yourself. | `--no-auto-network` |
| `--wan-interface IFACE` | Detected from default route | Outbound/WAN interface used by automatic network setup. | `--wan-interface eth0` |

**Subnet example:** if the server uses `10.8.0.1/24` and the client subnet is `10.8.0.0/24`, each client needs a different unused inner IP from that subnet. Do not assign the same VPN address to two simultaneous clients, and do not overlap the VPN subnet with a network that must be reached through the tunnel.

**IPv4-only warning:** automatic forwarding/NAT in this build is IPv4-only. IPv6 packets may be logged as unroutable/dropped. Setting a different TUN MTU does not enable IPv6 support.

### Batch sizing and timing

| Option | Default | Accepted values | What it does | Example |
|---|---:|---|---|---|
| `--max-batch BYTES` | `262144` (256 KiB) | `4096`–`4194304` (4 MiB) | Sets the uncompressed batch/protocol-buffer ceiling and the initial outgoing batch target. | `--max-batch 1048576` |
| `--batch-size BYTES` | `262144` (256 KiB) | `4096`–`4194304` (4 MiB) | Alias for `--max-batch`. Also used as the initial server-to-client/download batching target. During auto-tuning, candidate targets can be lower than the fixed ceiling. | `--batch-size 4194304` |
| `--flush-ms MS` | `20` | `0`–`60000` | Maximum normal age of a server-to-client batch before it is sent. Higher values can let more packets collect, but add latency. `0` effectively flushes as packets are queued, so normal batching is disabled. | `--flush-ms 250` |

`BYTES` means bytes, not KiB or MiB. Common values:

| Size | Bytes to enter |
|---|---:|
| 4 KiB | `4096` |
| 16 KiB | `16384` |
| 64 KiB | `65536` |
| 128 KiB | `131072` |
| 256 KiB | `262144` |
| 1 MiB | `1048576` |
| 4 MiB | `4194304` |

The size limit is a **maximum**, not a promise that every batch will be that large. Batches can flush early due to low traffic, the flush timeout, or other protocol/runtime conditions.

### Zstandard settings

| Option | Default | What it does | Example |
|---|---|---|---|
| `--compression-level N` | `3` | Zstandard compression level for **server-to-client/download** batches. Must be at least `1` and no greater than the maximum accepted by the linked Zstandard library. Higher levels may use more CPU and are not guaranteed to save more bytes. | `--compression-level 5` |
| `--min-batch BYTES` | `0` | Minimum batch size at which the server attempts Zstandard compression. Smaller batches are sent raw. `0` tries compression for every eligible batch. Must not exceed the configured batch ceiling. | `--min-batch 16384` |
| `--min-compress-batch N` | Same as `--min-batch` | Alias for `--min-batch`; the value is in bytes despite the shorter alias name. | `--min-compress-batch 4096` |
| `--min-batch-wait-ms MS` | `0` (disabled) | Gives a batch that is still below `--min-batch` additional time to collect packets beyond the usual `--flush-ms` age. The value is the maximum total age in milliseconds, not additional time added to `--flush-ms`. See the next section. | `--min-batch-wait-ms 1500` |
| `--no-compression` | Compression on | Disables server-side Zstandard compression. Packets are still batched/framed and sent as raw batch payloads. | `--no-compression` |

Compression settings described in this table control the server's **download direction** (TUN → client). The Android client compresses its upload direction (client → server); server command-line compression level does not control the client's compressor.

### Logging, UI, and testing

| Option | Default | What it does | Example |
|---|---|---|---|
| `--verbose` | Off | Enables debug logs, including packet metadata and detailed batch/compression messages. The source does not log packet payload contents as part of the normal verbose packet descriptions. Verbose logging can add overhead and distort performance tests. | `--verbose` |
| `--no-tui` | TUI when attached to an interactive terminal | Disables the alternate-screen interactive terminal UI and uses plain logs. Helpful for service managers, SSH log capture, and redirected output. | `--no-tui` |
| `--log-file PATH` | `zvpn-server.log` in the current working directory | Writes logs to the specified path. Use `none` to disable the log file. Console/plain logs may still be shown according to the execution mode. | `--log-file /var/log/zvpn-server.log` or `--log-file none` |
| `--auto-benchmark SEC` | Disabled | Automatically runs the eight-profile live download-compression comparison at startup. Valid duration: `60`–`3600` seconds total. Details and limitations are below. | `--auto-benchmark 120` |
| `--help` | — | Prints the command-line help and exits. | `./zvpn-server --help` |

### Automatic network configuration

| Option | Meaning | When to use it |
|---|---|---|
| `--auto-network` | Enable automatic IPv4 network configuration. | On Linux/Windows this is the default; use it when you want the server to set up the supported interface, forwarding, NAT, and firewall rules. |
| `--no-auto-network` | Do not change forwarding/NAT/firewall settings automatically. | Use only when you have already configured the tunnel, routes, forwarding, and NAT/firewall yourself. |
| `--wan-interface IFACE` | Choose the external interface for the automatic network setup. | Use if automatic detection chooses the wrong uplink; on a typical VPS it may be `eth0`, but verify with `ip route`. |

On Linux and Windows, automatic network changes require elevated permissions and can interact with existing firewall/NAT rules. On Windows, an existing WinNAT configuration may conflict with the NAT setup used by the server. Read the startup logs and check the active routes/firewall after starting the server.

---

## 📦 Batching, compression, and waiting

### `--batch-size` is a target, not a promise

Think of the batch target as the size at which the server will stop adding more packets to the current outgoing batch. If traffic is sparse, the flush timer may fire long before the target is reached. A 4 MiB target does **not** mean the server automatically waits until 4 MiB of data exists.

### `--min-batch` skips compression; it does not collect packets

For example:

```bash
--batch-size 262144 --flush-ms 250 --min-batch 16384
```

The server uses a 256 KiB target and normally sends a batch after 250 ms. If the outgoing batch is smaller than 16 KiB, it skips the Zstandard attempt and sends the batch raw. This saves compression work on tiny batches but can reduce total byte savings.

### `--min-batch-wait-ms` lets an under-sized batch wait longer

Example:

```bash
--batch-size 262144 --flush-ms 250 \
  --min-batch 16384 --min-batch-wait-ms 1500
```

In plain terms:

1. A batch starts collecting packets.
2. Under normal operation, it would be sent when it reaches the batch target or reaches 250 ms of age.
3. If it is still smaller than 16 KiB at the normal deadline, it may continue collecting packets.
4. If the batch reaches the 16 KiB threshold, it no longer qualifies for the extended under-minimum wait and is flushed according to normal age/size rules.
5. If it never reaches 16 KiB, it is still forced out when its total age reaches 1500 ms.

The option is **bounded**; a batch cannot wait indefinitely. It is disabled by default because it can increase latency for low-volume traffic. Current argument validation requires all of the following when waiting is enabled:

- `--min-batch` must be greater than `0`.
- `--flush-ms` must be greater than `0`.
- `--min-batch-wait-ms` must be greater than `--flush-ms`.
- The minimum size must not exceed the initial `--batch-size` target or the maximum batch ceiling.

### Suggested starting profiles

These are starting points for testing, not universally optimal values:

**Low latency / interactive use**

```bash
--batch-size 262144 --flush-ms 20 --compression-level 1 --min-batch 0
```

**Balanced starting point**

```bash
--batch-size 1048576 --flush-ms 100 --compression-level 3 --min-batch 0
```

**Try larger batches for bulk downloads**

```bash
--batch-size 4194304 --flush-ms 250 --compression-level 3 --min-batch 0
```

**Skip Zstandard on tiny batches to reduce CPU work**

```bash
--batch-size 1048576 --flush-ms 100 --compression-level 3 --min-batch 4096
```

**Wait briefly for small batches to reach a threshold**

```bash
--batch-size 1048576 --flush-ms 100 \
  --min-batch 16384 --min-batch-wait-ms 500 \
  --compression-level 3
```

Use the same workload when comparing these profiles. Increasing batch size or waiting longer may improve compression for repetitive data, but neither can remove encryption from HTTPS/TLS/QUIC payloads.

---

## 🔬 Benchmarking and auto-tuning

### Interactive benchmark/diagnostics page

When the TUI is enabled, press **`M`** to display the benchmark and diagnosis view. It presents separate upload and download results, the combined payload result, batch-size distribution, CPU, RSS, compression timings, and possible explanations for the current behavior.

Press **`I`** to write a diagnostic report to the log, or **`S`** to write both a statistics snapshot and the diagnosis. These commands are useful when collecting information to troubleshoot low savings.

### Automatic benchmark: `--auto-benchmark SEC`

Example:

```bash
sudo ./build/linux/zvpn-server \
  --batch-size 4194304 \
  --flush-ms 250 \
  --compression-level 3 \
  --auto-benchmark 120
```

The server compares **eight live server-to-client/download profiles** sequentially over the requested total duration. For a 120-second run, each profile gets about 15 seconds of measurement. Profiles vary the outgoing batch target, flush delay, compression level, and minimum compression threshold. The test does not replay an identical packet trace and does not directly optimize Android upload compression.

#### What the auto-tuner requires

- Zstandard compression must be enabled; do not combine with `--no-compression`.
- The starting `--batch-size`/batch ceiling must be at least **128 KiB** (`131072` bytes).
- A connected client and real batch traffic must exist. The tuner waits for them before measuring profiles.
- Each profile needs at least **128 KiB of original download payload and four outgoing batches** to count as valid.
- To compare profiles fairly, keep one representative, steady download workload running for the whole test. Avoid changing apps, videos, or user behavior halfway through.

The duration is the total measurement window, not the time the tuner may spend waiting for a client and active traffic to appear.

#### How the winner is chosen

For each profile the server records original bytes, encoded bytes, saved bytes, savings percentage, average batch size, saved bytes per second, CPU, and memory. It ignores profiles with insufficient traffic. Among valid results, it prefers the highest weighted savings percentage; near ties (within 0.05 percentage points), it uses saved bytes per second as the tie-breaker. The winning profile is applied **live** and the recommended startup arguments are logged.

The tuner selects the best valid profile from the eight it tested; it does **not** prove that the setting is globally optimal. Because the profiles run one after another on live traffic, changes in content or bitrate can bias the result. Repeat the test, then run the winning configuration on the same workload before treating it as a reliable result.

The program permits one auto-benchmark run per server process. If the run is not started at startup, press **`A`** in the interactive UI to start it. Restart the process to perform a new search.

### What it does not optimize

The auto-tuner does not directly optimize:

- Android client-to-server/upload compression settings;
- `--min-batch-wait-ms` (it preserves the configured wait value while testing profiles);
- MTU or route settings;
- physical network-interface overhead, TCP retransmissions, or end-to-end speed.

For a cleaner compression test, start with `--min-batch-wait-ms 0`, avoid verbose packet logging, and measure the same download traffic. If you are testing the waiting feature itself, compare it in a separate controlled run.

---

## 🖥️ Interactive console controls

The terminal interface is enabled automatically when the program runs with an interactive terminal, unless `--no-tui` is specified. If input/output is redirected or no interactive terminal is available, the server switches to plain logs.

| Key | Action | Notes |
|---|---|---|
| `Q` | Stop the server | Initiates shutdown/cleanup for configuration changes managed by this run. |
| `H` or `?` | Show/hide help | Displays a list of interactive keys. |
| `D` | Dashboard / return | Returns to the main dashboard from other pages. |
| `S` | Log statistics and diagnosis | Writes a snapshot to the log; useful for reports. |
| `I` | Log diagnostics | Writes compression, batch, CPU, and memory metrics plus likely causes. |
| `M` | Benchmark view | Opens the benchmark and diagnosis page. |
| `A` | Start auto-tuning | Starts the configured duration (or 120 seconds if none was configured). One run per process. |
| `C` | Toggle server-to-client compression | Affects download compression only; Android upload compression is client-side. |
| `+` or `=` | Increase Zstandard level | Higher levels may use more CPU. |
| `-` | Decrease Zstandard level | Cannot go below level 1. |
| `[` | Decrease flush age | Changes the download flush timeout by 25 ms. In the client/ban manager page it can instead navigate pages. |
| `]` | Increase flush age | Changes the download flush timeout by 25 ms. In the client/ban manager page it can instead navigate pages. |
| `T` | Cycle minimum compression size | Cycles through `0`, `4 KiB`, `16 KiB`, `64 KiB`, and `256 KiB` values that fit the current configured ceiling. Smaller batches are sent raw. |
| `R` | Reset counters | Resets global and per-client statistics and restarts the rate/statistics time origin; it does not reset the network interface counters. |
| `B` | Open client/ban manager | Provides peer management. Keys `1`–`8` toggle the selected peer's ban state; `N` changes the list view; `U` unbans all; `[`/`]` browse list pages where supported. |
| `V` | Toggle verbose logs | Enables/disables detailed debug messages. Logging itself can affect performance measurements. |

Changing a setting in the live UI generally changes the current process only. To keep a configuration after restart, put the option in your server launch command or service configuration.

---

## 📊 Understanding the statistics

### Original, encoded, and saved bytes

- **Original**: uncompressed batch payload size measured by the server.
- **Encoded**: payload size actually sent in the ZVPN frame, either compressed or raw.
- **Saved**: original payload bytes minus encoded payload bytes, when positive.
- **Weighted savings**: total saved bytes divided by total original bytes, multiplied by 100.

Conceptually:

```text
savings_percent = (total_original_bytes - total_encoded_bytes)
                  / total_original_bytes * 100
```

The server's payload counters exclude the 16-byte ZVPN frame header and the outer TCP/IP headers. They also do not subtract retransmissions or directly measure physical NIC usage. Packet batch records contain a 4-byte length field for each IP packet, so the batch payload counters are not exactly the same as the sum of raw IP packet lengths.

### Upload and download are different measurements

| Direction | What is measured | Which side compresses? |
|---|---|---|
| Upload / client → server | Batches received from Android | Android client |
| Download / server → client | Batches written from server TUN toward Android | Server |
| Combined | Sum of the two payload measurements | Both, using their own settings |

That means a server-side `--compression-level` change affects only the download side. It does not increase the Android client's upload compression level.

### Why may HTTPS traffic save very little?

HTTPS/TLS and QUIC commonly carry encrypted application data. Encrypted bytes usually have little remaining repetition for a generic compressor to exploit. Zstandard may still compress repeated packet headers or other structure in the batch, but savings of only a few percent may be entirely plausible for encrypted workloads.

Larger batches and higher compression levels can help when there is repeated, compressible data across packets. They cannot reconstruct redundancy that has already been hidden by encryption. To compare compression correctly, run the same content and workload through the configurations you are testing.

### CPU and memory

The UI and diagnostics report **process** resource usage:

- **CPU** is normalized to one logical core. `100%` means approximately one whole core. A multithreaded process can exceed `100%` on systems with multiple cores.
- **RSS** is the process's current resident memory (roughly, memory currently resident in RAM).
- **Peak RSS** is the highest resident-memory value observed/reported by the process during this run.
- **Warming-up / n/a** means a valid sample is not available yet or the platform could not provide that metric.

These numbers are not total machine CPU/RAM usage. Use system tools such as `top`, `htop`, `ps`, Task Manager, or platform-specific tools when you need host-wide resource use.

---

## 🌍 Networking and MTU

### Default network layout

On Linux/Windows the default network settings are:

| Setting | Default |
|---|---|
| Server tunnel address | `10.0.0.2/24` |
| Client subnet | `10.0.0.0/24` |
| Linux tunnel name | `zvpn0` |
| Windows interface name | `ZVPN` |
| MTU | `1500` |
| Server listen address / port | `0.0.0.0:61130` |

Automatic networking enables/configures supported IPv4 forwarding, NAT, and firewall/interface rules. On Linux it manages the TUN interface and relevant IPv4 rules; on Windows it uses Windows networking cmdlets and Wintun and may conflict with an existing WinNAT instance. On macOS, configure networking separately.

### Example for a physical network with a 1400-byte MTU

If your VPS physical interface has a path MTU of 1400 bytes, a tunnel MTU such as 1360 may be a useful test:

```bash
--mtu 1360
```

The Android VPN interface must be configured consistently with the server tunnel MTU. The correct value depends on your network path, encapsulation, and transport. A lower MTU can reduce fragmentation/PMTU problems but does not directly improve the compressibility of the payload.

### Check the active Linux MTU and routes

```bash
ip link show zvpn0
ip route
ip route get 1.1.1.1
```

Check the server's actual routes, tunnel address, forwarding, and firewall rules if the client connects but cannot reach the Internet. The program log reports whether auto-network setup succeeded and warns when it is disabled.

---

## 🩺 Troubleshooting

### The server cannot open the tunnel interface

- On Linux, run with the required privileges and confirm `/dev/net/tun` is available.
- On Windows, use an Administrator terminal and confirm the correct `wintun.dll` is present and loadable.
- On macOS, confirm `utun` permissions and configure the required routes manually.
- Read the first `[ERROR]` or `[NETCFG]` messages; later routing errors may be secondary to initialization failure.

### The client cannot connect to the server

1. Check that the server process is running and listening on the expected TCP port.
2. Check cloud security groups, host firewall rules, port forwarding, and the server's bind address.
3. If `--allow-client` is configured, ensure it exactly matches the client's observed public/peer IP.
4. Remember that the client must connect to the server's TCP port, not the TUN address.
5. Do not assume an accepted TCP connection means the tunnel's network routes or NAT are correctly configured.

### The client connects, but webpages do not load

- Confirm the client received a unique inner IPv4 address in the configured subnet.
- Confirm the server tunnel address/subnet, client VPN address, MTU, default route, and DNS settings agree.
- On Linux/Windows, confirm automatic networking succeeded; check forwarding and NAT/firewall rules if you use `--no-auto-network`.
- The server's automatic forwarding/NAT is IPv4-only in this build. IPv6-only destinations may fail.
- Check for logs such as `No connected client owns destination address`. These mean a packet was routed toward a VPN IP for which no connected client is currently registered; inspect client assignment/disconnection logs.
- A successful ZVPN TCP connection does not prove the return route is correct.

### Compression savings are low

1. Press `I` or `S`, then examine **download** savings separately from upload.
2. Check the average outgoing batch size and how many batches skip Zstandard due to `--min-batch`.
3. If average batches are small, test a longer `--flush-ms` using the same workload, accepting the added latency.
4. Try compression levels `1`, `3`, and `5` rather than assuming a very high level must save more.
5. If the batches are already large and savings remain low, encrypted HTTPS/TLS/QUIC or pre-compressed traffic may be the main limitation.
6. Use `--auto-benchmark 120` with a continuous, representative download to compare the supported profiles. Then repeat the winning profile with the same content.
7. Compare physical NIC counters separately if the real goal is reducing carrier/VPS traffic. Payload-level savings do not account for all transport overhead.

### Auto-tuning says there is not enough traffic

- Keep an Android client connected and actively downloading throughout the test.
- Increase `--auto-benchmark` duration if throughput is low.
- Ensure `--batch-size` is at least `131072` bytes and Zstandard is enabled.
- The program needs at least 128 KiB of original download payload and four outgoing batches for each candidate to be valid.
- Only one auto-tuning run is allowed per process; restart the server to run a fresh test.

### CPU usage is high

- Compare levels `1`, `3`, and `5` under the same workload.
- Turn off `--verbose` during the measurement because per-packet logging can add overhead.
- Consider setting `--min-batch 4096` or `--min-batch 16384` to skip attempts on tiny batches, but measure the effect on total savings.
- Do not raise the Zstandard level without checking whether the extra bytes saved justify the CPU cost.

### The log file appears in an unexpected directory

The default `zvpn-server.log` path is relative to the **current working directory**, not necessarily the folder containing the executable. Use an absolute path with `--log-file /path/to/zvpn-server.log` to avoid confusion.

---

## 📌 Known limitations

- ZVPN v1 as implemented here has **no built-in authentication or encryption**.
- Automatic forwarding/NAT is IPv4-only in this build; IPv6 forwarding/NAT is not enabled.
- Automatic network configuration is supported on Linux and Windows but not automated on macOS.
- `--allow-client` filters one numeric peer IP; it is not a credential system and does not replace a secure transport.
- There are up to 32 concurrent client slots. Each active client must have a unique inner VPN IPv4 address so returned packets can be routed to the correct client.
- `--compression-level` affects server-to-client/download compression only. Upload compression is performed by the Android client.
- The automatic tuner compares eight configurations using sequential live traffic. Changing content or bitrate during the test can bias the winner.
- Payload savings are not a measurement of total real-world data use at the physical network interface.
- Windows and macOS builds require verification on their respective toolchains and systems; a Linux build passing does not automatically prove those builds work on every target environment.

---

## 🧾 Defaults at a glance

| Setting | Default |
|---|---|
| Listen | `0.0.0.0:61130` |
| Allowed peer IP | Any |
| Linux tunnel name | `zvpn0` |
| Windows tunnel name | `ZVPN` |
| Server tunnel IPv4 | `10.0.0.2/24` |
| Client subnet | `10.0.0.0/24` |
| MTU | `1500` |
| Batch ceiling / initial target | `262144` bytes (256 KiB) |
| Minimum size before attempting Zstandard | `0` bytes (try all sizes) |
| Under-minimum extra wait | `0` ms (off) |
| Normal download flush age | `20` ms |
| Zstandard | On, level `3` |
| Auto-tuning | Off unless `--auto-benchmark` is supplied or `A` is pressed |
| Verbose logs | Off |
| Log file | `zvpn-server.log` in current working directory |
| Auto IPv4 network setup | On for Linux/Windows; off for macOS |

---

<div align="center">

**Measure first. Change one variable at a time. Repeat the winning test using the same traffic.**

ZVPN Server · C · ZVPN v1 · Zstandard

</div>
