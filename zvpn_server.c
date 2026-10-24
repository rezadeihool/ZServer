/*
 * zvpn_server.c -- portable C server for the Android ZVPN v1 protocol.
 *
 * Compatible wire protocol (must match zvpn_jni.c):
 *   16-byte header:
 *     0..3  "ZVPN"
 *     4     version = 1
 *     5     flags: bit 0 = Zstd compressed payload
 *     6..7  reserved = 0
 *     8..11 uncompressed batch length, big-endian u32
 *     12..15 payload length, big-endian u32
 *   payload:
 *     repeated [packet length: big-endian u32][raw IP packet]
 *
 * Architecture:
 *   client TCP -> decode batch -> write individual IP packets to server TUN
 *   server TUN -> batch individual IP packets -> encode batch -> TCP client
 *
 * This file is C, not C++. It supports Linux TUN, macOS utun, and Windows
 * Wintun (wintun.dll loaded at runtime). It supports up to 32 concurrent
 * clients through a shared TUN reader; each client needs a unique inner IPv4.
 * Linux automatically configures IPv4 TUN address/up, IP forwarding,
 * iptables forwarding/input rules, and source NAT unless --no-auto-network is used.
 * Windows and Linux automatically configure IPv4 networking by default. Windows uses
 * PowerShell NetTCPIP/NetNat/NetSecurity cmdlets and requires an elevated console.
 * macOS networking remains platform-specific and is not automated here.
 *
 * SECURITY: ZVPN v1 is unauthenticated plaintext TCP. Do not expose this
 * listener to untrusted networks or the public Internet without adding a
 * mutually authenticated secure transport compatible with the Android client.
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <zstd.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <process.h>
#include <io.h>
#include <fcntl.h>
#include <conio.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <poll.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#if defined(__linux__)
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/select.h>
#include <sys/time.h>
#elif defined(__APPLE__)
#include <net/if.h>
#include <net/if_utun.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#endif
#endif

#define ZVPN_HEADER_SIZE 16u
#define ZVPN_VERSION 1u
#define ZVPN_FLAG_ZSTD 0x01u
#define ZVPN_DEFAULT_PORT 61130
#define ZVPN_DEFAULT_BATCH (256u * 1024u)
#define ZVPN_MIN_BATCH (4u * 1024u)
#define ZVPN_MAX_BATCH (4u * 1024u * 1024u)
#define ZVPN_MAX_IP_PACKET 65575u
#define ZVPN_READ_TIMEOUT_MS 250
#define ZVPN_TUN_WAIT_MS 100
#define ZVPN_TUNNEL_CAPACITY (4u * 1024u * 1024u)
#define ZVPN_MAX_CLIENTS 32u
#define ZVPN_MAX_BANNED 64u
#define ZVPN_CLIENT_HISTORY 64u
#define ZVPN_TUI_CLIENT_ROWS 8u

#ifdef _WIN32
#define PATH_SEP '\\'
typedef SOCKET socket_t;
#define INVALID_SOCK INVALID_SOCKET
typedef CRITICAL_SECTION mutex_t;
static void mutex_init(mutex_t *m) { InitializeCriticalSection(m); }
static void mutex_destroy(mutex_t *m) { DeleteCriticalSection(m); }
static void mutex_lock(mutex_t *m) { EnterCriticalSection(m); }
static void mutex_unlock(mutex_t *m) { LeaveCriticalSection(m); }
typedef HANDLE thread_t;
typedef DWORD (WINAPI *thread_fn)(LPVOID);
static int thread_start(thread_t *t, thread_fn fn, void *arg) {
    *t = CreateThread(NULL, 0, fn, arg, 0, NULL);
    return *t == NULL ? -1 : 0;
}
static void thread_join(thread_t t) {
    if (t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
}
static void thread_detach(thread_t t) { if (t) CloseHandle(t); }
static void sleep_ms(unsigned ms) { Sleep(ms); }
static int socket_interrupted(int e) { return e == WSAEINTR; }
static int socket_close(socket_t s) { return closesocket(s); }
static int socket_shutdown(socket_t s) { return shutdown(s, SD_BOTH); }
static volatile LONG g_running = 1;
static int app_running(void) { return InterlockedCompareExchange(&g_running, 1, 1) != 0; }
static void app_stop_signal(void) { InterlockedExchange(&g_running, 0); }
#else
#define PATH_SEP '/'
typedef int socket_t;
#define INVALID_SOCK (-1)
typedef pthread_mutex_t mutex_t;
static void mutex_init(mutex_t *m) { (void)pthread_mutex_init(m, NULL); }
static void mutex_destroy(mutex_t *m) { (void)pthread_mutex_destroy(m); }
static void mutex_lock(mutex_t *m) { (void)pthread_mutex_lock(m); }
static void mutex_unlock(mutex_t *m) { (void)pthread_mutex_unlock(m); }
typedef pthread_t thread_t;
typedef void *(*thread_fn)(void *);
static int thread_start(thread_t *t, thread_fn fn, void *arg) {
    return pthread_create(t, NULL, fn, arg);
}
static void thread_join(thread_t t) { (void)pthread_join(t, NULL); }
static void thread_detach(thread_t t) { (void)pthread_detach(t); }
static void sleep_ms(unsigned ms) {
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}
static int socket_close(socket_t s) { return close(s); }
static int socket_shutdown(socket_t s) { return shutdown(s, SHUT_RDWR); }
/* atomic_int is lock-free on the supported Linux/macOS x86 and ARM targets,
 * so the same stop flag can safely be changed by worker threads and signals. */
static atomic_int g_running = ATOMIC_VAR_INIT(1);
static int app_running(void) {
    return atomic_load_explicit(&g_running, memory_order_acquire) != 0;
}
static void app_stop_signal(void) {
    atomic_store_explicit(&g_running, 0, memory_order_release);
}
#endif

typedef enum { LOG_DEBUG = 0, LOG_INFO = 1, LOG_WARN = 2, LOG_ERROR = 3 } LogLevel;

typedef struct {
    uint64_t client_ip_bytes_in;
    uint64_t client_ip_bytes_out;
    uint64_t transport_bytes_received;
    uint64_t transport_bytes_sent;
    uint64_t batches_received;
    uint64_t batches_sent;
    uint64_t compressed_batches_received;
    uint64_t compressed_batches_sent;
    uint64_t payload_original_bytes_received;
    uint64_t payload_encoded_bytes_received;
    uint64_t payload_saved_bytes_received;
    uint64_t payload_original_bytes_sent;
    uint64_t payload_encoded_bytes_sent;
    uint64_t payload_saved_bytes_sent;
    uint64_t packets_received_from_client;
    uint64_t packets_sent_to_client;
    uint64_t rejected_packets;
    uint64_t compression_attempts_sent;
    uint64_t compression_time_us_sent;
    uint64_t decompression_time_us_received;
    uint64_t small_batches_skipped_compression;
    uint64_t tx_batch_hist[7]; /* <=4K, 4-16K, 16-64K, 64-256K, 256K-1M, 1-4M, >4M */
    uint64_t rx_batch_hist[7];
} Stats;

typedef struct {
    char bind_address[128];
    int port;
    char tun_name[128];
    char wintun_dll[512];
    char log_file_path[512];
    /* max_batch_bytes is the immutable protocol/buffer ceiling. The active
     * server-to-client target may be lowered at runtime by the auto-tuner. */
    size_t max_batch_bytes;
    size_t out_batch_target_bytes;
    size_t min_compress_batch_bytes;
    /* If nonzero, under-minimum batches may wait this long (total age) to fill.
     * This only extends flush_timeout_ms when the batch is below the Zstd minimum. */
    int min_batch_wait_ms;
    int flush_timeout_ms;
    int compression_level;
    int auto_benchmark_seconds;
    int compression_enabled;
    int verbose;
    int tui;
    int allow_any_client;
    char allowed_client[128];
    int auto_network;
    int mtu;
    char wan_interface[128];
    char tun_ipv4_cidr[64];
    char client_subnet_cidr[64];
} Config;

typedef struct {
    mutex_t lock;
    Stats stats;
} StatsStore;

#if defined(__linux__)
typedef struct {
    int active;
    int old_ip_forward;
    int changed_ip_forward;
    int added_nat_rule;
    int added_forward_rule;
    int added_return_rule;
    int added_input_rule;
    char wan_interface[128];
} LinuxNetworkState;
#elif defined(_WIN32)
typedef struct {
    int active;
    int added_ip_address;
    int added_nat;
    int added_client_firewall_rule;
    int added_listener_firewall_rule;
    int changed_tun_forwarding;
    int changed_wan_forwarding;
    int changed_mtu;
    unsigned long old_mtu;
    char old_tun_forwarding[16];
    char old_wan_forwarding[16];
    char wan_interface[128];
} WindowsNetworkState;
#endif

typedef struct {
    int used;
    int active;
    char ip[INET6_ADDRSTRLEN];
    char endpoint[128];
    uint64_t connected_ms;
    uint64_t last_seen_ms;
    uint64_t sessions;
    uint64_t download_ip_bytes;
    uint64_t upload_ip_bytes;
    uint64_t download_original;
    uint64_t download_encoded;
    uint64_t download_saved;
    uint64_t upload_original;
    uint64_t upload_encoded;
    uint64_t upload_saved;
} ClientStats;

typedef struct {
    mutex_t lock;
    ClientStats rows[ZVPN_CLIENT_HISTORY];
} ClientStatsStore;

typedef struct {
    uint64_t rss_bytes;
    uint64_t peak_rss_bytes;
    double cpu_percent;
    int cpu_valid;
    int memory_valid;
} ResourceUsage;

typedef struct App App;

typedef struct {
    App *app;
    socket_t socket;
    ClientStats *stats_record;
    char endpoint[128];
    uint32_t tunnel_ip_host;
    int has_tunnel_ip;
    uint8_t *out_batch;
    size_t out_used;
    uint64_t out_batch_started_ms;
#ifdef _WIN32
    volatile LONG stop;
#else
    atomic_int stop;
#endif
    char peer[128];
} Client;

typedef struct {
    App *app;
#ifdef _WIN32
    HMODULE module;
    void *adapter;
    void *session;
    HANDLE read_event;
    void *(WINAPI *open_adapter)(LPCWSTR);
    void *(WINAPI *create_adapter)(LPCWSTR, LPCWSTR, const GUID *);
    void (WINAPI *close_adapter)(void *);
    void *(WINAPI *start_session)(void *, DWORD);
    void (WINAPI *end_session)(void *);
    HANDLE (WINAPI *get_read_wait_event)(void *);
    BYTE *(WINAPI *receive_packet)(void *, DWORD *);
    void (WINAPI *release_receive_packet)(void *, const BYTE *);
    BYTE *(WINAPI *allocate_send_packet)(void *, DWORD);
    void (WINAPI *send_packet)(void *, const BYTE *);
#else
    int fd;
#endif
    char name[128];
} Tun;

struct App {
    Config config;
    FILE *log_file;
    mutex_t log_lock;
    char last_log[512];
    StatsStore stats;
    ClientStatsStore client_stats;
    mutex_t clients_lock;
    Client *clients[ZVPN_MAX_CLIENTS];
    size_t client_count;
    mutex_t bans_lock;
    char banned_ips[ZVPN_MAX_BANNED][INET6_ADDRSTRLEN];
    size_t banned_count;
    int help_visible;
    int tui_page;
    int ban_list_view;
    size_t ban_list_offset;
    Tun tun;
    socket_t listener;
    uint64_t started_ms;
    /* Resource monitor fields are protected by stats.lock. */
    uint64_t resource_prev_sample_ms;
    uint64_t resource_prev_cpu_us;
    uint64_t resource_rss_bytes;
    uint64_t resource_peak_rss_bytes;
    double resource_cpu_percent;
    int resource_cpu_valid;
    /* Single non-detached worker; joined before App is destroyed. */
    thread_t auto_benchmark_thread;
    int auto_benchmark_thread_started;
    int auto_benchmark_active;
    int auto_benchmark_done;
    int auto_profile_index; /* 0 while waiting for traffic, otherwise 1..8 */
    int auto_profile_count;
    int tui_enabled;
#if defined(__linux__)
    LinuxNetworkState linux_net;
#elif defined(_WIN32)
    WindowsNetworkState windows_net;
#endif
};

typedef struct {
    size_t max_batch_bytes;
    size_t out_batch_target_bytes;
    size_t min_compress_batch_bytes;
    int min_batch_wait_ms;
    int flush_timeout_ms;
    int compression_level;
    int compression_enabled;
    int verbose;
    int auto_benchmark_active;
    int auto_benchmark_done;
    int auto_profile_index;
    int auto_profile_count;
    int auto_benchmark_seconds;
    uint64_t started_ms;
} RuntimeSettings;

static uint64_t monotonic_ms(void);
static RuntimeSettings runtime_settings_snapshot(App *app);
static size_t active_client_count(App *app);
static void start_auto_benchmark(App *app, int seconds);
static unsigned batch_size_bucket(size_t bytes);

static ClientStats *client_stats_begin(App *app, const char *ip, const char *endpoint) {
    ClientStats *slot = NULL;
    ClientStats *oldest = NULL;
    mutex_lock(&app->client_stats.lock);
    /* Reuse a prior row for the same endpoint only when it is idle. Multiple
       simultaneous TCP connections from one public IP get independent rows. */
    for (size_t i = 0; i < ZVPN_CLIENT_HISTORY; ++i) {
        ClientStats *row = &app->client_stats.rows[i];
        if (row->used && !row->active && strcmp(row->endpoint, endpoint) == 0) {
            slot = row;
            break;
        }
        if (!row->used && !slot) slot = row;
        if (row->used && !row->active && (!oldest || row->last_seen_ms < oldest->last_seen_ms))
            oldest = row;
    }
    if (!slot) slot = oldest;
    if (slot) {
        uint64_t sessions = (slot->used && strcmp(slot->endpoint, endpoint ? endpoint : "unknown") == 0) ? slot->sessions + 1u : 1u;
        memset(slot, 0, sizeof(*slot));
        slot->used = 1;
        (void)snprintf(slot->ip, sizeof(slot->ip), "%s", ip ? ip : "unknown");
        (void)snprintf(slot->endpoint, sizeof(slot->endpoint), "%s", endpoint ? endpoint : "unknown");
        slot->active = 1;
        slot->connected_ms = monotonic_ms();
        slot->last_seen_ms = slot->connected_ms;
        slot->sessions = sessions;
    }
    mutex_unlock(&app->client_stats.lock);
    return slot;
}

static void client_stats_end(App *app, ClientStats *row) {
    if (!row) return;
    mutex_lock(&app->client_stats.lock);
    row->active = 0;
    row->last_seen_ms = monotonic_ms();
    mutex_unlock(&app->client_stats.lock);
}

static void client_stats_add_download(App *app, ClientStats *row,
                                      uint64_t original, uint64_t encoded,
                                      uint64_t ip_bytes) {
    if (!row) return;
    mutex_lock(&app->client_stats.lock);
    row->download_original += original;
    row->download_encoded += encoded;
    if (original > encoded) row->download_saved += original - encoded;
    row->download_ip_bytes += ip_bytes;
    row->last_seen_ms = monotonic_ms();
    mutex_unlock(&app->client_stats.lock);
}

static void client_stats_add_upload(App *app, ClientStats *row,
                                    uint64_t original, uint64_t encoded,
                                    uint64_t ip_bytes) {
    if (!row) return;
    mutex_lock(&app->client_stats.lock);
    row->upload_original += original;
    row->upload_encoded += encoded;
    if (original > encoded) row->upload_saved += original - encoded;
    row->upload_ip_bytes += ip_bytes;
    row->last_seen_ms = monotonic_ms();
    mutex_unlock(&app->client_stats.lock);
}

static void client_stats_reset(App *app) {
    mutex_lock(&app->client_stats.lock);
    for (size_t i = 0; i < ZVPN_CLIENT_HISTORY; ++i) {
        ClientStats *row = &app->client_stats.rows[i];
        row->download_ip_bytes = row->upload_ip_bytes = 0;
        row->download_original = row->download_encoded = row->download_saved = 0;
        row->upload_original = row->upload_encoded = row->upload_saved = 0;
        row->last_seen_ms = monotonic_ms();
    }
    mutex_unlock(&app->client_stats.lock);
}

static size_t client_stats_snapshot(App *app, ClientStats out[ZVPN_CLIENT_HISTORY]) {
    size_t count = 0;
    mutex_lock(&app->client_stats.lock);
    for (size_t i = 0; i < ZVPN_CLIENT_HISTORY; ++i) {
        if (app->client_stats.rows[i].used) out[count++] = app->client_stats.rows[i];
    }
    mutex_unlock(&app->client_stats.lock);
    for (size_t i = 0; i < count; ++i) {
        for (size_t j = i + 1; j < count; ++j) {
            if (out[j].last_seen_ms > out[i].last_seen_ms) {
                ClientStats tmp = out[i]; out[i] = out[j]; out[j] = tmp;
            }
        }
    }
    return count;
}

#ifdef _WIN32
static BOOL WINAPI console_control_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT) {
        /* The main loop polls select() with a finite timeout; do not race
         * the listener descriptor from this control-handler thread. */
        app_stop_signal();
        return TRUE;
    }
    return FALSE;
}
#else
static void signal_handler(int sig) {
    (void)sig;
    /* atomic_int is lock-free on the supported POSIX targets. */
    app_stop_signal();
}
#endif

static uint64_t monotonic_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

static uint64_t monotonic_us(void) {
#ifdef _WIN32
    LARGE_INTEGER counter, frequency;
    if (!QueryPerformanceCounter(&counter) || !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0)
        return monotonic_ms() * 1000u;
    uint64_t ticks = (uint64_t)counter.QuadPart;
    uint64_t freq = (uint64_t)frequency.QuadPart;
    return (ticks / freq) * 1000000u + ((ticks % freq) * 1000000u) / freq;
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return monotonic_ms() * 1000u;
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
#endif
}

static RuntimeSettings runtime_settings_snapshot(App *app) {
    RuntimeSettings r;
    memset(&r, 0, sizeof(r));
    /* Separate locks, in the same order used by the tuner, avoid lock inversion. */
    mutex_lock(&app->clients_lock);
    r.out_batch_target_bytes = app->config.out_batch_target_bytes;
    r.min_batch_wait_ms = app->config.min_batch_wait_ms;
    r.flush_timeout_ms = app->config.flush_timeout_ms;
    mutex_unlock(&app->clients_lock);
    r.max_batch_bytes = app->config.max_batch_bytes; /* immutable after startup */
    mutex_lock(&app->log_lock);
    r.min_compress_batch_bytes = app->config.min_compress_batch_bytes;
    r.compression_level = app->config.compression_level;
    r.compression_enabled = app->config.compression_enabled;
    r.verbose = app->config.verbose;
    r.auto_benchmark_active = app->auto_benchmark_active;
    r.auto_benchmark_done = app->auto_benchmark_done;
    r.auto_profile_index = app->auto_profile_index;
    r.auto_profile_count = app->auto_profile_count;
    r.auto_benchmark_seconds = app->config.auto_benchmark_seconds;
    r.started_ms = app->started_ms;
    mutex_unlock(&app->log_lock);
    return r;
}

/* Process CPU time in microseconds; percent is normalized to one logical core
 * (100% means one fully occupied core; multi-threaded use may exceed 100%). */
static uint64_t process_cpu_time_us(void) {
#ifdef _WIN32
    FILETIME creation, exit_time, kernel, user;
    ULARGE_INTEGER k, u;
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit_time, &kernel, &user)) return 0;
    k.LowPart = kernel.dwLowDateTime; k.HighPart = kernel.dwHighDateTime;
    u.LowPart = user.dwLowDateTime; u.HighPart = user.dwHighDateTime;
    return (uint64_t)((k.QuadPart + u.QuadPart) / 10u); /* 100 ns -> us */
#else
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return 0;
    return (uint64_t)ru.ru_utime.tv_sec * 1000000u + (uint64_t)ru.ru_utime.tv_usec +
           (uint64_t)ru.ru_stime.tv_sec * 1000000u + (uint64_t)ru.ru_stime.tv_usec;
#endif
}

static void process_memory_bytes(uint64_t *rss_bytes, uint64_t *peak_bytes) {
    *rss_bytes = 0;
    *peak_bytes = 0;
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX pmc;
    memset(&pmc, 0, sizeof(pmc));
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS *)&pmc, sizeof(pmc))) {
        *rss_bytes = (uint64_t)pmc.WorkingSetSize;
        *peak_bytes = (uint64_t)pmc.PeakWorkingSetSize;
    }
#elif defined(__linux__)
    FILE *f = fopen("/proc/self/statm", "r");
    unsigned long total_pages = 0, resident_pages = 0;
    if (f) {
        if (fscanf(f, "%lu %lu", &total_pages, &resident_pages) == 2) {
            long page_size = sysconf(_SC_PAGESIZE);
            if (page_size > 0) *rss_bytes = (uint64_t)resident_pages * (uint64_t)page_size;
        }
        fclose(f);
    }
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0 && ru.ru_maxrss > 0)
        *peak_bytes = (uint64_t)ru.ru_maxrss * 1024u; /* Linux reports KiB */
#elif defined(__APPLE__)
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    memset(&info, 0, sizeof(info));
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  (task_info_t)&info, &count) == KERN_SUCCESS)
        *rss_bytes = (uint64_t)info.resident_size;
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0 && ru.ru_maxrss > 0)
        *peak_bytes = (uint64_t)ru.ru_maxrss; /* macOS reports bytes */
#else
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0 && ru.ru_maxrss > 0) {
        *rss_bytes = (uint64_t)ru.ru_maxrss * 1024u;
        *peak_bytes = *rss_bytes;
    }
#endif
    if (*peak_bytes < *rss_bytes) *peak_bytes = *rss_bytes;
}

/* Call from UI/diagnostic paths. stats.lock serializes sampling state across
 * the TUI and command thread. */
static ResourceUsage resource_usage_snapshot(App *app) {
    ResourceUsage r;
    memset(&r, 0, sizeof(r));
    mutex_lock(&app->stats.lock);
    uint64_t now_ms = monotonic_ms();
    uint64_t cpu_us = process_cpu_time_us();
    uint64_t rss = 0, peak = 0;
    process_memory_bytes(&rss, &peak);
    if (app->resource_prev_sample_ms != 0 && now_ms > app->resource_prev_sample_ms &&
        now_ms - app->resource_prev_sample_ms >= 500u) {
        uint64_t wall_us = (now_ms - app->resource_prev_sample_ms) * 1000u;
        if (cpu_us >= app->resource_prev_cpu_us && wall_us > 0) {
            app->resource_cpu_percent = 100.0 * (double)(cpu_us - app->resource_prev_cpu_us) / (double)wall_us;
            app->resource_cpu_valid = 1;
        }
        app->resource_prev_sample_ms = now_ms;
        app->resource_prev_cpu_us = cpu_us;
    } else if (app->resource_prev_sample_ms == 0) {
        app->resource_prev_sample_ms = now_ms;
        app->resource_prev_cpu_us = cpu_us;
    }
    app->resource_rss_bytes = rss;
    if (peak > app->resource_peak_rss_bytes) app->resource_peak_rss_bytes = peak;
    r.rss_bytes = app->resource_rss_bytes;
    r.peak_rss_bytes = app->resource_peak_rss_bytes;
    r.cpu_percent = app->resource_cpu_percent;
    r.cpu_valid = app->resource_cpu_valid;
    r.memory_valid = rss > 0 || peak > 0;
    mutex_unlock(&app->stats.lock);
    return r;
}

static unsigned batch_size_bucket(size_t bytes) {
    if (bytes <= 4u * 1024u) return 0;
    if (bytes <= 16u * 1024u) return 1;
    if (bytes <= 64u * 1024u) return 2;
    if (bytes <= 256u * 1024u) return 3;
    if (bytes <= 1024u * 1024u) return 4;
    if (bytes <= 4u * 1024u * 1024u) return 5;
    return 6;
}

static const char *level_name(LogLevel level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO: return "INFO ";
        case LOG_WARN: return "WARN ";
        default: return "ERROR";
    }
}

static const char *log_ansi_color(LogLevel level) {
    switch (level) {
        case LOG_DEBUG: return "\033[36m"; /* cyan */
        case LOG_INFO:  return "\033[32m"; /* green */
        case LOG_WARN:  return "\033[33m"; /* yellow */
        default:        return "\033[31;1m"; /* bright red */
    }
}

static void log_message(App *app, LogLevel level, const char *fmt, ...) {
    if (!app) return;

    /* Runtime commands may change verbosity while workers are logging. */
    int verbose_now;
    mutex_lock(&app->log_lock);
    verbose_now = app->config.verbose;
    mutex_unlock(&app->log_lock);
    if ((int)level < (verbose_now ? LOG_DEBUG : LOG_INFO)) return;

    char body[1024];
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(body, sizeof(body), fmt, args);
    va_end(args);

    time_t now = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &now);
#else
    localtime_r(&now, &tmv);
#endif
    char timestamp[32];
    (void)strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tmv);

    char line[1536];
    (void)snprintf(line, sizeof(line), "%s %-5s %s", timestamp,
                   level_name(level), body);

    mutex_lock(&app->log_lock);
    (void)snprintf(app->last_log, sizeof(app->last_log), "%.511s", line);
    if (app->log_file) {
        (void)fprintf(app->log_file, "%s\n", line);
        (void)fflush(app->log_file);
    }
    if (!app->tui_enabled) {
#ifndef _WIN32
        if (isatty(STDERR_FILENO))
            (void)fprintf(stderr, "%s%s\033[0m\n", log_ansi_color(level), line);
        else
#endif
            (void)fprintf(stderr, "%s\n", line);
        (void)fflush(stderr);
    }
    mutex_unlock(&app->log_lock);
}

#define STAT_ADD(app, field, value) do { \
    mutex_lock(&(app)->stats.lock); \
    (app)->stats.stats.field += (uint64_t)(value); \
    mutex_unlock(&(app)->stats.lock); \
} while (0)

static Stats stats_snapshot(App *app) {
    Stats s;
    mutex_lock(&app->stats.lock);
    s = app->stats.stats;
    mutex_unlock(&app->stats.lock);
    return s;
}

static void put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int parse_ipv4_port(const uint8_t *p, size_t len, uint16_t *src, uint16_t *dst) {
    if (len < 20 || (p[0] >> 4) != 4) return 0;
    size_t ihl = (size_t)(p[0] & 0x0f) * 4u;
    if (ihl < 20 || ihl + 4 > len) return 0;
    if (p[9] != 6 && p[9] != 17) return 0;
    *src = (uint16_t)(((uint16_t)p[ihl] << 8) | p[ihl + 1]);
    *dst = (uint16_t)(((uint16_t)p[ihl + 2] << 8) | p[ihl + 3]);
    return 1;
}

static int get_ip_version(const uint8_t *p, size_t len) {
    if (len == 0) return 0;
    int v = (p[0] >> 4) & 0x0f;
    if ((v == 4 && len >= 20) || (v == 6 && len >= 40)) return v;
    return 0;
}

static const char *protocol_name(const uint8_t *p, size_t len) {
    int v = get_ip_version(p, len);
    if (v == 4) {
        switch (p[9]) { case 6: return "TCP"; case 17: return "UDP"; case 1: return "ICMP"; default: return "IPv4-other"; }
    }
    if (v == 6) {
        switch (p[6]) { case 6: return "TCP"; case 17: return "UDP"; case 58: return "ICMPv6"; default: return "IPv6/extension"; }
    }
    return "invalid-IP";
}

static void describe_packet(char *dst, size_t cap, const uint8_t *p, size_t len) {
    uint16_t sport, dport;
    int v = get_ip_version(p, len);
    if (v == 4) {
        char src_addr[INET_ADDRSTRLEN] = "?";
        char dst_addr[INET_ADDRSTRLEN] = "?";
        (void)inet_ntop(AF_INET, p + 12, src_addr, sizeof(src_addr));
        (void)inet_ntop(AF_INET, p + 16, dst_addr, sizeof(dst_addr));
        if (parse_ipv4_port(p, len, &sport, &dport)) {
            (void)snprintf(dst, cap, "IPv4 %s %s:%u -> %s:%u %zuB",
                           protocol_name(p, len), src_addr, sport, dst_addr, dport, len);
        } else {
            (void)snprintf(dst, cap, "IPv4 %s %s -> %s %zuB",
                           protocol_name(p, len), src_addr, dst_addr, len);
        }
        return;
    }
    if (v == 6) {
        char src_addr[INET6_ADDRSTRLEN] = "?";
        char dst_addr[INET6_ADDRSTRLEN] = "?";
        (void)inet_ntop(AF_INET6, p + 8, src_addr, sizeof(src_addr));
        (void)inet_ntop(AF_INET6, p + 24, dst_addr, sizeof(dst_addr));
        if (len >= 44 && (p[6] == 6 || p[6] == 17)) {
            sport = (uint16_t)(((uint16_t)p[40] << 8) | p[41]);
            dport = (uint16_t)(((uint16_t)p[42] << 8) | p[43]);
            (void)snprintf(dst, cap, "IPv6 %s [%s]:%u -> [%s]:%u %zuB",
                           protocol_name(p, len), src_addr, sport, dst_addr, dport, len);
        } else {
            (void)snprintf(dst, cap, "IPv6 %s %s -> %s %zuB",
                           protocol_name(p, len), src_addr, dst_addr, len);
        }
        return;
    }
    (void)snprintf(dst, cap, "invalid-IP %zuB", len);
}

static int validate_ip_packet(const uint8_t *p, size_t len) {
    int v = get_ip_version(p, len);
    if (v == 4) {
        size_t ihl = (size_t)(p[0] & 0x0f) * 4u;
        if (ihl < 20 || ihl > len) return 0;
        uint16_t total = (uint16_t)(((uint16_t)p[2] << 8) | p[3]);
        /* TUN/Wintun returns one whole IP packet. Accepting trailing bytes can
         * forward malformed frames and hide framing/length bugs. */
        return total >= ihl && (size_t)total == len;
    }
    if (v == 6) {
        uint16_t payload = (uint16_t)(((uint16_t)p[4] << 8) | p[5]);
        /* ZVPN's packet limit does not support IPv6 jumbograms. A zero
         * payload length is therefore valid only for the 40-byte base header. */
        return payload == 0 ? len == 40u : ((size_t)payload + 40u == len);
    }
    return 0;
}

static int count_batch_packets(App *app, const uint8_t *batch, size_t len,
                               uint64_t *count_out, uint64_t *ip_bytes_out,
                               int log_packets, const char *direction) {
    size_t off = 0;
    uint64_t count = 0, total_ip_bytes = 0;
    while (off < len) {
        if (len - off < 4) { errno = EPROTO; return -1; }
        uint32_t packet_len = get_u32(batch + off);
        off += 4;
        if (packet_len == 0 || packet_len > ZVPN_MAX_IP_PACKET || packet_len > len - off) {
            errno = EPROTO;
            return -1;
        }
        if (!validate_ip_packet(batch + off, packet_len)) {
            errno = EPROTO;
            return -1;
        }
        if (log_packets) {
            char description[128];
            describe_packet(description, sizeof(description), batch + off, packet_len);
            log_message(app, LOG_DEBUG, "%s packet #%" PRIu64 ": %s", direction, count + 1, description);
        }
        off += packet_len;
        count++;
        total_ip_bytes += packet_len;
    }
    *count_out = count;
    *ip_bytes_out = total_ip_bytes;
    return 0;
}

/* -------------------- Platform-specific TUN -------------------- */
#ifdef _WIN32
static int utf8_to_wide(const char *s, wchar_t *out, int out_count) {
    return MultiByteToWideChar(CP_UTF8, 0, s, -1, out, out_count);
}

#define LOAD_WINTUN(field, symbol, fn_type) do { \
    app->tun.field = (fn_type)GetProcAddress(app->tun.module, symbol); \
    if (!app->tun.field) { \
        log_message(app, LOG_ERROR, "wintun.dll missing symbol %s", symbol); \
        return -1; \
    } \
} while (0)

static int tun_open(App *app) {
    wchar_t adapter_name[128];
    wchar_t tunnel_type[128];
    if (!utf8_to_wide(app->config.tun_name, adapter_name, 128) ||
        !utf8_to_wide("ZVPN", tunnel_type, 128)) {
        log_message(app, LOG_ERROR, "Cannot convert Wintun adapter name to UTF-16");
        return -1;
    }

    app->tun.module = LoadLibraryA(app->config.wintun_dll[0] ? app->config.wintun_dll : "wintun.dll");
    if (!app->tun.module) {
        log_message(app, LOG_ERROR, "Could not load %s (Windows requires the matching Wintun DLL)",
                    app->config.wintun_dll[0] ? app->config.wintun_dll : "wintun.dll");
        return -1;
    }

    LOAD_WINTUN(open_adapter, "WintunOpenAdapter", void *(WINAPI *)(LPCWSTR));
    LOAD_WINTUN(create_adapter, "WintunCreateAdapter", void *(WINAPI *)(LPCWSTR, LPCWSTR, const GUID *));
    LOAD_WINTUN(close_adapter, "WintunCloseAdapter", void (WINAPI *)(void *));
    LOAD_WINTUN(start_session, "WintunStartSession", void *(WINAPI *)(void *, DWORD));
    LOAD_WINTUN(end_session, "WintunEndSession", void (WINAPI *)(void *));
    LOAD_WINTUN(get_read_wait_event, "WintunGetReadWaitEvent", HANDLE (WINAPI *)(void *));
    LOAD_WINTUN(receive_packet, "WintunReceivePacket", BYTE *(WINAPI *)(void *, DWORD *));
    LOAD_WINTUN(release_receive_packet, "WintunReleaseReceivePacket", void (WINAPI *)(void *, const BYTE *));
    LOAD_WINTUN(allocate_send_packet, "WintunAllocateSendPacket", BYTE *(WINAPI *)(void *, DWORD));
    LOAD_WINTUN(send_packet, "WintunSendPacket", void (WINAPI *)(void *, const BYTE *));

    app->tun.adapter = app->tun.open_adapter(adapter_name);
    if (!app->tun.adapter) {
        app->tun.adapter = app->tun.create_adapter(adapter_name, tunnel_type, NULL);
        if (!app->tun.adapter) {
            log_message(app, LOG_ERROR, "WintunCreateAdapter failed (Win32 error %lu)", GetLastError());
            return -1;
        }
        log_message(app, LOG_INFO, "Created Wintun adapter '%s'", app->config.tun_name);
    } else {
        log_message(app, LOG_INFO, "Opened existing Wintun adapter '%s'", app->config.tun_name);
    }

    app->tun.session = app->tun.start_session(app->tun.adapter, ZVPN_TUNNEL_CAPACITY);
    if (!app->tun.session) {
        log_message(app, LOG_ERROR, "WintunStartSession failed (Win32 error %lu)", GetLastError());
        app->tun.close_adapter(app->tun.adapter);
        app->tun.adapter = NULL;
        return -1;
    }
    app->tun.read_event = app->tun.get_read_wait_event(app->tun.session);
    if (!app->tun.read_event) {
        log_message(app, LOG_ERROR, "WintunGetReadWaitEvent failed (Win32 error %lu)", GetLastError());
        app->tun.end_session(app->tun.session);
        app->tun.session = NULL;
        app->tun.close_adapter(app->tun.adapter);
        app->tun.adapter = NULL;
        return -1;
    }
    (void)snprintf(app->tun.name, sizeof(app->tun.name), "%s", app->config.tun_name);
    log_message(app, LOG_INFO, "Wintun session started; automatic network setup runs before the TCP listener opens.");
    return 0;
}

static void tun_close(App *app) {
    if (app->tun.session && app->tun.end_session) app->tun.end_session(app->tun.session);
    app->tun.session = NULL;
    if (app->tun.adapter && app->tun.close_adapter) app->tun.close_adapter(app->tun.adapter);
    app->tun.adapter = NULL;
    if (app->tun.module) FreeLibrary(app->tun.module);
    app->tun.module = NULL;
}

static int tun_read_packet(App *app, uint8_t *buffer, size_t cap, int timeout_ms,
                           size_t *packet_len) {
    *packet_len = 0;
    DWORD wr = WaitForSingleObject(app->tun.read_event, (DWORD)timeout_ms);
    if (wr == WAIT_TIMEOUT) return 0;
    if (wr != WAIT_OBJECT_0) {
        DWORD err = GetLastError();
        log_message(app, LOG_WARN, "Wintun read-event wait failed: wait=%lu Win32 error=%lu",
                    (unsigned long)wr, (unsigned long)err);
        errno = EIO;
        return -1;
    }

    DWORD size = 0;
    BYTE *packet = app->tun.receive_packet(app->tun.session, &size);
    if (!packet) {
        DWORD err = GetLastError();
        if (err == ERROR_NO_MORE_ITEMS) return 0;
        log_message(app, LOG_WARN, "WintunReceivePacket error=%lu", err);
        errno = EIO;
        return -1;
    }
    if (size == 0 || (size_t)size > cap) {
        app->tun.release_receive_packet(app->tun.session, packet);
        errno = EMSGSIZE;
        return -1;
    }
    memcpy(buffer, packet, size);
    app->tun.release_receive_packet(app->tun.session, packet);
    *packet_len = (size_t)size;
    return 1;
}

static int tun_write_packet(App *app, const uint8_t *packet, size_t packet_len) {
    if (packet_len > UINT32_MAX) { errno = EMSGSIZE; return -1; }
    BYTE *dest = app->tun.allocate_send_packet(app->tun.session, (DWORD)packet_len);
    if (!dest) {
        DWORD err = GetLastError();
        log_message(app, LOG_WARN, "WintunAllocateSendPacket failed: %lu", err);
        errno = ENOBUFS;
        return -1;
    }
    memcpy(dest, packet, packet_len);
    app->tun.send_packet(app->tun.session, dest);
    return 0;
}

#else /* POSIX tunnel */
static int tun_open(App *app) {
#if defined(__linux__)
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        log_message(app, LOG_ERROR, "open /dev/net/tun failed: %s", strerror(errno));
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    if (strlen(app->config.tun_name) >= sizeof(ifr.ifr_name)) {
        (void)close(fd);
        log_message(app, LOG_ERROR, "Linux TUN name is too long (maximum %zu characters)", sizeof(ifr.ifr_name) - 1u);
        errno = ENAMETOOLONG;
        return -1;
    }
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    memcpy(ifr.ifr_name, app->config.tun_name, strlen(app->config.tun_name) + 1u);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int e = errno;
        (void)close(fd);
        log_message(app, LOG_ERROR, "TUNSETIFF for '%s' failed: %s (run with CAP_NET_ADMIN/root)",
                    app->config.tun_name, strerror(e));
        errno = e;
        return -1;
    }
    app->tun.fd = fd;
    (void)snprintf(app->tun.name, sizeof(app->tun.name), "%s", ifr.ifr_name);
    log_message(app, LOG_INFO, "Linux TUN interface '%s' created/opened", app->tun.name);
    return 0;
#elif defined(__APPLE__)
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        log_message(app, LOG_ERROR, "utun socket failed: %s", strerror(errno));
        return -1;
    }
    struct ctl_info ctl;
    memset(&ctl, 0, sizeof(ctl));
    {
        const char *control_name = "com.apple.net.utun_control";
        if (strlen(control_name) >= sizeof(ctl.ctl_name)) {
            close(fd);
            errno = ENAMETOOLONG;
            log_message(app, LOG_ERROR, "utun control name is too long for this SDK");
            return -1;
        }
        memcpy(ctl.ctl_name, control_name, strlen(control_name) + 1u);
    }
    if (ioctl(fd, CTLIOCGINFO, &ctl) < 0) {
        int e = errno; close(fd); errno = e;
        log_message(app, LOG_ERROR, "CTLIOCGINFO for utun failed: %s", strerror(e));
        return -1;
    }
    struct sockaddr_ctl addr;
    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = ctl.ctl_id;
    addr.sc_unit = 0; /* zero asks the kernel to allocate an unused utunN */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno; close(fd); errno = e;
        log_message(app, LOG_ERROR, "connect utun failed: %s", strerror(e));
        return -1;
    }
    char ifname[IFNAMSIZ] = {0};
    socklen_t iflen = sizeof(ifname);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &iflen) < 0) {
        int e = errno; close(fd); errno = e;
        log_message(app, LOG_ERROR, "getsockopt UTUN_OPT_IFNAME failed: %s", strerror(e));
        return -1;
    }
    app->tun.fd = fd;
    (void)snprintf(app->tun.name, sizeof(app->tun.name), "%s", ifname);
    log_message(app, LOG_INFO, "macOS utun interface '%s' created (configure its address/routes separately)", app->tun.name);
    return 0;
#else
    (void)app;
    errno = ENOTSUP;
    return -1;
#endif
}

static void tun_close(App *app) {
    if (app->tun.fd >= 0) (void)close(app->tun.fd);
    app->tun.fd = -1;
}

static int tun_read_packet(App *app, uint8_t *buffer, size_t cap, int timeout_ms,
                           size_t *packet_len) {
    *packet_len = 0;
#if defined(__APPLE__)
    struct pollfd pfd = { app->tun.fd, POLLIN, 0 };
    int ready;
    do { ready = poll(&pfd, 1, timeout_ms); } while (ready < 0 && errno == EINTR);
    if (ready == 0) return 0;
    if (ready < 0) return -1;
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) { errno = EIO; return -1; }
    if (!(pfd.revents & POLLIN)) return 0;
    uint8_t raw[ZVPN_MAX_IP_PACKET + 4u];
    ssize_t n = read(app->tun.fd, raw, sizeof(raw));
    if (n < 0) return -1;
    if (n < 4) { errno = EPROTO; return -1; }
    uint32_t family_network;
    memcpy(&family_network, raw, 4);
    uint32_t family = ntohl(family_network);
    if (family != AF_INET && family != AF_INET6) {
        log_message(app, LOG_DEBUG, "Skipping utun non-IP address family %u", family);
        return 0;
    }
    size_t payload_len = (size_t)n - 4u;
    if (payload_len > cap) { errno = EMSGSIZE; return -1; }
    memcpy(buffer, raw + 4, payload_len);
    *packet_len = payload_len;
    return 1;
#else
    struct pollfd pfd = { app->tun.fd, POLLIN, 0 };
    int ready;
    do { ready = poll(&pfd, 1, timeout_ms); } while (ready < 0 && errno == EINTR);
    if (ready == 0) return 0;
    if (ready < 0) return -1;
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) { errno = EIO; return -1; }
    ssize_t n;
    do { n = read(app->tun.fd, buffer, cap); } while (n < 0 && errno == EINTR);
    if (n < 0) return -1;
    if (n == 0) return 0;
    *packet_len = (size_t)n;
    return 1;
#endif
}

static int tun_write_packet(App *app, const uint8_t *packet, size_t packet_len) {
#if defined(__APPLE__)
    int version = get_ip_version(packet, packet_len);
    uint32_t family;
    if (version == 4) family = htonl(AF_INET);
    else if (version == 6) family = htonl(AF_INET6);
    else { errno = EPROTO; return -1; }
    uint8_t *framed = (uint8_t *)malloc(packet_len + 4u);
    if (!framed) return -1;
    memcpy(framed, &family, 4);
    memcpy(framed + 4, packet, packet_len);
    ssize_t n;
    do { n = write(app->tun.fd, framed, packet_len + 4u); } while (n < 0 && errno == EINTR);
    free(framed);
    if (n != (ssize_t)(packet_len + 4u)) { if (n >= 0) errno = EIO; return -1; }
    return 0;
#else
    ssize_t n;
    do { n = write(app->tun.fd, packet, packet_len); } while (n < 0 && errno == EINTR);
    if (n != (ssize_t)packet_len) { if (n >= 0) errno = EIO; return -1; }
    return 0;
#endif
}
#endif

/* -------------------- Linux automatic IPv4 networking -------------------- */
#if defined(__linux__)
static int run_command(App *app, char *const argv[], char *out, size_t out_cap,
                       int log_failure) {
    int pipefd[2];
    if (out && out_cap) out[0] = '\0';
    if (pipe(pipefd) != 0) {
        if (log_failure) log_message(app, LOG_ERROR, "[SYS] pipe failed: %s", strerror(errno));
        return 127;
    }
    pid_t pid = fork();
    if (pid < 0) {
        int e = errno; close(pipefd[0]); close(pipefd[1]);
        if (log_failure) log_message(app, LOG_ERROR, "[SYS] fork failed: %s", strerror(e));
        return 127;
    }
    if (pid == 0) {
        (void)close(pipefd[0]);
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)dup2(pipefd[1], STDERR_FILENO);
        (void)close(pipefd[1]);
        execvp(argv[0], argv);
        (void)fprintf(stderr, "execvp %s failed: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    (void)close(pipefd[1]);
    size_t used = 0;
    char chunk[512];
    for (;;) {
        ssize_t n = read(pipefd[0], chunk, sizeof(chunk));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        if (out && out_cap && used < out_cap - 1) {
            size_t copy_n = (size_t)n;
            if (copy_n > out_cap - 1 - used) copy_n = out_cap - 1 - used;
            memcpy(out + used, chunk, copy_n);
            used += copy_n;
            out[used] = '\0';
        }
    }
    (void)close(pipefd[0]);
    int status = 127;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        status = 127;
        break;
    }
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    if (code == 0) {
        if (out && out_cap && out[0]) {
            size_t n = strlen(out);
            while (n && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = '\0';
            if (n) log_message(app, LOG_DEBUG, "[SYS][OK] %s: %s", argv[0], out);
        }
    } else if (log_failure) {
        if (out && out_cap && out[0]) {
            size_t n = strlen(out);
            while (n && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = '\0';
            log_message(app, LOG_ERROR, "[SYS][FAIL] %s exited %d: %s", argv[0], code, out);
        } else {
            log_message(app, LOG_ERROR, "[SYS][FAIL] %s exited with status %d", argv[0], code);
        }
    }
    return code;
}

static int safe_interface_name(const char *name) {
    size_t n = name ? strlen(name) : 0;
    if (n == 0 || n >= IFNAMSIZ) return 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':' || c == '@'))
            return 0;
    }
    return 1;
}

static int parse_ipv4_cidr(const char *text, struct in_addr *addr, int *prefix) {
    if (!text || !addr || !prefix) return -1;
    char tmp[64];
    size_t n = strlen(text);
    if (!n || n >= sizeof(tmp)) return -1;
    memcpy(tmp, text, n + 1);
    char *slash = strchr(tmp, '/');
    if (!slash || strchr(slash + 1, '/')) return -1;
    *slash++ = '\0';
    char *end = NULL;
    errno = 0;
    long pfx = strtol(slash, &end, 10);
    if (errno || !slash[0] || !end || *end || pfx < 1 || pfx > 32 ||
        inet_pton(AF_INET, tmp, addr) != 1)
        return -1;
    *prefix = (int)pfx;
    return 0;
}

static int read_ip_forward_value(int *value) {
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    if (!f) return -1;
    int rc = fscanf(f, "%d", value);
    int e = ferror(f) ? EIO : 0;
    (void)fclose(f);
    if (rc != 1) { errno = e ? e : EINVAL; return -1; }
    return 0;
}

static int write_ip_forward_value(int value) {
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (!f) return -1;
    int rc = fprintf(f, "%d\n", value);
    int saved = errno;
    if (fclose(f) != 0 && rc >= 0) { rc = -1; saved = errno; }
    if (rc < 0) { errno = saved ? saved : EIO; return -1; }
    return 0;
}

static int ensure_iptables_rule(App *app, const char *label,
                                char *const check_argv[], char *const add_argv[],
                                int *added_flag) {
    char output[1024];
    int check = run_command(app, check_argv, output, sizeof(output), 0);
    if (check == 0) {
        log_message(app, LOG_INFO, "[FIREWALL] Existing rule is present: %s", label);
        *added_flag = 0;
        return 0;
    }
    if (run_command(app, add_argv, output, sizeof(output), 1) != 0) {
        log_message(app, LOG_ERROR, "[FIREWALL] Could not install rule: %s", label);
        return -1;
    }
    *added_flag = 1;
    log_message(app, LOG_INFO, "[FIREWALL] Added rule: %s", label);
    return 0;
}

static void linux_network_cleanup(App *app) {
    LinuxNetworkState *ns = &app->linux_net;
    if (!ns->active && !ns->changed_ip_forward && !ns->added_nat_rule &&
        !ns->added_forward_rule && !ns->added_return_rule && !ns->added_input_rule)
        return;
    log_message(app, LOG_INFO, "[NETCFG] Removing only firewall rules added by this server");
    char *del_input[] = {"iptables", "-w", "-D", "INPUT", "-i", app->tun.name,
                         "-s", app->config.client_subnet_cidr, "-j", "ACCEPT", NULL};
    char *del_return[] = {"iptables", "-w", "-D", "FORWARD", "-i", ns->wan_interface,
                          "-o", app->tun.name, "-d", app->config.client_subnet_cidr,
                          "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT", NULL};
    char *del_forward[] = {"iptables", "-w", "-D", "FORWARD", "-i", app->tun.name,
                           "-o", ns->wan_interface, "-s", app->config.client_subnet_cidr,
                           "-j", "ACCEPT", NULL};
    char *del_nat[] = {"iptables", "-w", "-t", "nat", "-D", "POSTROUTING", "-s",
                       app->config.client_subnet_cidr, "-o", ns->wan_interface, "-j", "MASQUERADE", NULL};
    char *unused[1] = {NULL};
    char output[1024];
    (void)unused;
    if (ns->added_input_rule) (void)run_command(app, del_input, output, sizeof(output), 1);
    if (ns->added_return_rule) (void)run_command(app, del_return, output, sizeof(output), 1);
    if (ns->added_forward_rule) (void)run_command(app, del_forward, output, sizeof(output), 1);
    if (ns->added_nat_rule) (void)run_command(app, del_nat, output, sizeof(output), 1);
    ns->added_input_rule = ns->added_return_rule = ns->added_forward_rule = ns->added_nat_rule = 0;
    if (ns->changed_ip_forward) {
        if (write_ip_forward_value(ns->old_ip_forward) == 0)
            log_message(app, LOG_INFO, "[NETCFG] Restored net.ipv4.ip_forward=%d", ns->old_ip_forward);
        else
            log_message(app, LOG_WARN, "[NETCFG] Could not restore ip_forward: %s", strerror(errno));
        ns->changed_ip_forward = 0;
    }
    ns->active = 0;
}

static int linux_network_setup(App *app) {
    LinuxNetworkState *ns = &app->linux_net;
    if (!app->config.auto_network) {
        log_message(app, LOG_WARN, "[NETCFG] Automatic network setup is disabled; TUN IP/UP, forwarding, firewall and NAT must be configured manually");
        return 0;
    }
    if (geteuid() != 0) {
        log_message(app, LOG_ERROR, "[NETCFG] Automatic Linux networking needs root. Run: sudo ./zvpn-server ...");
        return -1;
    }
    if (!safe_interface_name(app->tun.name)) {
        log_message(app, LOG_ERROR, "[NETCFG] Unsafe/invalid TUN interface name '%s'", app->tun.name);
        return -1;
    }
    struct in_addr tun_addr, subnet_addr;
    int tun_prefix = 0, subnet_prefix = 0;
    if (parse_ipv4_cidr(app->config.tun_ipv4_cidr, &tun_addr, &tun_prefix) < 0 ||
        parse_ipv4_cidr(app->config.client_subnet_cidr, &subnet_addr, &subnet_prefix) < 0 ||
        tun_prefix != subnet_prefix) {
        log_message(app, LOG_ERROR, "[NETCFG] Invalid CIDR config; TUN IP and client subnet must use matching valid IPv4 prefixes");
        return -1;
    }
    uint32_t mask = subnet_prefix == 32 ? 0xffffffffu : (0xffffffffu << (32 - subnet_prefix));
    uint32_t tun_host = ntohl(tun_addr.s_addr), subnet_host = ntohl(subnet_addr.s_addr);
    if ((subnet_host & mask) != subnet_host || (tun_host & mask) != subnet_host ||
        tun_host == subnet_host || (subnet_prefix < 31 && tun_host == (subnet_host | ~mask))) {
        log_message(app, LOG_ERROR, "[NETCFG] TUN IP %s must be a usable host inside client subnet %s",
                    app->config.tun_ipv4_cidr, app->config.client_subnet_cidr);
        return -1;
    }
    if (app->config.mtu < 576 || app->config.mtu > 9000) {
        log_message(app, LOG_ERROR, "[NETCFG] Invalid MTU %d", app->config.mtu);
        return -1;
    }
    char route_out[2048];
    if (app->config.wan_interface[0]) {
        (void)snprintf(ns->wan_interface, sizeof(ns->wan_interface), "%s", app->config.wan_interface);
    } else {
        char *route_argv[] = {"ip", "-4", "route", "get", "1.1.1.1", NULL};
        if (run_command(app, route_argv, route_out, sizeof(route_out), 1) != 0) return -1;
        char *dev = strstr(route_out, " dev ");
        if (!dev || sscanf(dev + 5, "%127s", ns->wan_interface) != 1) {
            log_message(app, LOG_ERROR, "[NETCFG] Could not determine outbound interface from 'ip -4 route get 1.1.1.1'; specify --wan-interface IFACE");
            return -1;
        }
    }
    if (!safe_interface_name(ns->wan_interface) || strcmp(ns->wan_interface, app->tun.name) == 0) {
        log_message(app, LOG_ERROR, "[NETCFG] Invalid outbound interface '%s' (must differ from TUN '%s')",
                    ns->wan_interface, app->tun.name);
        return -1;
    }
    log_message(app, LOG_INFO, "[NETCFG] Configuring Linux IPv4: tun=%s addr=%s clients=%s wan=%s mtu=%d",
                app->tun.name, app->config.tun_ipv4_cidr, app->config.client_subnet_cidr,
                ns->wan_interface, app->config.mtu);

    char mtu_text[16];
    (void)snprintf(mtu_text, sizeof(mtu_text), "%d", app->config.mtu);
    char *addr_argv[] = {"ip", "addr", "replace", app->config.tun_ipv4_cidr, "dev", app->tun.name, NULL};
    char *link_argv[] = {"ip", "link", "set", "dev", app->tun.name, "mtu", mtu_text, "up", NULL};
    if (run_command(app, addr_argv, route_out, sizeof(route_out), 1) != 0 ||
        run_command(app, link_argv, route_out, sizeof(route_out), 1) != 0) {
        log_message(app, LOG_ERROR, "[NETCFG] Failed to address/bring UP TUN; refusing client connections");
        return -1;
    }
    log_message(app, LOG_INFO, "[NETCFG] TUN '%s' is UP with %s; this fixes the common TUN write EIO caused by a DOWN interface",
                app->tun.name, app->config.tun_ipv4_cidr);
    char *route_dev_argv[] = {"ip", "-4", "route", "show", "dev", app->tun.name, NULL};
    if (run_command(app, route_dev_argv, route_out, sizeof(route_out), 1) != 0 || !route_out[0]) {
        log_message(app, LOG_ERROR, "[NETCFG] Expected connected route via TUN '%s' is missing", app->tun.name);
        return -1;
    }

    if (read_ip_forward_value(&ns->old_ip_forward) < 0) {
        log_message(app, LOG_ERROR, "[NETCFG] Cannot read /proc/sys/net/ipv4/ip_forward: %s", strerror(errno));
        return -1;
    }
    if (ns->old_ip_forward != 1) {
        if (write_ip_forward_value(1) < 0) {
            log_message(app, LOG_ERROR, "[NETCFG] Cannot enable IPv4 forwarding: %s", strerror(errno));
            return -1;
        }
        ns->changed_ip_forward = 1;
        log_message(app, LOG_INFO, "[NETCFG] Enabled net.ipv4.ip_forward (previous value=%d)", ns->old_ip_forward);
    } else {
        log_message(app, LOG_INFO, "[NETCFG] net.ipv4.ip_forward was already enabled");
    }

    char *iptables_ver[] = {"iptables", "--version", NULL};
    if (run_command(app, iptables_ver, route_out, sizeof(route_out), 1) != 0) {
        log_message(app, LOG_ERROR, "[NETCFG] iptables is required for automatic NAT/firewall setup. Install the Debian package 'iptables' and restart; no client will be accepted until setup succeeds.");
        return -1;
    }

    char *check_nat[] = {"iptables", "-w", "-t", "nat", "-C", "POSTROUTING", "-s", app->config.client_subnet_cidr,
                         "-o", ns->wan_interface, "-j", "MASQUERADE", NULL};
    char *add_nat[] = {"iptables", "-w", "-t", "nat", "-I", "POSTROUTING", "1", "-s", app->config.client_subnet_cidr,
                       "-o", ns->wan_interface, "-j", "MASQUERADE", NULL};
    char *check_forward[] = {"iptables", "-w", "-C", "FORWARD", "-i", app->tun.name, "-o", ns->wan_interface,
                             "-s", app->config.client_subnet_cidr, "-j", "ACCEPT", NULL};
    char *add_forward[] = {"iptables", "-w", "-I", "FORWARD", "1", "-i", app->tun.name, "-o", ns->wan_interface,
                           "-s", app->config.client_subnet_cidr, "-j", "ACCEPT", NULL};
    char *check_return[] = {"iptables", "-w", "-C", "FORWARD", "-i", ns->wan_interface, "-o", app->tun.name,
                            "-d", app->config.client_subnet_cidr, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
                            "-j", "ACCEPT", NULL};
    char *add_return[] = {"iptables", "-w", "-I", "FORWARD", "1", "-i", ns->wan_interface, "-o", app->tun.name,
                          "-d", app->config.client_subnet_cidr, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
                          "-j", "ACCEPT", NULL};
    char *check_input[] = {"iptables", "-w", "-C", "INPUT", "-i", app->tun.name, "-s", app->config.client_subnet_cidr,
                          "-j", "ACCEPT", NULL};
    char *add_input[] = {"iptables", "-w", "-I", "INPUT", "1", "-i", app->tun.name, "-s", app->config.client_subnet_cidr,
                         "-j", "ACCEPT", NULL};
    ns->active = 1;
    if (ensure_iptables_rule(app, "source NAT for VPN clients", check_nat, add_nat, &ns->added_nat_rule) < 0 ||
        ensure_iptables_rule(app, "client-to-WAN forwarding", check_forward, add_forward, &ns->added_forward_rule) < 0 ||
        ensure_iptables_rule(app, "established WAN-to-client return traffic", check_return, add_return, &ns->added_return_rule) < 0 ||
        ensure_iptables_rule(app, "traffic from VPN clients to services hosted on this Linux server", check_input, add_input, &ns->added_input_rule) < 0) {
        log_message(app, LOG_ERROR, "[NETCFG] Automatic firewall/NAT setup failed; cleaning up rules added by this run");
        linux_network_cleanup(app);
        return -1;
    }
    log_message(app, LOG_INFO, "[NETCFG] IPv4 forwarding, source NAT, FORWARD rules, and local-service INPUT access are ready");
    log_message(app, LOG_INFO, "[NETCFG] Route to %s is via %s; no manual default route was changed", app->config.client_subnet_cidr, app->tun.name);
    return 0;
}
#endif /* __linux__ automatic networking */

/* -------------------- Windows automatic IPv4 networking -------------------- */
#ifdef _WIN32
static int powershell_quote(const char *src, char *dst, size_t cap) {
    size_t used = 0;
    if (!cap) return -1;
    dst[used++] = '\'';
    for (const char *p = src; *p; ++p) {
        if (*p == '\'') {
            if (used + 2 >= cap) return -1;
            dst[used++] = '\'';
            dst[used++] = '\'';
        } else {
            if (used + 1 >= cap) return -1;
            dst[used++] = *p;
        }
    }
    if (used + 2 > cap) return -1;
    dst[used++] = '\'';
    dst[used] = '\0';
    return 0;
}

static char *base64_encode_bytes(const uint8_t *src, size_t len) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (len > (SIZE_MAX - 4u) / 4u * 3u) return NULL;
    size_t cap = ((len + 2u) / 3u) * 4u + 1u;
    char *out = (char *)malloc(cap);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (len - i >= 3u) {
        uint32_t v = ((uint32_t)src[i] << 16) | ((uint32_t)src[i + 1u] << 8) | src[i + 2u];
        out[j++] = alphabet[(v >> 18) & 63u];
        out[j++] = alphabet[(v >> 12) & 63u];
        out[j++] = alphabet[(v >> 6) & 63u];
        out[j++] = alphabet[v & 63u];
        i += 3u;
    }
    if (len - i == 1u) {
        uint32_t v = (uint32_t)src[i] << 16;
        out[j++] = alphabet[(v >> 18) & 63u];
        out[j++] = alphabet[(v >> 12) & 63u];
        out[j++] = '=';
        out[j++] = '=';
    } else if (len - i == 2u) {
        uint32_t v = ((uint32_t)src[i] << 16) | ((uint32_t)src[i + 1u] << 8);
        out[j++] = alphabet[(v >> 18) & 63u];
        out[j++] = alphabet[(v >> 12) & 63u];
        out[j++] = alphabet[(v >> 6) & 63u];
        out[j++] = '=';
    }
    out[j] = '\0';
    return out;
}

/* Run a UTF-8 PowerShell script using -EncodedCommand, avoiding command-line
 * quoting/injection issues for adapter aliases and paths with spaces. */
static int run_powershell(App *app, const char *script, char *out, size_t out_cap,
                          int log_failure) {
    if (out && out_cap) out[0] = '\0';
    int wide_count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, script, -1, NULL, 0);
    if (wide_count <= 0) {
        if (log_failure) log_message(app, LOG_ERROR, "[SYS] Cannot convert PowerShell script to UTF-16 (Win32 error=%lu)", GetLastError());
        return 127;
    }
    wchar_t *wide = (wchar_t *)calloc((size_t)wide_count, sizeof(wchar_t));
    if (!wide) return 127;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, script, -1, wide, wide_count) <= 0) {
        free(wide);
        return 127;
    }
    /* Windows wchar_t is 16-bit; PowerShell expects UTF-16LE bytes without NUL. */
    size_t raw_len = (size_t)(wide_count - 1) * sizeof(wchar_t);
    char *encoded = base64_encode_bytes((const uint8_t *)wide, raw_len);
    free(wide);
    if (!encoded) return 127;

    size_t command_cap = strlen(encoded) + 160u;
    char *command_line = (char *)malloc(command_cap);
    if (!command_line) { free(encoded); return 127; }
    (void)snprintf(command_line, command_cap,
        "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand %s", encoded);
    free(encoded);

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE read_pipe = NULL, write_pipe = NULL;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
        DWORD e = GetLastError(); free(command_line);
        if (log_failure) log_message(app, LOG_ERROR, "[SYS] CreatePipe failed (Win32 error=%lu)", e);
        return 127;
    }
    (void)SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    HANDLE null_input = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    si.hStdInput = (null_input != INVALID_HANDLE_VALUE) ? null_input : GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = write_pipe;
    si.hStdError = write_pipe;
    BOOL created = CreateProcessA(NULL, command_line, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    DWORD create_error = created ? ERROR_SUCCESS : GetLastError();
    free(command_line);
    if (null_input != INVALID_HANDLE_VALUE) CloseHandle(null_input);
    CloseHandle(write_pipe);
    if (!created) {
        CloseHandle(read_pipe);
        if (log_failure) log_message(app, LOG_ERROR, "[SYS] Could not start powershell.exe (Win32 error=%lu)", create_error);
        return 127;
    }

    size_t used = 0;
    char chunk[512];
    for (;;) {
        DWORD got = 0;
        BOOL ok = ReadFile(read_pipe, chunk, sizeof(chunk), &got, NULL);
        if (!ok || got == 0) break;
        if (out && out_cap && used < out_cap - 1u) {
            size_t copy_n = (size_t)got;
            if (copy_n > out_cap - 1u - used) copy_n = out_cap - 1u - used;
            memcpy(out + used, chunk, copy_n);
            used += copy_n;
            out[used] = '\0';
        }
    }
    CloseHandle(read_pipe);
    (void)WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 127;
    (void)GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (out && out_cap && out[0]) {
        size_t n = strlen(out);
        while (n && (out[n - 1u] == '\n' || out[n - 1u] == '\r')) out[--n] = '\0';
    }
    if (exit_code == 0) {
        if (out && out_cap && out[0]) log_message(app, LOG_DEBUG, "[SYS][OK] PowerShell: %.400s", out);
    } else if (log_failure) {
        log_message(app, LOG_ERROR, "[SYS][FAIL] PowerShell exit=%lu: %.700s", exit_code,
                    (out && out_cap && out[0]) ? out : "no output");
    }
    return exit_code == 0 ? 0 : (exit_code > 255u ? 1 : (int)exit_code);
}

static int parse_ipv4_cidr_windows(const char *text, struct in_addr *addr, int *prefix) {
    char tmp[64];
    if (!text || !addr || !prefix) return -1;
    size_t n = strlen(text);
    if (!n || n >= sizeof(tmp)) return -1;
    memcpy(tmp, text, n + 1u);
    char *slash = strchr(tmp, '/');
    if (!slash || strchr(slash + 1, '/')) return -1;
    *slash++ = '\0';
    char *end = NULL;
    errno = 0;
    long pfx = strtol(slash, &end, 10);
    if (errno || !slash[0] || !end || *end || pfx < 1 || pfx > 32 || inet_pton(AF_INET, tmp, addr) != 1)
        return -1;
    *prefix = (int)pfx;
    return 0;
}

static int windows_network_setup(App *app) {
    WindowsNetworkState *ns = &app->windows_net;
    if (!app->config.auto_network) {
        log_message(app, LOG_WARN, "[NETCFG] Windows auto-network disabled; Wintun IP, MTU, forwarding, NAT and firewall must be configured manually");
        return 0;
    }

    struct in_addr tun_addr, subnet_addr;
    int tun_prefix = 0, subnet_prefix = 0;
    if (parse_ipv4_cidr_windows(app->config.tun_ipv4_cidr, &tun_addr, &tun_prefix) < 0 ||
        parse_ipv4_cidr_windows(app->config.client_subnet_cidr, &subnet_addr, &subnet_prefix) < 0 ||
        tun_prefix != subnet_prefix || app->config.mtu < 576 || app->config.mtu > 9000) {
        log_message(app, LOG_ERROR, "[NETCFG] Invalid Windows IPv4 CIDR/MTU configuration");
        return -1;
    }
    uint32_t mask = subnet_prefix == 32 ? 0xffffffffu : (0xffffffffu << (32 - subnet_prefix));
    uint32_t tun_host = ntohl(tun_addr.s_addr), subnet_host = ntohl(subnet_addr.s_addr);
    if ((subnet_host & mask) != subnet_host || (tun_host & mask) != subnet_host ||
        tun_host == subnet_host || (subnet_prefix < 31 && tun_host == (subnet_host | ~mask))) {
        log_message(app, LOG_ERROR, "[NETCFG] TUN IP %s must be a usable host inside client subnet %s",
                    app->config.tun_ipv4_cidr, app->config.client_subnet_cidr);
        return -1;
    }

    char tun_quoted[320], tun_ip_quoted[96], subnet_quoted[96], wan_quoted[320];
    char wan_option_quoted[320];
    char tun_ip[64];
    (void)snprintf(tun_ip, sizeof(tun_ip), "%s", app->config.tun_ipv4_cidr);
    char *slash = strchr(tun_ip, '/');
    if (!slash) return -1;
    *slash = '\0';
    if (powershell_quote(app->tun.name, tun_quoted, sizeof(tun_quoted)) < 0 ||
        powershell_quote(tun_ip, tun_ip_quoted, sizeof(tun_ip_quoted)) < 0 ||
        powershell_quote(app->config.client_subnet_cidr, subnet_quoted, sizeof(subnet_quoted)) < 0 ||
        powershell_quote(app->config.wan_interface, wan_option_quoted, sizeof(wan_option_quoted)) < 0) {
        log_message(app, LOG_ERROR, "[NETCFG] Cannot quote Windows interface configuration");
        return -1;
    }
    char prefix_text[16], mtu_text[16], port_text[16];
    (void)snprintf(prefix_text, sizeof(prefix_text), "%d", tun_prefix);
    (void)snprintf(mtu_text, sizeof(mtu_text), "%d", app->config.mtu);
    (void)snprintf(port_text, sizeof(port_text), "%d", app->config.port);
    (void)wan_quoted;

    char script[16000];
    int n = snprintf(script, sizeof(script),
        "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
        "$tunName=%s; $tunIp=%s; $prefix=%s; $subnet=%s; $mtu=%s; $port=%s; $wanOption=%s; "
        "$ipAdded=$false; $natAdded=$false; $clientFwAdded=$false; $listenerFwAdded=$false; "
        "$tunForwardChanged=$false; $wanForwardChanged=$false; $mtuChanged=$false; "
        "$oldTunForward='Disabled'; $oldWanForward='Disabled'; $oldMtu=1500; $wanName=''; "
        "try { "
        "$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); "
        "if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run this server from an Administrator console.'}; "
        "$null=Get-NetAdapter -Name $tunName -ErrorAction Stop; "
        "Enable-NetAdapter -Name $tunName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; "
        "$tunIf=Get-NetIPInterface -InterfaceAlias $tunName -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1; "
        "$oldTunForward=$tunIf.Forwarding.ToString(); $oldMtu=[int]$tunIf.NlMtuBytes; "
        "$existing=Get-NetIPAddress -IPAddress $tunIp -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
        "if($existing){$match=$existing | Where-Object { $_.InterfaceAlias -eq $tunName -and $_.PrefixLength -eq $prefix }; "
        "if(-not $match){throw ('IP '+$tunIp+' already exists on a different interface or with a different prefix.')}} "
        "else {New-NetIPAddress -InterfaceAlias $tunName -IPAddress $tunIp -PrefixLength $prefix -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; $ipAdded=$true}; "
        "if($oldMtu -ne $mtu){$mtuChanged=$true; Set-NetIPInterface -InterfaceAlias $tunName -AddressFamily IPv4 -NlMtuBytes $mtu -PolicyStore ActiveStore -ErrorAction Stop}; "
        "if($oldTunForward -ne 'Enabled'){$tunForwardChanged=$true; Set-NetIPInterface -InterfaceAlias $tunName -AddressFamily IPv4 -Forwarding Enabled -PolicyStore ActiveStore -ErrorAction Stop}; "
        "if($wanOption){$wanName=$wanOption; $wanIf=Get-NetIPInterface -InterfaceAlias $wanName -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1} "
        "else {$route=Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction Stop | "
        "Where-Object { $_.InterfaceAlias -ne $tunName } | Sort-Object RouteMetric | Select-Object -First 1; "
        "if(-not $route){throw 'Could not find an IPv4 default route; specify --wan-interface.'}; "
        "$wanIf=Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1; $wanName=$wanIf.InterfaceAlias}; "
        "if(-not $wanName -or $wanName -eq $tunName){throw 'Invalid WAN interface; it must exist and differ from the Wintun adapter.'}; "
        "$oldWanForward=$wanIf.Forwarding.ToString(); if($oldWanForward -ne 'Enabled'){$wanForwardChanged=$true; "
        "Set-NetIPInterface -InterfaceAlias $wanName -AddressFamily IPv4 -Forwarding Enabled -PolicyStore ActiveStore -ErrorAction Stop}; "
        "$nats=@(Get-NetNat -ErrorAction SilentlyContinue); $sameNat=$nats | Where-Object { $_.InternalIPInterfaceAddressPrefix -eq $subnet } | Select-Object -First 1; "
        "if($sameNat){Write-Output ('Using existing WinNAT '+$sameNat.Name+' for '+$subnet)} "
        "elseif($nats.Count -gt 0){$prefixes=($nats | ForEach-Object { $_.InternalIPInterfaceAddressPrefix }) -join ', '; "
        "throw ('Windows already has WinNAT prefix(es): '+$prefixes+'. Windows WinNAT generally supports only one internal NAT subnet; no existing NAT was changed. Disable/reconfigure the conflicting NAT or choose the same subnet.') } "
        "else {New-NetNat -Name 'ZVPN-Auto-IPv4' -InternalIPInterfaceAddressPrefix $subnet -ErrorAction Stop | Out-Null; $natAdded=$true}; "
        "$clientRule=Get-NetFirewallRule -Name 'ZVPN-Auto-ClientSubnet' -ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if(-not $clientRule){New-NetFirewallRule -Name 'ZVPN-Auto-ClientSubnet' -DisplayName 'ZVPN VPN client subnet to host services' "
        "-Direction Inbound -Action Allow -InterfaceAlias $tunName -RemoteAddress $subnet -Profile Any -Enabled True -ErrorAction Stop | Out-Null; $clientFwAdded=$true}; "
        "$listenRule=Get-NetFirewallRule -Name 'ZVPN-Auto-ListenerTCP' -ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if(-not $listenRule){New-NetFirewallRule -Name 'ZVPN-Auto-ListenerTCP' -DisplayName ('ZVPN server TCP '+$port) "
        "-Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -Profile Any -Enabled True -ErrorAction Stop | Out-Null; $listenerFwAdded=$true}; "
        "Write-Output ('__ZVPN_STATE__|'+[int]$ipAdded+'|'+[int]$natAdded+'|'+[int]$clientFwAdded+'|'+[int]$listenerFwAdded+'|'+[int]$tunForwardChanged+'|'+[int]$wanForwardChanged+'|'+[int]$mtuChanged+'|'+$oldMtu+'|'+$oldTunForward+'|'+$oldWanForward+'|'+$wanName); "
        "Write-Output ('Windows IPv4 auto-network ready: Wintun='+$tunName+' '+$tunIp+'/'+$prefix+' subnet='+$subnet+' WAN='+$wanName+' MTU='+$mtu) "
        "} catch { $failure=$_.Exception.Message; "
        "if($listenerFwAdded){Remove-NetFirewallRule -Name 'ZVPN-Auto-ListenerTCP' -ErrorAction SilentlyContinue}; "
        "if($clientFwAdded){Remove-NetFirewallRule -Name 'ZVPN-Auto-ClientSubnet' -ErrorAction SilentlyContinue}; "
        "if($natAdded){Remove-NetNat -Name 'ZVPN-Auto-IPv4' -Confirm:$false -ErrorAction SilentlyContinue}; "
        "if($wanForwardChanged -and $wanName){Set-NetIPInterface -InterfaceAlias $wanName -AddressFamily IPv4 -Forwarding $oldWanForward -PolicyStore ActiveStore -ErrorAction SilentlyContinue}; "
        "if($tunForwardChanged){Set-NetIPInterface -InterfaceAlias $tunName -AddressFamily IPv4 -Forwarding $oldTunForward -PolicyStore ActiveStore -ErrorAction SilentlyContinue}; "
        "if($mtuChanged){Set-NetIPInterface -InterfaceAlias $tunName -AddressFamily IPv4 -NlMtuBytes $oldMtu -PolicyStore ActiveStore -ErrorAction SilentlyContinue}; "
        "if($ipAdded){Get-NetIPAddress -InterfaceAlias $tunName -IPAddress $tunIp -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue}; "
        "Write-Output ('Windows auto-network setup failed: '+$failure); exit 1 }",
        tun_quoted, tun_ip_quoted, prefix_text, subnet_quoted, mtu_text, port_text, wan_option_quoted);
    if (n < 0 || (size_t)n >= sizeof(script)) {
        log_message(app, LOG_ERROR, "[NETCFG] Windows setup script exceeded internal buffer");
        return -1;
    }

    char output[8192];
    int rc = run_powershell(app, script, output, sizeof(output), 1);
    if (rc != 0) {
        log_message(app, LOG_ERROR, "[NETCFG] Windows automatic network setup failed. Start elevated; check PowerShell NetNat and Defender Firewall availability.");
        return -1;
    }
    char *marker = strstr(output, "__ZVPN_STATE__|");
    if (!marker) {
        log_message(app, LOG_ERROR, "[NETCFG] Windows setup succeeded but did not return cleanup state; refusing to continue");
        return -1;
    }
    marker += strlen("__ZVPN_STATE__|");
    char *marker_end = strpbrk(marker, "\r\n");
    if (marker_end) *marker_end = '\0';
    char *fields[11];
    size_t field_count = 0;
    char *cursor = marker;
    while (field_count < 11) {
        fields[field_count++] = cursor;
        char *bar = strchr(cursor, '|');
        if (!bar) break;
        *bar = '\0';
        cursor = bar + 1;
    }
    if (field_count != 11) {
        log_message(app, LOG_ERROR, "[NETCFG] Malformed Windows network cleanup state");
        return -1;
    }
    ns->added_ip_address = atoi(fields[0]);
    ns->added_nat = atoi(fields[1]);
    ns->added_client_firewall_rule = atoi(fields[2]);
    ns->added_listener_firewall_rule = atoi(fields[3]);
    ns->changed_tun_forwarding = atoi(fields[4]);
    ns->changed_wan_forwarding = atoi(fields[5]);
    ns->changed_mtu = atoi(fields[6]);
    ns->old_mtu = strtoul(fields[7], NULL, 10);
    (void)snprintf(ns->old_tun_forwarding, sizeof(ns->old_tun_forwarding), "%s", fields[8]);
    (void)snprintf(ns->old_wan_forwarding, sizeof(ns->old_wan_forwarding), "%s", fields[9]);
    (void)snprintf(ns->wan_interface, sizeof(ns->wan_interface), "%s", fields[10]);
    ns->active = 1;
    log_message(app, LOG_INFO, "[NETCFG] Windows IPv4 interface, forwarding, NAT and firewall setup completed");
    return 0;
}

static void windows_network_cleanup(App *app) {
    WindowsNetworkState *ns = &app->windows_net;
    if (!ns->active) return;
    char tun_quoted[320], tun_ip_quoted[96], subnet_quoted[96], wan_quoted[320];
    if (powershell_quote(app->tun.name, tun_quoted, sizeof(tun_quoted)) < 0 ||
        powershell_quote(app->config.tun_ipv4_cidr, tun_ip_quoted, sizeof(tun_ip_quoted)) < 0 ||
        powershell_quote(app->config.client_subnet_cidr, subnet_quoted, sizeof(subnet_quoted)) < 0 ||
        powershell_quote(ns->wan_interface, wan_quoted, sizeof(wan_quoted)) < 0) {
        log_message(app, LOG_WARN, "[NETCFG] Could not quote cleanup parameters; Windows settings may remain in place");
        return;
    }
    char tun_ip[64];
    (void)snprintf(tun_ip, sizeof(tun_ip), "%s", app->config.tun_ipv4_cidr);
    char *slash = strchr(tun_ip, '/');
    if (slash) *slash = '\0';
    char tun_ip_plain[96];
    if (powershell_quote(tun_ip, tun_ip_plain, sizeof(tun_ip_plain)) < 0) return;
    char old_mtu[24];
    (void)snprintf(old_mtu, sizeof(old_mtu), "%lu", ns->old_mtu);

    char script[10000];
    int n = snprintf(script, sizeof(script),
        "$ErrorActionPreference='Continue'; $tunName=%s; $tunIp=%s; $subnet=%s; $wanName=%s; $oldMtu=%s; "
        "if(%d){Remove-NetFirewallRule -Name 'ZVPN-Auto-ListenerTCP' -ErrorAction SilentlyContinue}; "
        "if(%d){Remove-NetFirewallRule -Name 'ZVPN-Auto-ClientSubnet' -ErrorAction SilentlyContinue}; "
        "if(%d){Remove-NetNat -Name 'ZVPN-Auto-IPv4' -Confirm:$false -ErrorAction SilentlyContinue}; "
        "if(%d -and $wanName){Set-NetIPInterface -InterfaceAlias $wanName -AddressFamily IPv4 -Forwarding %s -PolicyStore ActiveStore -ErrorAction SilentlyContinue}; "
        "if(%d){Set-NetIPInterface -InterfaceAlias $tunName -AddressFamily IPv4 -Forwarding %s -PolicyStore ActiveStore -ErrorAction SilentlyContinue}; "
        "if(%d){Set-NetIPInterface -InterfaceAlias $tunName -AddressFamily IPv4 -NlMtuBytes $oldMtu -PolicyStore ActiveStore -ErrorAction SilentlyContinue}; "
        "if(%d){Get-NetIPAddress -InterfaceAlias $tunName -IPAddress $tunIp -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue}; "
        "Write-Output 'Windows auto-network cleanup finished.'",
        tun_quoted, tun_ip_plain, subnet_quoted, wan_quoted, old_mtu,
        ns->added_listener_firewall_rule, ns->added_client_firewall_rule, ns->added_nat,
        ns->changed_wan_forwarding, ns->old_wan_forwarding[0] ? ns->old_wan_forwarding : "Disabled",
        ns->changed_tun_forwarding, ns->old_tun_forwarding[0] ? ns->old_tun_forwarding : "Disabled",
        ns->changed_mtu, ns->added_ip_address);
    if (n < 0 || (size_t)n >= sizeof(script)) {
        log_message(app, LOG_WARN, "[NETCFG] Windows cleanup script exceeded buffer");
        return;
    }
    char output[4096];
    if (run_powershell(app, script, output, sizeof(output), 0) != 0)
        log_message(app, LOG_WARN, "[NETCFG] Windows cleanup reported an issue: %.400s", output);
    else
        log_message(app, LOG_INFO, "[NETCFG] Removed only Windows rules/address/NAT created by this run and restored prior interface settings");
    ns->active = 0;
}
#endif /* _WIN32 */

static int platform_network_setup(App *app) {
#ifdef __linux__
    return linux_network_setup(app);
#elif defined(_WIN32)
    return windows_network_setup(app);
#else
    if (app->config.auto_network) {
        log_message(app, LOG_ERROR, "Automatic network setup is supported on Linux and Windows only");
        return -1;
    }
    log_message(app, LOG_WARN, "[NETCFG] Configure macOS utun routing/NAT/firewall manually");
    return 0;
#endif
}

static void platform_network_cleanup(App *app) {
#ifdef __linux__
    linux_network_cleanup(app);
#elif defined(_WIN32)
    windows_network_cleanup(app);
#else
    (void)app;
#endif
}

/* -------------------- Socket/protocol helpers -------------------- */
static int client_stopping(Client *c);
static void client_request_stop(Client *c);

static int send_all(App *app, socket_t sock, const uint8_t *buf, size_t len) {
    size_t offset = 0;
    while (offset < len) {
#ifdef _WIN32
        int chunk = (len - offset > INT_MAX) ? INT_MAX : (int)(len - offset);
        int n = send(sock, (const char *)buf + offset, chunk, 0);
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (socket_interrupted(e)) continue;
            log_message(app, LOG_WARN, "send failed: WSA error %d", e);
            return -1;
        }
#else
        size_t chunk = len - offset;
#ifdef MSG_NOSIGNAL
        ssize_t n = send(sock, buf + offset, chunk, MSG_NOSIGNAL);
#else
        ssize_t n = send(sock, buf + offset, chunk, 0);
#endif
        if (n < 0) {
            if (errno == EINTR) continue;
            log_message(app, LOG_WARN, "send failed: %s", strerror(errno));
            return -1;
        }
#endif
        if (n <= 0) return -1;
        offset += (size_t)n;
        STAT_ADD(app, transport_bytes_sent, n);
    }
    return 0;
}

static int wait_socket_readable(socket_t sock, int timeout_ms) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
#ifdef _WIN32
    return select(0, &readfds, NULL, NULL, &tv);
#else
    return select(sock + 1, &readfds, NULL, NULL, &tv);
#endif
}

static int recv_all(App *app, Client *client, uint8_t *buf, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        if (!app_running() || client_stopping(client)) { errno = ECANCELED; return -1; }
        int ready = wait_socket_readable(client->socket, ZVPN_READ_TIMEOUT_MS);
        if (ready == 0) continue;
        if (ready < 0) {
#ifdef _WIN32
            int e = WSAGetLastError();
            if (socket_interrupted(e)) continue;
            log_message(app, LOG_WARN, "select on client socket failed: WSA error %d", e);
#else
            if (errno == EINTR) continue;
            log_message(app, LOG_WARN, "select on client socket failed: %s", strerror(errno));
#endif
            return -1;
        }
#ifdef _WIN32
        int chunk = (len - offset > INT_MAX) ? INT_MAX : (int)(len - offset);
        int n = recv(client->socket, (char *)buf + offset, chunk, 0);
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (socket_interrupted(e)) continue;
            log_message(app, LOG_WARN, "[NET][RX] recv failed: WSA error=%d", e);
            errno = EIO; /* Caller must not report a stale WSAGetLastError(). */
            return -1;
        }
#else
        ssize_t n = recv(client->socket, buf + offset, len - offset, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            log_message(app, LOG_WARN, "[NET][RX] recv failed: %s", strerror(errno));
            return -1;
        }
#endif
        if (n == 0) { errno = ECONNRESET; return -1; }
        offset += (size_t)n;
        STAT_ADD(app, transport_bytes_received, n);
    }
    return 0;
}

static int encode_send_batch(App *app, Client *client,
                             const uint8_t *batch, size_t batch_len,
                             uint64_t packet_count, uint64_t ip_bytes) {
    if (batch_len == 0 || batch_len > app->config.max_batch_bytes || batch_len > UINT32_MAX) {
        errno = EMSGSIZE;
        return -1;
    }

    const uint8_t *payload = batch;
    size_t payload_len = batch_len;
    uint8_t flags = 0;
    uint8_t *compressed = NULL;
    uint64_t compression_ms = 0;
    int compression_enabled_now;
    int compression_level_now;
    size_t min_compress_batch_now;
    mutex_lock(&app->log_lock);
    compression_enabled_now = app->config.compression_enabled;
    compression_level_now = app->config.compression_level;
    min_compress_batch_now = app->config.min_compress_batch_bytes;
    mutex_unlock(&app->log_lock);

    if (compression_enabled_now && batch_len >= min_compress_batch_now) {
        size_t bound = ZSTD_compressBound(batch_len);
        compressed = (uint8_t *)malloc(bound);
        if (!compressed) {
            log_message(app, LOG_WARN,
                        "[ZSTD] allocation failed for %zu-byte batch; falling back to raw",
                        batch_len);
        } else {
            uint64_t compression_started_us = monotonic_us();
            STAT_ADD(app, compression_attempts_sent, 1);
            size_t result = ZSTD_compress(compressed, bound, batch, batch_len,
                                          compression_level_now);
            uint64_t compression_elapsed_us = monotonic_us() - compression_started_us;
            compression_ms = compression_elapsed_us / 1000u;
            STAT_ADD(app, compression_time_us_sent, compression_elapsed_us);
            if (ZSTD_isError(result)) {
                log_message(app, LOG_WARN, "[ZSTD] compression failed: %s; sending raw batch",
                            ZSTD_getErrorName(result));
            } else if (result < batch_len) {
                payload = compressed;
                payload_len = result;
                flags = ZVPN_FLAG_ZSTD;
            } else {
                log_message(app, LOG_DEBUG,
                            "[ZSTD] compressed payload was not smaller (%zu >= %zu); sending raw",
                            result, batch_len);
            }
        }
    } else if (compression_enabled_now && batch_len < min_compress_batch_now) {
        STAT_ADD(app, small_batches_skipped_compression, 1);
        log_message(app, LOG_DEBUG,
                    "[ZSTD][SKIP] batch=%zu below minimum compression threshold=%zu; sending raw",
                    batch_len, min_compress_batch_now);
    }

    uint8_t header[ZVPN_HEADER_SIZE] = {0};
    memcpy(header, "ZVPN", 4);
    header[4] = ZVPN_VERSION;
    header[5] = flags;
    put_u32(header + 8, (uint32_t)batch_len);
    put_u32(header + 12, (uint32_t)payload_len);

    uint64_t send_started = monotonic_ms();
    int rc = send_all(app, client->socket, header, sizeof(header));
    if (rc == 0) rc = send_all(app, client->socket, payload, payload_len);
    uint64_t send_ms = monotonic_ms() - send_started;
    if (rc == 0) {
        STAT_ADD(app, batches_sent, 1);
        STAT_ADD(app, packets_sent_to_client, packet_count);
        STAT_ADD(app, client_ip_bytes_out, ip_bytes);
        STAT_ADD(app, payload_original_bytes_sent, batch_len);
        STAT_ADD(app, payload_encoded_bytes_sent, payload_len);
        if (batch_len > payload_len)
            STAT_ADD(app, payload_saved_bytes_sent, batch_len - payload_len);
        if (flags & ZVPN_FLAG_ZSTD) STAT_ADD(app, compressed_batches_sent, 1);
        STAT_ADD(app, tx_batch_hist[batch_size_bucket(batch_len)], 1);
        client_stats_add_download(app, client->stats_record, batch_len, payload_len, ip_bytes);
        log_message(app, LOG_DEBUG,
                    "[NET][TX] batch sent: packets=%" PRIu64 " original=%zu encoded=%zu saved=%zu frame=%zu compressed=%s ratio=%.2f%% compression_ms=%" PRIu64 " send_ms=%" PRIu64,
                    packet_count, batch_len, payload_len, batch_len > payload_len ? batch_len - payload_len : 0u,
                    ZVPN_HEADER_SIZE + payload_len, (flags & ZVPN_FLAG_ZSTD) ? "yes" : "no",
                    batch_len ? (100.0 * (double)payload_len / (double)batch_len) : 0.0,
                    compression_ms, send_ms);
    }
    free(compressed);
    return rc;
}

static int decode_receive_batch(App *app, Client *client,
                                uint8_t **out_batch, size_t *out_len,
                                uint64_t *packet_count, uint64_t *ip_bytes) {
    *out_batch = NULL; *out_len = 0;
    uint8_t header[ZVPN_HEADER_SIZE];
    if (recv_all(app, client, header, sizeof(header)) < 0) return -1;

    if (memcmp(header, "ZVPN", 4) != 0 || header[4] != ZVPN_VERSION ||
        (header[5] & (uint8_t)~ZVPN_FLAG_ZSTD) != 0 ||
        header[6] != 0 || header[7] != 0) {
        log_message(app, LOG_WARN, "Invalid ZVPN header (magic/version/flags/reserved)");
        errno = EPROTO;
        return -1;
    }

    uint32_t original_len = get_u32(header + 8);
    uint32_t payload_len = get_u32(header + 12);
    size_t max_payload = ZSTD_compressBound(app->config.max_batch_bytes);
    if (original_len == 0 || original_len > app->config.max_batch_bytes ||
        payload_len == 0 || (size_t)payload_len > max_payload) {
        log_message(app, LOG_WARN, "Invalid ZVPN lengths: original=%u payload=%u limit=%zu",
                    original_len, payload_len, app->config.max_batch_bytes);
        errno = EMSGSIZE;
        return -1;
    }
    if (!(header[5] & ZVPN_FLAG_ZSTD) && payload_len != original_len) {
        log_message(app, LOG_WARN, "Raw frame payload length does not match original length");
        errno = EPROTO;
        return -1;
    }

    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload) return -1;
    if (recv_all(app, client, payload, payload_len) < 0) { free(payload); return -1; }

    uint8_t *decoded = payload;
    size_t decoded_len = payload_len;
    uint64_t decompression_ms = 0;
    if (header[5] & ZVPN_FLAG_ZSTD) {
        uint64_t start_us = monotonic_us();
        decoded = (uint8_t *)malloc(original_len);
        if (!decoded) { free(payload); return -1; }
        decoded_len = ZSTD_decompress(decoded, original_len, payload, payload_len);
        free(payload);
        uint64_t decompression_elapsed_us = monotonic_us() - start_us;
        decompression_ms = decompression_elapsed_us / 1000u;
        if (ZSTD_isError(decoded_len) || decoded_len != original_len) {
            log_message(app, LOG_WARN, "Zstd decompression error: %s",
                        ZSTD_isError(decoded_len) ? ZSTD_getErrorName(decoded_len) : "wrong output size");
            free(decoded);
            errno = EPROTO;
            return -1;
        }
        STAT_ADD(app, decompression_time_us_received, decompression_elapsed_us);
    }

    int verbose_now;
    mutex_lock(&app->log_lock);
    verbose_now = app->config.verbose;
    mutex_unlock(&app->log_lock);
    if (count_batch_packets(app, decoded, decoded_len, packet_count, ip_bytes,
                            verbose_now, "CLIENT->TUN") < 0) {
        log_message(app, LOG_WARN, "Rejected malformed packet batch");
        free(decoded);
        return -1;
    }

    STAT_ADD(app, batches_received, 1);
    STAT_ADD(app, packets_received_from_client, *packet_count);
    STAT_ADD(app, payload_original_bytes_received, original_len);
    STAT_ADD(app, payload_encoded_bytes_received, payload_len);
    if (original_len > payload_len)
        STAT_ADD(app, payload_saved_bytes_received, original_len - payload_len);
    if (header[5] & ZVPN_FLAG_ZSTD) STAT_ADD(app, compressed_batches_received, 1);
    STAT_ADD(app, rx_batch_hist[batch_size_bucket(original_len)], 1);
    client_stats_add_upload(app, client->stats_record, original_len, payload_len, *ip_bytes);
    log_message(app, LOG_DEBUG,
                "RX batch: packets=%" PRIu64 " original=%u encoded=%u saved=%u compressed=%s decode_ms=%" PRIu64,
                *packet_count, original_len, payload_len,
                original_len > payload_len ? original_len - payload_len : 0u,
                (header[5] & ZVPN_FLAG_ZSTD) ? "yes" : "no",
                decompression_ms);

    *out_batch = decoded;
    *out_len = decoded_len;
    return 0;
}

static int client_subnet_values(App *app, uint32_t *network_host, uint32_t *mask_host,
                                uint32_t *tun_host, int *prefix_out) {
    char subnet_text[64], tun_text[64];
    (void)snprintf(subnet_text, sizeof(subnet_text), "%s", app->config.client_subnet_cidr);
    (void)snprintf(tun_text, sizeof(tun_text), "%s", app->config.tun_ipv4_cidr);
    char *subnet_slash = strchr(subnet_text, '/');
    char *tun_slash = strchr(tun_text, '/');
    if (!subnet_slash || !tun_slash) return -1;
    *subnet_slash++ = '\0'; *tun_slash = '\0';
    char *end = NULL;
    long prefix = strtol(subnet_slash, &end, 10);
    struct in_addr subnet_addr, tun_addr;
    if (!subnet_slash[0] || !end || *end || prefix < 1 || prefix > 32 ||
        inet_pton(AF_INET, subnet_text, &subnet_addr) != 1 ||
        inet_pton(AF_INET, tun_text, &tun_addr) != 1) return -1;
    uint32_t mask = prefix == 32 ? UINT32_MAX : (UINT32_MAX << (32 - (int)prefix));
    uint32_t subnet_host = ntohl(subnet_addr.s_addr);
    uint32_t tun_h = ntohl(tun_addr.s_addr);
    *network_host = subnet_host & mask;
    *mask_host = mask;
    *tun_host = tun_h;
    if (prefix_out) *prefix_out = (int)prefix;
    return 0;
}

static uint32_t packet_ipv4_addr_host(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

/* Learn and reserve the inner IPv4 address used by a client. ZVPN v1 has no
   address-assignment handshake, so each connected client must be configured
   with a distinct address inside --client-subnet. */
static int client_learn_ipv4(App *app, Client *client, const uint8_t *packet, size_t packet_len) {
    if (get_ip_version(packet, packet_len) != 4) return 0;
    uint32_t network_host, mask_host, server_host;
    int prefix = 0;
    if (client_subnet_values(app, &network_host, &mask_host, &server_host, &prefix) < 0) {
        errno = EINVAL;
        log_message(app, LOG_ERROR, "Invalid client subnet/TUN IPv4 configuration; cannot route multiple clients");
        return -1;
    }
    uint32_t source_host = packet_ipv4_addr_host(packet + 12);
    if ((source_host & mask_host) != network_host || source_host == server_host ||
        (prefix <= 30 && (source_host == network_host || source_host == (network_host | ~mask_host)))) {
        char source_text[INET_ADDRSTRLEN] = "?";
        struct in_addr a; a.s_addr = htonl(source_host);
        (void)inet_ntop(AF_INET, &a, source_text, sizeof(source_text));
        log_message(app, LOG_WARN, "Rejected client %s packet with inner source %s outside usable subnet %s",
                    client->peer, source_text, app->config.client_subnet_cidr);
        STAT_ADD(app, rejected_packets, 1);
        errno = EACCES;
        return -1;
    }
    mutex_lock(&app->clients_lock);
    if (client->has_tunnel_ip && client->tunnel_ip_host != source_host) {
        mutex_unlock(&app->clients_lock);
        log_message(app, LOG_WARN, "Client %s changed inner IPv4 address during a session; rejected", client->peer);
        STAT_ADD(app, rejected_packets, 1);
        errno = EACCES;
        return -1;
    }
    for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i) {
        Client *other = app->clients[i];
        if (other && other != client && other->has_tunnel_ip && other->tunnel_ip_host == source_host) {
            mutex_unlock(&app->clients_lock);
            char source_text[INET_ADDRSTRLEN] = "?";
            struct in_addr a; a.s_addr = htonl(source_host);
            (void)inet_ntop(AF_INET, &a, source_text, sizeof(source_text));
            log_message(app, LOG_WARN, "Rejected duplicate VPN IPv4 %s from %s; already assigned to another connection",
                        source_text, client->peer);
            STAT_ADD(app, rejected_packets, 1);
            errno = EADDRINUSE;
            return -1;
        }
    }
    if (!client->has_tunnel_ip) {
        client->tunnel_ip_host = source_host;
        client->has_tunnel_ip = 1;
        char source_text[INET_ADDRSTRLEN] = "?";
        struct in_addr a; a.s_addr = htonl(source_host);
        (void)inet_ntop(AF_INET, &a, source_text, sizeof(source_text));
        log_message(app, LOG_INFO, "Client %s assigned inner IPv4 %s", client->peer, source_text);
    }
    mutex_unlock(&app->clients_lock);
    return 0;
}

static int write_batch_to_tun(App *app, Client *client, const uint8_t *batch, size_t len) {
    size_t off = 0;
    while (off < len) {
        if (len - off < 4) { errno = EPROTO; return -1; }
        uint32_t packet_len = get_u32(batch + off);
        off += 4;
        if (packet_len == 0 || packet_len > ZVPN_MAX_IP_PACKET || packet_len > len - off) {
            errno = EPROTO;
            return -1;
        }
        if (!validate_ip_packet(batch + off, packet_len)) {
            log_message(app, LOG_WARN, "Dropping invalid IP packet in batch (length=%u)", packet_len);
            STAT_ADD(app, rejected_packets, 1);
            errno = EPROTO;
            return -1;
        }
        /* Automatic NAT/forwarding is IPv4-only on Linux and Windows. IPv6
           must not be accepted then silently black-holed by an IPv4-only route. */
        if (app->config.auto_network && get_ip_version(batch + off, packet_len) == 6) {
            char v6_description[256];
            describe_packet(v6_description, sizeof(v6_description), batch + off, packet_len);
            log_message(app, LOG_DEBUG, "[FILTER] Dropping IPv6 packet (automatic network mode is IPv4-only): %s", v6_description);
            STAT_ADD(app, rejected_packets, 1);
            off += packet_len;
            continue;
        }
        if (get_ip_version(batch + off, packet_len) == 4 &&
            client_learn_ipv4(app, client, batch + off, packet_len) < 0) {
            int source_error = errno;
            /* A duplicate inner IPv4 address makes return routing ambiguous, so
               disconnect that session instead of silently black-holing all of it. */
            if (source_error == EADDRINUSE) client_request_stop(client);
            off += packet_len;
            continue;
        }
        if (tun_write_packet(app, batch + off, packet_len) < 0) {
            int saved_errno = errno;
            char description[256];
            describe_packet(description, sizeof(description), batch + off, packet_len);
            log_message(app, LOG_ERROR, "[FLOW][CLIENT->TUN] TUN write failed on '%s': %s; packet=%s",
                        app->tun.name, strerror(saved_errno), description);
            errno = saved_errno;
            return -1;
        }
        STAT_ADD(app, client_ip_bytes_in, packet_len);
        char description[256];
        describe_packet(description, sizeof(description), batch + off, packet_len);
        log_message(app, LOG_DEBUG, "[CLIENT->TUN] injected packet: %s", description);
        off += packet_len;
    }
    return 0;
}

static int client_stopping(Client *c) {
#ifdef _WIN32
    return InterlockedCompareExchange(&c->stop, 0, 0) != 0;
#else
    return atomic_load_explicit(&c->stop, memory_order_acquire) != 0;
#endif
}

static void client_request_stop(Client *c) {
#ifdef _WIN32
    InterlockedExchange(&c->stop, 1);
#else
    atomic_store_explicit(&c->stop, 1, memory_order_release);
#endif
    (void)socket_shutdown(c->socket);
}

#ifdef _WIN32
#define THREAD_ENTRY(name) static DWORD WINAPI name(LPVOID opaque)
#define THREAD_DONE return 0
#else
#define THREAD_ENTRY(name) static void *name(void *opaque)
#define THREAD_DONE return NULL
#endif

static int flush_client_batch_locked(App *app, Client *client) {
    if (!client || !client->out_used) return 0;
    uint64_t packet_count = 0, ip_bytes = 0;
    if (count_batch_packets(app, client->out_batch, client->out_used,
                            &packet_count, &ip_bytes, 0, "TUN->CLIENT") < 0) {
        client_request_stop(client);
        client->out_used = 0;
        client->out_batch_started_ms = 0;
        return -1;
    }
    size_t batch_len = client->out_used;
    client->out_used = 0;
    client->out_batch_started_ms = 0;
    if (encode_send_batch(app, client, client->out_batch, batch_len,
                          packet_count, ip_bytes) < 0) {
        log_message(app, LOG_WARN, "Could not send TUN batch to client %s; disconnecting it", client->peer);
        client_request_stop(client);
        return -1;
    }
    return 0;
}

/* Called only by the single TUN reader while clients_lock is held. */
static int queue_tun_packet_locked(App *app, Client *client,
                                   const uint8_t *packet, size_t packet_len) {
    if (packet_len == 0 || packet_len > ZVPN_MAX_IP_PACKET ||
        packet_len + 4u > app->config.out_batch_target_bytes) return -1;
    size_t needed = packet_len + 4u;
    if (client->out_used && needed > app->config.out_batch_target_bytes - client->out_used) {
        if (flush_client_batch_locked(app, client) < 0) return -1;
    }
    if (!client->out_used) client->out_batch_started_ms = monotonic_ms();
    put_u32(client->out_batch + client->out_used, (uint32_t)packet_len);
    client->out_used += 4u;
    memcpy(client->out_batch + client->out_used, packet, packet_len);
    client->out_used += packet_len;
    if (client->out_used >= app->config.out_batch_target_bytes || app->config.flush_timeout_ms == 0)
        return flush_client_batch_locked(app, client);
    return 0;
}

/* Called while clients_lock is held. Lock ordering is clients_lock -> log_lock,
 * matching the TUN batch and auto-tuner paths. The wait is bounded: a batch
 * below --min-batch can be held past --flush-ms only until --min-batch-wait-ms. */
static uint64_t client_batch_timeout_locked(App *app, Client *client) {
    uint64_t timeout = (uint64_t)app->config.flush_timeout_ms;
    if (timeout == 0 || app->config.min_batch_wait_ms <= app->config.flush_timeout_ms ||
        !client || !client->out_used) return timeout;

    size_t min_compress_bytes;
    mutex_lock(&app->log_lock);
    min_compress_bytes = app->config.min_compress_batch_bytes;
    mutex_unlock(&app->log_lock);

    if (min_compress_bytes > 0 && client->out_used < min_compress_bytes)
        timeout = (uint64_t)app->config.min_batch_wait_ms;
    return timeout;
}

static int client_flush_wait_ms(App *app) {
    int wait_ms = ZVPN_TUN_WAIT_MS;
    uint64_t now = monotonic_ms();
    mutex_lock(&app->clients_lock);
    for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i) {
        Client *c = app->clients[i];
        if (!c || !c->out_used) continue;
        uint64_t timeout = client_batch_timeout_locked(app, c);
        uint64_t deadline = c->out_batch_started_ms + timeout;
        int remain = deadline <= now ? 0 : (deadline - now > (uint64_t)INT_MAX ? INT_MAX : (int)(deadline - now));
        if (remain < wait_ms) wait_ms = remain;
    }
    mutex_unlock(&app->clients_lock);
    return wait_ms;
}

static void flush_aged_client_batches(App *app) {
    uint64_t now = monotonic_ms();
    mutex_lock(&app->clients_lock);
    for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i) {
        Client *c = app->clients[i];
        if (!c || !c->out_used) continue;
        uint64_t timeout = client_batch_timeout_locked(app, c);
        if (now >= c->out_batch_started_ms + timeout)
            (void)flush_client_batch_locked(app, c);
    }
    mutex_unlock(&app->clients_lock);
}

THREAD_ENTRY(tun_to_clients_worker) {
    App *app = (App *)opaque;
    uint8_t packet[ZVPN_MAX_IP_PACKET];
    log_message(app, LOG_INFO, "Shared TUN reader started (download target=%zu bytes; buffer/protocol ceiling=%zu; min-Zstd=%zu; under-min wait=%d ms; flush=%d ms)",
                app->config.out_batch_target_bytes, app->config.max_batch_bytes,
                app->config.min_compress_batch_bytes, app->config.min_batch_wait_ms,
                app->config.flush_timeout_ms);
    while (app_running()) {
        size_t packet_len = 0;
        int rc = tun_read_packet(app, packet, sizeof(packet), client_flush_wait_ms(app), &packet_len);
        if (rc < 0) {
            if (app_running()) log_message(app, LOG_WARN, "Shared TUN read failed: %s", strerror(errno));
            sleep_ms(20);
            if (app_running()) continue;
            break;
        }
        if (rc > 0 && packet_len > 0 && packet_len <= sizeof(packet) && validate_ip_packet(packet, packet_len)) {
            if (get_ip_version(packet, packet_len) == 4) {
                uint32_t dst_host = packet_ipv4_addr_host(packet + 16);
                int routed = 0;
                mutex_lock(&app->clients_lock);
                for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i) {
                    Client *c = app->clients[i];
                    if (c && !client_stopping(c) && c->has_tunnel_ip && c->tunnel_ip_host == dst_host) {
                        (void)queue_tun_packet_locked(app, c, packet, packet_len);
                        routed = 1;
                        break;
                    }
                }
                mutex_unlock(&app->clients_lock);
                if (!routed) {
                    char descr[256];
                    describe_packet(descr, sizeof(descr), packet, packet_len);
                    log_message(app, LOG_DEBUG, "[ROUTE][DROP] No connected client owns destination address: %s", descr);
                }
            } else {
                log_message(app, LOG_DEBUG, "[ROUTE][DROP] Unroutable non-IPv4 packet from shared TUN (auto networking is IPv4-only)");
            }
        } else if (rc > 0) {
            log_message(app, LOG_DEBUG, "Skipping invalid packet read from shared TUN (%zu bytes)", packet_len);
        }
        flush_aged_client_batches(app);
    }
    THREAD_DONE;
}

static void client_unregister_and_free(Client *client) {
    App *app = client->app;
    client_request_stop(client);
    mutex_lock(&app->clients_lock);
    for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i) {
        if (app->clients[i] == client) {
            app->clients[i] = NULL;
            if (app->client_count) app->client_count--;
            break;
        }
    }
    mutex_unlock(&app->clients_lock);
    if (client->stats_record) client_stats_end(app, client->stats_record);
    (void)socket_close(client->socket);
    log_message(app, LOG_INFO, "Client disconnected: %s (%s)", client->peer, client->endpoint);
    free(client->out_batch);
    free(client);
}

THREAD_ENTRY(client_worker) {
    Client *client = (Client *)opaque;
    App *app = client->app;
    /* A finite send timeout prevents slow receivers from stalling shared TUN routing indefinitely. */
#ifdef _WIN32
    DWORD send_timeout = 2000;
    (void)setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO,
                     (const char *)&send_timeout, sizeof(send_timeout));
#else
    struct timeval send_timeout = {2, 0};
    (void)setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO,
                     &send_timeout, sizeof(send_timeout));
#endif
    log_message(app, LOG_INFO, "Client connected: %s (%s); waiting for unique inner IPv4", client->peer, client->endpoint);
    while (app_running() && !client_stopping(client)) {
        uint8_t *batch = NULL;
        size_t batch_len = 0;
        uint64_t packets = 0, ip_bytes = 0;
        if (decode_receive_batch(app, client, &batch, &batch_len, &packets, &ip_bytes) < 0) {
            if (app_running() && !client_stopping(client))
                log_message(app, LOG_INFO, "[NET] Receive loop ended for %s (%s)", client->peer,
                            errno == ECANCELED ? "shutdown requested" : strerror(errno));
            free(batch);
            break;
        }
        if (write_batch_to_tun(app, client, batch, batch_len) < 0) {
            log_message(app, LOG_WARN, "Could not inject client %s batch into TUN: %s", client->peer, strerror(errno));
            free(batch);
            break;
        }
        free(batch);
        log_message(app, LOG_DEBUG, "[FLOW][CLIENT->TUN] %s batch injected: packets=%" PRIu64 " ip_bytes=%" PRIu64,
                    client->peer, packets, ip_bytes);
    }
    client_unregister_and_free(client);
    THREAD_DONE;
}

static socket_t create_listener(App *app) {
    char port_text[16];
    (void)snprintf(port_text, sizeof(port_text), "%d", app->config.port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *addresses = NULL;
    int gai = getaddrinfo(app->config.bind_address, port_text, &hints, &addresses);
    if (gai != 0) {
#ifdef _WIN32
        log_message(app, LOG_ERROR, "getaddrinfo failed: %d", gai);
#else
        log_message(app, LOG_ERROR, "getaddrinfo failed: %s", gai_strerror(gai));
#endif
        return INVALID_SOCK;
    }

    socket_t listener = INVALID_SOCK;
    for (struct addrinfo *ai = addresses; ai; ai = ai->ai_next) {
        socket_t s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCK) continue;
        int yes = 1;
#ifdef _WIN32
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
#else
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif
#ifdef _WIN32
        int bind_rc = bind(s, ai->ai_addr, (int)ai->ai_addrlen);
#else
        int bind_rc = bind(s, ai->ai_addr, (socklen_t)ai->ai_addrlen);
#endif
        if (bind_rc == 0 && listen(s, 64) == 0) {
            listener = s;
            break;
        }
        /* Keep the bind/listen error in the log before close can overwrite it. */
#ifdef _WIN32
        int bind_error = WSAGetLastError();
        log_message(app, LOG_DEBUG, "Listener candidate bind/listen failed: WSA error=%d", bind_error);
#else
        int bind_error = errno;
        log_message(app, LOG_DEBUG, "Listener candidate bind/listen failed: %s", strerror(bind_error));
#endif
        socket_close(s);
    }
    freeaddrinfo(addresses);
    if (listener == INVALID_SOCK) {
#ifdef _WIN32
        log_message(app, LOG_ERROR, "Could not bind/listen on %s:%d (WSA error=%d)",
                    app->config.bind_address, app->config.port, WSAGetLastError());
#else
        log_message(app, LOG_ERROR, "Could not bind/listen on %s:%d: %s",
                    app->config.bind_address, app->config.port, strerror(errno));
#endif
    }
    return listener;
}

static int get_peer_name(const struct sockaddr *sa, char *out, size_t cap) {
    if (getnameinfo(sa,
#ifdef _WIN32
        (socklen_t)(sa->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)),
#else
        sa->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in),
#endif
        out, (socklen_t)cap, NULL, 0, NI_NUMERICHOST) != 0) {
        (void)snprintf(out, cap, "unknown");
        return -1;
    }
    return 0;
}

static int get_peer_endpoint(const struct sockaddr *sa, char *out, size_t cap) {
    char host[INET6_ADDRSTRLEN] = "unknown", service[16] = "0";
    int rc = getnameinfo(sa,
#ifdef _WIN32
        (socklen_t)(sa->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)),
#else
        sa->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in),
#endif
        host, (socklen_t)sizeof(host), service, (socklen_t)sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) { (void)snprintf(out, cap, "unknown"); return -1; }
    if (sa->sa_family == AF_INET6)
        (void)snprintf(out, cap, "[%s]:%s", host, service);
    else
        (void)snprintf(out, cap, "%s:%s", host, service);
    return 0;
}

static int is_numeric_ip_address(const char *text) {
    struct in_addr a4;
    struct in6_addr a6;
    return inet_pton(AF_INET, text, &a4) == 1 ||
           inet_pton(AF_INET6, text, &a6) == 1;
}

static int ipv6_is_mapped_v4(const struct in6_addr *a6) {
    return IN6_IS_ADDR_V4MAPPED(a6);
}

/* Compare numeric peer addresses independent of IPv6 text compression and
 * IPv4-mapped IPv6 presentation used by dual-stack sockets on Windows. */
static int peer_address_matches(const char *peer, const char *allowed) {
    struct in_addr p4, a4;
    struct in6_addr p6, a6;
    int p_is4 = inet_pton(AF_INET, peer, &p4) == 1;
    int a_is4 = inet_pton(AF_INET, allowed, &a4) == 1;
    if (p_is4 && a_is4) return memcmp(&p4, &a4, sizeof(p4)) == 0;

    int p_is6 = inet_pton(AF_INET6, peer, &p6) == 1;
    int a_is6 = inet_pton(AF_INET6, allowed, &a6) == 1;
    if (p_is6 && a_is6) {
        if (ipv6_is_mapped_v4(&p6) && ipv6_is_mapped_v4(&a6))
            return memcmp(&p6.s6_addr[12], &a6.s6_addr[12], 4) == 0;
        return memcmp(&p6, &a6, sizeof(p6)) == 0;
    }
    if (p_is6 && ipv6_is_mapped_v4(&p6) && a_is4)
        return memcmp(&p6.s6_addr[12], &a4, 4) == 0;
    if (a_is6 && ipv6_is_mapped_v4(&a6) && p_is4)
        return memcmp(&a6.s6_addr[12], &p4, 4) == 0;
    return 0;
}

static int client_ip_is_banned(App *app, const char *ip) {
    int found = 0;
    mutex_lock(&app->bans_lock);
    for (size_t i = 0; i < app->banned_count; ++i) {
        if (peer_address_matches(ip, app->banned_ips[i])) { found = 1; break; }
    }
    mutex_unlock(&app->bans_lock);
    return found;
}

static size_t banned_ips_snapshot(App *app, char out[ZVPN_MAX_BANNED][INET6_ADDRSTRLEN]) {
    mutex_lock(&app->bans_lock);
    size_t count = app->banned_count;
    if (count > ZVPN_MAX_BANNED) count = ZVPN_MAX_BANNED;
    for (size_t i = 0; i < count; ++i)
        (void)snprintf(out[i], INET6_ADDRSTRLEN, "%s", app->banned_ips[i]);
    mutex_unlock(&app->bans_lock);
    return count;
}

static void toggle_client_ban(App *app, const char *ip) {
    if (!ip || !is_numeric_ip_address(ip)) {
        log_message(app, LOG_WARN, "Cannot ban/unban invalid peer IP '%s'", ip ? ip : "(null)");
        return;
    }
    int now_banned = 0;
    mutex_lock(&app->bans_lock);
    size_t index = app->banned_count;
    for (size_t i = 0; i < app->banned_count; ++i) {
        if (peer_address_matches(ip, app->banned_ips[i])) { index = i; break; }
    }
    if (index < app->banned_count) {
        for (size_t i = index + 1; i < app->banned_count; ++i)
            memmove(app->banned_ips[i - 1], app->banned_ips[i], INET6_ADDRSTRLEN);
        app->banned_count--;
        app->banned_ips[app->banned_count][0] = '\0';
        now_banned = 0;
    } else if (app->banned_count < ZVPN_MAX_BANNED) {
        (void)snprintf(app->banned_ips[app->banned_count++], INET6_ADDRSTRLEN, "%s", ip);
        now_banned = 1;
    } else {
        mutex_unlock(&app->bans_lock);
        log_message(app, LOG_WARN, "Ban list is full (%u entries)", (unsigned)ZVPN_MAX_BANNED);
        return;
    }
    mutex_unlock(&app->bans_lock);
    if (now_banned) {
        mutex_lock(&app->clients_lock);
        for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i) {
            Client *c = app->clients[i];
            if (c && peer_address_matches(c->peer, ip)) client_request_stop(c);
        }
        mutex_unlock(&app->clients_lock);
    }
    log_message(app, LOG_INFO, "[ACCESS] Peer IP %s %s (bans are runtime-only; all sessions from that public IP are affected)",
                ip, now_banned ? "BANNED" : "UNBANNED");
}

static void clear_all_bans(App *app) {
    mutex_lock(&app->bans_lock);
    app->banned_count = 0;
    memset(app->banned_ips, 0, sizeof(app->banned_ips));
    mutex_unlock(&app->bans_lock);
    log_message(app, LOG_INFO, "[ACCESS] All runtime client bans cleared");
}

static void log_stats_snapshot(App *app, const char *prefix) {
    Stats s = stats_snapshot(app);
    uint64_t original = s.payload_original_bytes_received + s.payload_original_bytes_sent;
    uint64_t encoded = s.payload_encoded_bytes_received + s.payload_encoded_bytes_sent;
    uint64_t saved = s.payload_saved_bytes_received + s.payload_saved_bytes_sent;
    double saved_pct = original ? (100.0 * (double)saved / (double)original) : 0.0;
    log_message(app, LOG_INFO,
        "%s | packets client->TUN=%" PRIu64 " TUN->client=%" PRIu64
        " | batches RX/TX=%" PRIu64 "/%" PRIu64
        " compressed RX/TX=%" PRIu64 "/%" PRIu64
        " | IP bytes in/out=%" PRIu64 "/%" PRIu64
        " | wire bytes RX/TX=%" PRIu64 "/%" PRIu64
        " | payload original=%" PRIu64 " encoded=%" PRIu64 " saved=%" PRIu64 " (%.2f%%)"
        " | rejected=%" PRIu64,
        prefix, s.packets_received_from_client, s.packets_sent_to_client,
        s.batches_received, s.batches_sent,
        s.compressed_batches_received, s.compressed_batches_sent,
        s.client_ip_bytes_in, s.client_ip_bytes_out,
        s.transport_bytes_received, s.transport_bytes_sent,
        original, encoded, saved, saved_pct, s.rejected_packets);
}

static void print_usage(FILE *out, const char *name) {
    fprintf(out,
        "ZVPN server - cross-platform ZVPN v1 / Zstandard TUN bridge\n\n"
        "Usage: %s [options]\n\n"
        "Options:\n"
        "  --bind ADDRESS           Listen address (default 0.0.0.0)\n"
        "  --port PORT              TCP port (default %d)\n"
        "  --tun-name NAME          TUN/Wintun name (default zvpn0 on Linux, ZVPN on Windows)\n"
        "  --wintun-dll PATH        Windows Wintun DLL path (default wintun.dll)\n"
        "  --max-batch BYTES        Max uncompressed batch, %u..%u (default %u)\n"
        "  --batch-size BYTES       Alias for --max-batch; also initial download target\n"
        "  --min-batch BYTES        Skip Zstd below this batch size; 0=always try (default 0)\n"
        "  --min-compress-batch N   Alias for --min-batch\n"
        "  --min-batch-wait-ms MS   While below --min-batch, extend flush age up to MS (0=off)\n"
        "                            bounded total age; requires MS > --flush-ms and min-batch > 0\n"
        "  --flush-ms MS            Download batch max age, 0..60000 ms (default 20)\n"
        "  --compression-level N    Download Zstd level (default 3; higher uses more CPU)\n"
        "  --auto-benchmark SEC     Auto-test 8 live profiles in SEC total seconds (60..3600)\n"
        "  --no-compression         Disable Zstd compression\n"
        "  --verbose                Debug logs, including packet metadata (not payload)\n"
        "  --log-file PATH          Log file (default zvpn-server.log; use none to disable)\n"
        "  --no-tui                 Plain log output instead of status TUI\n"
        "  --allow-client IP        Only allow one numeric TCP peer IP (default any)\n"
        "  --auto-network           Auto-configure IPv4, forwarding, NAT/firewall (Linux/Windows)\n"
        "  --no-auto-network        Disable automatic network configuration\n"
        "  --wan-interface IFACE    Outbound interface (default: detect default route)\n"
        "  --tun-ipv4 CIDR          TUN address (default 10.0.0.2/24)\n"
        "  --client-subnet CIDR     VPN client subnet (default 10.0.0.0/24)\n"
        "  --mtu N                  TUN MTU, 576..9000 (default 1500)\n"
        "  --help                   Show this help\n\n"
        "Defaults summary:\n"
        "  Bind/listen: 0.0.0.0:61130; max concurrent clients: 32; client allowlist: any\n"
        "  TUN: 10.0.0.2/24; client subnet: 10.0.0.0/24; MTU: 1500\n"
        "  Download batching: max 262144 bytes (256 KiB), flush age 20 ms\n"
        "  Minimum size for Zstd attempt: 0 bytes (attempt all batch sizes)\n"
        "  Under-minimum wait: off; when enabled, wait for min-batch until its bounded deadline\n"
        "  Download compression: enabled, Zstandard level 3; non-smaller output is sent raw\n"
        "  Automatic benchmark: 8 profiles, equal time slices, actual live traffic required\n"
        "  TUI: enabled when attached to a terminal; verbose: off; log: zvpn-server.log\n"
#if defined(__linux__) || defined(_WIN32)
        "  Automatic IPv4 network setup: on (requires root/Administrator)\n"
#else
        "  Automatic IPv4 network setup: off on this platform\n"
#endif
        "  TUN name: "
#ifdef _WIN32
        "ZVPN; Wintun DLL: wintun.dll\n\n"
#else
        "zvpn0; Wintun DLL option defaults to wintun.dll (Windows only)\n\n"
#endif
        "Interactive TUI keys (when attached to a terminal):\n"
        "  Q quit  S stats  I diagnostics  V verbose  C compression  R reset  H help\n"
        "  B client ban manager  M benchmark  A auto-tune  D dashboard\n"
        "  + / - change compression level; [ / ] change flush delay by 25 ms\n\n"
        "Linux/Windows automatic IPv4 networking is enabled by default (requires root/Admin).\n"
        "Windows requires Wintun DLL + PowerShell NetNat; another WinNAT subnet may conflict.\n"
        "IPv6 forwarding/NAT is not enabled by this build.\n"
        "WARNING: protocol is unauthenticated plaintext TCP. Use only on a trusted network.\n",
        name, ZVPN_DEFAULT_PORT, ZVPN_MIN_BATCH, ZVPN_MAX_BATCH, ZVPN_DEFAULT_BATCH);
}

static int parse_long(const char *s, long min, long max, long *out) {
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || !s[0] || !end || *end || v < min || v > max) return -1;
    *out = v;
    return 0;
}

static void config_defaults(Config *c) {
    memset(c, 0, sizeof(*c));
    (void)snprintf(c->bind_address, sizeof(c->bind_address), "0.0.0.0");
    (void)snprintf(c->tun_name, sizeof(c->tun_name),
#ifdef _WIN32
        "ZVPN"
#else
        "zvpn0"
#endif
    );
    (void)snprintf(c->wintun_dll, sizeof(c->wintun_dll), "wintun.dll");
    (void)snprintf(c->log_file_path, sizeof(c->log_file_path), "zvpn-server.log");
    c->port = ZVPN_DEFAULT_PORT;
    c->max_batch_bytes = ZVPN_DEFAULT_BATCH;
    c->out_batch_target_bytes = ZVPN_DEFAULT_BATCH;
    c->min_compress_batch_bytes = 0;
    c->min_batch_wait_ms = 0;
    c->flush_timeout_ms = 20;
    c->compression_level = 3;
    c->compression_enabled = 1;
    c->verbose = 0;
    c->tui = 1;
    c->allow_any_client = 1;
#if defined(__linux__) || defined(_WIN32)
    c->auto_network = 1;
#else
    c->auto_network = 0;
#endif
    c->mtu = 1500;
    (void)snprintf(c->tun_ipv4_cidr, sizeof(c->tun_ipv4_cidr), "10.0.0.2/24");
    (void)snprintf(c->client_subnet_cidr, sizeof(c->client_subnet_cidr), "10.0.0.0/24");
}

static int parse_args(int argc, char **argv, Config *c) {
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
            print_usage(stdout, argv[0]);
            exit(0);
        } else if (!strcmp(a, "--verbose") || !strcmp(a, "-v")) {
            c->verbose = 1;
        } else if (!strcmp(a, "--no-tui")) {
            c->tui = 0;
        } else if (!strcmp(a, "--no-compression")) {
            c->compression_enabled = 0;
        } else if (!strcmp(a, "--auto-network")) {
            c->auto_network = 1;
        } else if (!strcmp(a, "--no-auto-network")) {
            c->auto_network = 0;
        } else if (!strcmp(a, "--bind") || !strcmp(a, "--port") ||
                   !strcmp(a, "--tun-name") || !strcmp(a, "--wintun-dll") ||
                   !strcmp(a, "--max-batch") || !strcmp(a, "--batch-size") || !strcmp(a, "--min-batch") ||
                   !strcmp(a, "--min-compress-batch") || !strcmp(a, "--min-batch-wait-ms") || !strcmp(a, "--flush-ms") ||
                   !strcmp(a, "--compression-level") || !strcmp(a, "--auto-benchmark") || !strcmp(a, "--log-file") ||
                   !strcmp(a, "--allow-client") || !strcmp(a, "--wan-interface") ||
                   !strcmp(a, "--tun-ipv4") || !strcmp(a, "--client-subnet") ||
                   !strcmp(a, "--mtu")) {
            if (i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", a); return -1; }
            const char *v = argv[++i];
            long n;
            if (!strcmp(a, "--bind")) {
                if (strlen(v) >= sizeof(c->bind_address)) return -1;
                (void)snprintf(c->bind_address, sizeof(c->bind_address), "%s", v);
            } else if (!strcmp(a, "--port")) {
                if (parse_long(v, 1, 65535, &n) < 0) return -1;
                c->port = (int)n;
            } else if (!strcmp(a, "--tun-name")) {
                if (strlen(v) >= sizeof(c->tun_name)) return -1;
                (void)snprintf(c->tun_name, sizeof(c->tun_name), "%s", v);
            } else if (!strcmp(a, "--wintun-dll")) {
                if (strlen(v) >= sizeof(c->wintun_dll)) return -1;
                (void)snprintf(c->wintun_dll, sizeof(c->wintun_dll), "%s", v);
            } else if (!strcmp(a, "--max-batch") || !strcmp(a, "--batch-size")) {
                if (parse_long(v, ZVPN_MIN_BATCH, ZVPN_MAX_BATCH, &n) < 0) return -1;
                c->max_batch_bytes = (size_t)n;
                c->out_batch_target_bytes = (size_t)n;
            } else if (!strcmp(a, "--min-batch") || !strcmp(a, "--min-compress-batch")) {
                if (parse_long(v, 0, ZVPN_MAX_BATCH, &n) < 0) return -1;
                c->min_compress_batch_bytes = (size_t)n;
            } else if (!strcmp(a, "--min-batch-wait-ms")) {
                if (parse_long(v, 0, 60000, &n) < 0) return -1;
                c->min_batch_wait_ms = (int)n;
            } else if (!strcmp(a, "--auto-benchmark")) {
                if (parse_long(v, 60, 3600, &n) < 0) return -1;
                c->auto_benchmark_seconds = (int)n;
            } else if (!strcmp(a, "--flush-ms")) {
                if (parse_long(v, 0, 60000, &n) < 0) return -1;
                c->flush_timeout_ms = (int)n;
            } else if (!strcmp(a, "--compression-level")) {
                if (parse_long(v, 1, ZSTD_maxCLevel(), &n) < 0) return -1;
                c->compression_level = (int)n;
            } else if (!strcmp(a, "--log-file")) {
                if (strlen(v) >= sizeof(c->log_file_path)) return -1;
                (void)snprintf(c->log_file_path, sizeof(c->log_file_path), "%s", v);
            } else if (!strcmp(a, "--allow-client")) {
                if (strlen(v) >= sizeof(c->allowed_client)) return -1;
                (void)snprintf(c->allowed_client, sizeof(c->allowed_client), "%s", v);
                c->allow_any_client = 0;
            } else if (!strcmp(a, "--wan-interface")) {
                if (strlen(v) >= sizeof(c->wan_interface)) return -1;
                (void)snprintf(c->wan_interface, sizeof(c->wan_interface), "%s", v);
            } else if (!strcmp(a, "--tun-ipv4")) {
                if (strlen(v) >= sizeof(c->tun_ipv4_cidr)) return -1;
                (void)snprintf(c->tun_ipv4_cidr, sizeof(c->tun_ipv4_cidr), "%s", v);
            } else if (!strcmp(a, "--client-subnet")) {
                if (strlen(v) >= sizeof(c->client_subnet_cidr)) return -1;
                (void)snprintf(c->client_subnet_cidr, sizeof(c->client_subnet_cidr), "%s", v);
            } else if (!strcmp(a, "--mtu")) {
                if (parse_long(v, 576, 9000, &n) < 0) return -1;
                c->mtu = (int)n;
            }
        } else {
            fprintf(stderr, "Unknown option: %s\n", a);
            return -1;
        }
    }
    if (c->min_compress_batch_bytes > c->max_batch_bytes) {
        fprintf(stderr, "--min-batch cannot exceed --batch-size/--max-batch ceiling (%zu bytes)\n", c->max_batch_bytes);
        return -1;
    }
    if (c->min_batch_wait_ms > 0) {
        if (c->min_compress_batch_bytes == 0) {
            fprintf(stderr, "--min-batch-wait-ms requires --min-batch greater than 0\n");
            return -1;
        }
        if (c->flush_timeout_ms == 0 || c->min_batch_wait_ms <= c->flush_timeout_ms) {
            fprintf(stderr, "--min-batch-wait-ms must be greater than --flush-ms, and --flush-ms must be greater than 0\n");
            return -1;
        }
        if (c->min_compress_batch_bytes > c->out_batch_target_bytes) {
            fprintf(stderr, "--min-batch must not exceed the initial --batch-size when minimum waiting is enabled\n");
            return -1;
        }
    }
    return 0;
}

static void format_bytes(uint64_t value, char *out, size_t cap) {
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double n = (double)value;
    size_t i = 0;
    while (n >= 1024.0 && i < 4) { n /= 1024.0; i++; }
    (void)snprintf(out, cap, i == 0 ? "%.0f %s" : "%.2f %s", n, units[i]);
}

typedef struct {
    size_t batch_bytes;
    int flush_ms;
    int level;
    size_t min_compress_bytes;
} AutoProfile;

typedef struct {
    size_t batch_size_index;
    int flush_ms;
    int level;
    size_t min_compress_bytes;
} AutoProfileSeed;

typedef struct {
    AutoProfile profile;
    uint64_t original_bytes;
    uint64_t encoded_bytes;
    uint64_t saved_bytes;
    uint64_t batches;
    double savings_pct;
    double saved_bytes_per_second;
    int valid;
} AutoResult;

static void apply_auto_profile(App *app, const AutoProfile *profile) {
    /* Lock order follows the TUN->client path (clients_lock then log_lock).
     * Drain batches created under the previous profile before switching. */
    mutex_lock(&app->clients_lock);
    for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i) {
        Client *c = app->clients[i];
        if (c && c->out_used) (void)flush_client_batch_locked(app, c);
    }
    mutex_lock(&app->log_lock);
    app->config.compression_level = profile->level;
    app->config.min_compress_batch_bytes = profile->min_compress_bytes;
    mutex_unlock(&app->log_lock);
    app->config.out_batch_target_bytes = profile->batch_bytes;
    app->config.flush_timeout_ms = profile->flush_ms;
    mutex_unlock(&app->clients_lock);
    log_message(app, LOG_INFO,
        "[AUTO][PROFILE] target=%zu flush=%dms level=%d min-Zstd=%zu",
        profile->batch_bytes, profile->flush_ms, profile->level, profile->min_compress_bytes);
}

THREAD_ENTRY(auto_benchmark_worker) {
    App *app = (App *)opaque;
    enum { PROFILE_COUNT = 8 };
    AutoResult results[PROFILE_COUNT];
    memset(results, 0, sizeof(results));

    /* Use sizes that never exceed the startup allocation/protocol ceiling. */
    size_t cap = app->config.max_batch_bytes;
    AutoProfile original_profile;
    original_profile.batch_bytes = app->config.out_batch_target_bytes;
    original_profile.flush_ms = app->config.flush_timeout_ms;
    int original_verbose;
    mutex_lock(&app->log_lock);
    original_profile.level = app->config.compression_level;
    original_profile.min_compress_bytes = app->config.min_compress_batch_bytes;
    original_verbose = app->config.verbose;
    /* Avoid per-packet debug logging distorting CPU and batching measurements. */
    app->config.verbose = 0;
    mutex_unlock(&app->log_lock);
    if (cap < 128u * 1024u) {
        log_message(app, LOG_ERROR, "[AUTO] startup batch ceiling %zu is below 128 KiB; use --batch-size at least 131072 for safe profile comparison", cap);
        goto auto_done;
    }
    size_t sizes[4] = { 128u * 1024u, 256u * 1024u, 1024u * 1024u, cap };
    for (size_t i = 0; i < 3; ++i) if (sizes[i] > cap) sizes[i] = cap;
    for (size_t i = 0; i < 4; ++i) {
        if (sizes[i] < ZVPN_MIN_BATCH) sizes[i] = ZVPN_MIN_BATCH;
        if (sizes[i] > cap) sizes[i] = cap;
    }
    const AutoProfileSeed seeds[PROFILE_COUNT] = {
        {0,  50, 1, 0}, {1, 100, 3, 4u * 1024u},
        {2, 200, 5, 16u * 1024u}, {3, 400, 9, 64u * 1024u},
        {0, 200, 5, 16u * 1024u}, {1, 400, 9, 64u * 1024u},
        {2,  50, 1, 0}, {3, 100, 3, 4u * 1024u}
    };
    AutoProfile profiles[PROFILE_COUNT];
    for (int i = 0; i < PROFILE_COUNT; ++i) {
        profiles[i].batch_bytes = sizes[seeds[i].batch_size_index];
        profiles[i].flush_ms = seeds[i].flush_ms;
        profiles[i].level = seeds[i].level;
        profiles[i].min_compress_bytes = seeds[i].min_compress_bytes;
        if (profiles[i].min_compress_bytes > profiles[i].batch_bytes)
            profiles[i].min_compress_bytes = profiles[i].batch_bytes;
    }

    mutex_lock(&app->log_lock);
    int total_seconds = app->config.auto_benchmark_seconds > 0 ? app->config.auto_benchmark_seconds : 120;
    mutex_unlock(&app->log_lock);
    const uint64_t phase_ms = ((uint64_t)total_seconds * 1000u) / PROFILE_COUNT;
    mutex_lock(&app->log_lock);
    app->auto_profile_index = 0;
    app->auto_profile_count = PROFILE_COUNT;
    mutex_unlock(&app->log_lock);
    log_message(app, LOG_INFO,
        "[AUTO] starting %d-second live search across %d profiles (~%" PRIu64 " ms/profile); keep the same download workload running",
        total_seconds, PROFILE_COUNT, phase_ms);

    /* Wait for both an active client and real batch traffic so startup idle time
     * is not charged against the first profile. */
    while (app_running()) {
        Stats st = stats_snapshot(app);
        if (active_client_count(app) > 0 && (st.batches_received + st.batches_sent) > 0) break;
        sleep_ms(200);
    }
    if (!app_running()) goto auto_done;

    int best_index = -1;
    for (int i = 0; i < PROFILE_COUNT && app_running(); ++i) {
        Stats before, after;
        mutex_lock(&app->log_lock);
        app->auto_profile_index = i + 1;
        mutex_unlock(&app->log_lock);
        apply_auto_profile(app, &profiles[i]);
        before = stats_snapshot(app);
        uint64_t start = monotonic_ms();
        while (app_running() && monotonic_ms() - start < phase_ms) sleep_ms(100);
        uint64_t actual_ms = monotonic_ms() - start;
        after = stats_snapshot(app);
        uint64_t original = after.payload_original_bytes_sent >= before.payload_original_bytes_sent ?
            after.payload_original_bytes_sent - before.payload_original_bytes_sent : 0;
        uint64_t encoded = after.payload_encoded_bytes_sent >= before.payload_encoded_bytes_sent ?
            after.payload_encoded_bytes_sent - before.payload_encoded_bytes_sent : 0;
        uint64_t saved = after.payload_saved_bytes_sent >= before.payload_saved_bytes_sent ?
            after.payload_saved_bytes_sent - before.payload_saved_bytes_sent : 0;
        uint64_t batches = after.batches_sent >= before.batches_sent ? after.batches_sent - before.batches_sent : 0;
        results[i].profile = profiles[i];
        results[i].original_bytes = original;
        results[i].encoded_bytes = encoded;
        results[i].saved_bytes = saved;
        results[i].batches = batches;
        results[i].savings_pct = original ? 100.0 * (double)saved / (double)original : 0.0;
        results[i].saved_bytes_per_second = actual_ms ? (double)saved * 1000.0 / (double)actual_ms : 0.0;
        results[i].valid = original >= 128u * 1024u && batches >= 4u;
        ResourceUsage phase_ru = resource_usage_snapshot(app);
        char phase_rss[32];
        format_bytes(phase_ru.rss_bytes, phase_rss, sizeof(phase_rss));
        log_message(app, LOG_INFO,
            "[AUTO][RESULT] #%d valid=%s target=%zu flush=%dms level=%d min-Zstd=%zu batches=%" PRIu64
            " avg=%.1fKiB original=%" PRIu64 " encoded=%" PRIu64 " saved=%" PRIu64
            " savings=%.2f%% saved-rate=%.1fB/s CPU=%s%.1f%% RSS=%s",
            i + 1, results[i].valid ? "yes" : "no", profiles[i].batch_bytes,
            profiles[i].flush_ms, profiles[i].level, profiles[i].min_compress_bytes, batches,
            batches ? ((double)original / (double)batches / 1024.0) : 0.0,
            original, encoded, saved, results[i].savings_pct, results[i].saved_bytes_per_second,
            phase_ru.cpu_valid ? "" : "warming-up ", phase_ru.cpu_percent,
            phase_ru.memory_valid ? phase_rss : "n/a");
        if (results[i].valid && (best_index < 0 ||
            results[i].savings_pct > results[best_index].savings_pct + 0.05 ||
            (results[i].savings_pct >= results[best_index].savings_pct - 0.05 &&
             results[i].saved_bytes_per_second > results[best_index].saved_bytes_per_second))) {
            best_index = i;
        }
    }

    if (app_running() && best_index >= 0) {
        apply_auto_profile(app, &results[best_index].profile);
        log_message(app, LOG_INFO,
            "[AUTO][BEST] savings=%.2f%% target=%zu flush=%dms level=%d min-Zstd=%zu; applied live",
            results[best_index].savings_pct, results[best_index].profile.batch_bytes,
            results[best_index].profile.flush_ms, results[best_index].profile.level,
            results[best_index].profile.min_compress_bytes);
        log_message(app, LOG_INFO,
            "[AUTO][SAVE] add to startup args: --batch-size %zu --flush-ms %d --compression-level %d --min-batch %zu --min-batch-wait-ms %d",
            results[best_index].profile.batch_bytes, results[best_index].profile.flush_ms,
            results[best_index].profile.level, results[best_index].profile.min_compress_bytes,
            app->config.min_batch_wait_ms);
        log_message(app, LOG_WARN,
            "[AUTO] winner is based on sequential live traffic, not identical replay; repeat the same workload before treating it as definitive");
    } else if (app_running()) {
        /* Do not leave an arbitrary test profile active if sample traffic was inadequate. */
        log_message(app, LOG_WARN,
            "[AUTO] no profile had enough download traffic (need >=128 KiB and >=4 batches/profile); restoring startup settings");
        apply_auto_profile(app, &original_profile);
    }

auto_done:
    mutex_lock(&app->log_lock);
    app->config.verbose = original_verbose;
    app->auto_benchmark_active = 0;
    app->auto_benchmark_done = 1;
    mutex_unlock(&app->log_lock);
    log_message(app, LOG_INFO, "[AUTO] search finished");
    THREAD_DONE;
}

static void start_auto_benchmark(App *app, int seconds) {
    if (!app_running()) {
        log_message(app, LOG_WARN, "[AUTO] ignored because server shutdown has started");
        return;
    }
    if (seconds < 60) seconds = 120;
    if (seconds > 3600) seconds = 3600;
    mutex_lock(&app->log_lock);
    if (app->auto_benchmark_thread_started) {
        int active = app->auto_benchmark_active;
        mutex_unlock(&app->log_lock);
        log_message(app, LOG_WARN, "[AUTO] auto-benchmark %s/already ran; restart server to run another search",
                    active ? "is already running" : "has already completed");
        return;
    }
    if (!app->config.compression_enabled) {
        mutex_unlock(&app->log_lock);
        log_message(app, LOG_WARN, "[AUTO] server-to-client compression is OFF; press C to enable it before auto-tuning");
        return;
    }
    app->config.auto_benchmark_seconds = seconds;
    app->auto_benchmark_active = 1;
    app->auto_benchmark_thread_started = 1;
    mutex_unlock(&app->log_lock);

    int rc = thread_start(&app->auto_benchmark_thread, auto_benchmark_worker, app);
    if (rc != 0) {
        mutex_lock(&app->log_lock);
        app->auto_benchmark_active = 0;
        app->auto_benchmark_thread_started = 0;
        mutex_unlock(&app->log_lock);
        log_message(app, LOG_ERROR, "[AUTO] could not start benchmark thread (error=%d)", rc);
        return;
    }
    log_message(app, LOG_INFO, "[AUTO] queued; waiting for an active client and real batch traffic");
}

static void log_diagnostics(App *app) {
    Stats s = stats_snapshot(app);
    ResourceUsage ru = resource_usage_snapshot(app);
    RuntimeSettings cfg = runtime_settings_snapshot(app);
    uint64_t orig = s.payload_original_bytes_sent;
    uint64_t saved = s.payload_saved_bytes_sent;
    double pct = orig ? 100.0 * (double)saved / (double)orig : 0.0;
    double avg = s.batches_sent ? (double)orig / (double)s.batches_sent : 0.0;
    log_message(app, LOG_INFO,
        "[DIAG] DL original=%" PRIu64 " encoded=%" PRIu64 " saved=%" PRIu64 " savings=%.2f%% batches=%" PRIu64 " avg_batch=%.1fKiB min-Zstd=%zu under-min-wait=%dms flush=%dms",
        orig, s.payload_encoded_bytes_sent, saved, pct, s.batches_sent, avg / 1024.0,
        cfg.min_compress_batch_bytes, cfg.min_batch_wait_ms, cfg.flush_timeout_ms);
    log_message(app, LOG_INFO,
        "[DIAG] RX batches=%" PRIu64 " compressed=%" PRIu64 " decode_ms=%" PRIu64
        " | TX batches=%" PRIu64 " compressed=%" PRIu64 " attempts=%" PRIu64 " compress_ms=%" PRIu64 " skipped-small=%" PRIu64,
        s.batches_received, s.compressed_batches_received, s.decompression_time_us_received / 1000u,
        s.batches_sent, s.compressed_batches_sent, s.compression_attempts_sent,
        s.compression_time_us_sent / 1000u, s.small_batches_skipped_compression);
    log_message(app, LOG_INFO,
        "[DIAG] CPU=%s%.1f%% of one core RSS=%" PRIu64 "B peak-RSS=%" PRIu64 "B; 100%% CPU means one full core",
        ru.cpu_valid ? "" : "warming-up ", ru.cpu_percent, ru.rss_bytes, ru.peak_rss_bytes);
    if (!cfg.compression_enabled)
        log_message(app, LOG_WARN, "[DIAG][CAUSE] server-to-client compression is disabled; enable Zstd with C or restart without --no-compression");
    else if (s.batches_sent < 4 || orig < 256u * 1024u)
        log_message(app, LOG_WARN, "[DIAG][CAUSE] insufficient download sample; run a steady workload before judging savings");
    else if (s.batches_sent > 0 && s.small_batches_skipped_compression > s.batches_sent / 2u)
        log_message(app, LOG_WARN, "[DIAG][CAUSE] many batches bypass Zstd below --min-batch=%zu; lower the threshold to attempt compression on more batches", cfg.min_compress_batch_bytes);
    else if (pct < 10.0 && avg < 64.0 * 1024.0)
        log_message(app, LOG_WARN, "[DIAG][CAUSE] low savings with small batches; test higher --flush-ms with the same workload, noting the added latency");
    else if (pct < 10.0)
        log_message(app, LOG_WARN, "[DIAG][CAUSE] low savings despite larger batches; HTTPS/TLS/QUIC or already-compressed content is likely; larger batches or higher levels may not help");
    else if (ru.cpu_valid && ru.cpu_percent > 80.0)
        log_message(app, LOG_WARN, "[DIAG][CAUSE] process CPU is high (%.1f%% of one core); compare Zstd levels 1, 3, and 5", ru.cpu_percent);
    else
        log_message(app, LOG_INFO, "[DIAG][CAUSE] current server-side counters show no obvious severe download-compression issue; verify physical NIC bytes for real traffic savings");
}

typedef enum {
    TUI_STYLE_NORMAL = 0,
    TUI_STYLE_TITLE,
    TUI_STYLE_SECTION,
    TUI_STYLE_MUTED,
    TUI_STYLE_BLUE,
    TUI_STYLE_GREEN,
    TUI_STYLE_YELLOW,
    TUI_STYLE_SAVED,
    TUI_STYLE_HELP,
    TUI_STYLE_ERROR
} TuiStyle;

static const char *tui_style_code(TuiStyle style) {
    switch (style) {
        case TUI_STYLE_TITLE:   return "\033[1;4;38;5;51m";  /* bold + underline, aqua */
        case TUI_STYLE_SECTION: return "\033[1;38;5;213m";   /* bold, orchid */
        case TUI_STYLE_MUTED:   return "\033[2;3;38;5;245m";  /* dim + italic */
        case TUI_STYLE_BLUE:    return "\033[38;5;75m";
        case TUI_STYLE_GREEN:   return "\033[1;38;5;82m";
        case TUI_STYLE_YELLOW:  return "\033[1;38;5;220m";
        case TUI_STYLE_SAVED:   return "\033[1;4;38;5;46m";   /* bold + underline */
        case TUI_STYLE_HELP:    return "\033[1;38;5;226m";
        case TUI_STYLE_ERROR:   return "\033[1;38;5;203m";
        default:                return "\033[38;5;252m";
    }
}

static void terminal_dimensions(int *columns, int *rows) {
    *columns = 80;
    *rows = 24;
#ifdef _WIN32
    HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (hout != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(hout, &info)) {
        int cols = (int)(info.srWindow.Right - info.srWindow.Left + 1);
        int lines = (int)(info.srWindow.Bottom - info.srWindow.Top + 1);
        if (cols > 0) *columns = cols;
        if (lines > 0) *rows = lines;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_col > 0) *columns = (int)ws.ws_col;
        if (ws.ws_row > 0) *rows = (int)ws.ws_row;
    }
#endif
}

static void tui_border(int newline) {
    char line[81];
    line[0] = '+';
    memset(line + 1, '-', 78);
    line[79] = '+';
    line[80] = '\0';
    printf("\033[1;38;5;45m%s\033[0m", line);
    if (newline) putchar('\n');
}

static void tui_row_style(TuiStyle style, int newline, const char *fmt, ...) {
    char row[512];
    va_list args;
    va_start(args, fmt);
    (void)vsnprintf(row, sizeof(row), fmt, args);
    va_end(args);

    /* Row text itself contains no ANSI codes, so its visible width is deterministic. */
    row[76] = '\0';
    printf("\033[1;38;5;45m|\033[0m %s%-76.76s\033[0m \033[1;38;5;45m|\033[0m",
           tui_style_code(style), row);
    if (newline) putchar('\n');
}

static void tui_small_message(int columns, int rows) {
    const char *line1 = "ZVPN SERVER - live dashboard";
    const char *line2 = "Resize terminal to at least 80 columns and 16 rows.";
    int n1 = columns > 1 ? columns - 1 : 1;
    int n2 = n1;
    printf("\033[2J\033[H\033[1;38;5;51m%.*s\033[0m", n1, line1);
    if (rows >= 2) printf("\n\033[3;38;5;220m%.*s\033[0m", n2, line2);
    fflush(stdout);
}

static size_t active_client_count(App *app);

static void render_tui_compact(App *app, Stats s,
                               int compression_display, int verbose_display, uint64_t raw_total,
                               uint64_t wire_total, double saved_pct, int terminal_rows) {
    char a[32], b[32], c[32], d[32], e[32], f[32];
    char dl_original[32], dl_encoded[32], dl_saved[32];
    char ul_original[32], ul_encoded[32], ul_saved[32];
    format_bytes(s.client_ip_bytes_in, a, sizeof(a));
    format_bytes(s.client_ip_bytes_out, b, sizeof(b));
    format_bytes(s.transport_bytes_received, c, sizeof(c));
    format_bytes(s.transport_bytes_sent, d, sizeof(d));
    format_bytes(raw_total, e, sizeof(e));
    format_bytes(wire_total, f, sizeof(f));
    format_bytes(s.payload_original_bytes_sent, dl_original, sizeof(dl_original));
    format_bytes(s.payload_encoded_bytes_sent, dl_encoded, sizeof(dl_encoded));
    format_bytes(s.payload_saved_bytes_sent, dl_saved, sizeof(dl_saved));
    format_bytes(s.payload_original_bytes_received, ul_original, sizeof(ul_original));
    format_bytes(s.payload_encoded_bytes_received, ul_encoded, sizeof(ul_encoded));
    format_bytes(s.payload_saved_bytes_received, ul_saved, sizeof(ul_saved));
    tui_row_style(TUI_STYLE_TITLE, 1, "ZVPN SERVER  |  ZVPN v1  |  Zstd %s  |  %s",
                  ZSTD_versionString(), app_running() ? "RUNNING" : "STOPPING");
    tui_row_style(TUI_STYLE_NORMAL, 1, "Listen: %s:%d | TUN: %s",
                  app->config.bind_address, app->config.port, app->tun.name);
    tui_row_style(TUI_STYLE_BLUE, 1, "Client sessions: %zu/%u | unique VPN IPv4 per client",
                  active_client_count(app), (unsigned)ZVPN_MAX_CLIENTS);
    tui_border(1);
    tui_row_style(TUI_STYLE_SECTION, 1, "TRAFFIC  |  IP payload / TCP transport bytes");
    tui_row_style(TUI_STYLE_NORMAL, 1, "Upload client->server: %s IP / %s TCP", a, c);
    tui_row_style(TUI_STYLE_NORMAL, 1, "Download server->client: %s IP / %s TCP", b, d);
    tui_row_style(TUI_STYLE_GREEN, 1, "Combined: %s IP / %s TCP", e, f);
    tui_border(1);
    tui_row_style(TUI_STYLE_SECTION, 1, "COMPRESSION SAVINGS  |  %.2f%% overall; framing/TCP/IP overhead excluded", saved_pct);
    tui_row_style(TUI_STYLE_NORMAL, 1, "DOWNLOAD O/E/S: %s / %s / %s", dl_original, dl_encoded, dl_saved);
    tui_row_style(TUI_STYLE_NORMAL, 1, "UPLOAD   O/E/S: %s / %s / %s", ul_original, ul_encoded, ul_saved);
    ClientStats compact_clients[ZVPN_CLIENT_HISTORY];
    size_t compact_count = client_stats_snapshot(app, compact_clients);
    if (terminal_rows >= 19) {
        tui_border(1);
        tui_row_style(TUI_STYLE_SECTION, 1, "CLIENT MONITOR  |  recent IPs; multiple concurrent TCP clients (unique VPN IPv4 per client)");
        size_t show = compact_count < 2 ? compact_count : 2;
        if (show == 0) {
            tui_row_style(TUI_STYLE_NORMAL, 1, "No client sessions yet.");
        } else {
            for (size_t i = 0; i < show; ++i) {
                char row_dl_original[32], row_dl_saved[32], row_ul_original[32], row_ul_saved[32];
                format_bytes(compact_clients[i].download_original, row_dl_original, sizeof(row_dl_original));
                format_bytes(compact_clients[i].download_saved, row_dl_saved, sizeof(row_dl_saved));
                format_bytes(compact_clients[i].upload_original, row_ul_original, sizeof(row_ul_original));
                format_bytes(compact_clients[i].upload_saved, row_ul_saved, sizeof(row_ul_saved));
                tui_row_style(compact_clients[i].active ? TUI_STYLE_GREEN : TUI_STYLE_NORMAL, 1,
                    "%-18.18s | %-4s | DL %9s/%9s | UL %9s/%9s",
                    compact_clients[i].ip, compact_clients[i].active ? "LIVE" : "idle",
                    row_dl_original, row_dl_saved, row_ul_original, row_ul_saved);
            }
        }
        tui_border(1);
    } else if (compact_count > 0) {
        char first_dl_saved[32], first_ul_saved[32];
        format_bytes(compact_clients[0].download_saved, first_dl_saved, sizeof(first_dl_saved));
        format_bytes(compact_clients[0].upload_saved, first_ul_saved, sizeof(first_ul_saved));
        tui_row_style(TUI_STYLE_BLUE, 1, "CLIENT: %.18s | DL saved %s | UL saved %s",
                      compact_clients[0].ip, first_dl_saved, first_ul_saved);
    } else {
        tui_row_style(TUI_STYLE_BLUE, 1, "CLIENT MONITOR: no sessions yet");
    }
    RuntimeSettings compact_cfg = runtime_settings_snapshot(app);
    tui_row_style(TUI_STYLE_MUTED, 1, "Config: level %d | compression %s | target %zu | min %zu | wait %dms | flush %dms | verbose %s",
                  compact_cfg.compression_level, compression_display ? "ON" : "OFF",
                  compact_cfg.out_batch_target_bytes, compact_cfg.min_compress_batch_bytes,
                  compact_cfg.min_batch_wait_ms, compact_cfg.flush_timeout_ms, verbose_display ? "ON" : "OFF");
    ResourceUsage compact_ru = resource_usage_snapshot(app);
    char compact_rss[32], compact_peak[32];
    format_bytes(compact_ru.rss_bytes, compact_rss, sizeof(compact_rss));
    format_bytes(compact_ru.peak_rss_bytes, compact_peak, sizeof(compact_peak));
    tui_row_style(TUI_STYLE_BLUE, 1, "CPU %s%.1f%%/core | RSS %s | peak %s",
                  compact_ru.cpu_valid ? "" : "warming-up ", compact_ru.cpu_percent,
                  compact_ru.memory_valid ? compact_rss : "n/a", compact_ru.memory_valid ? compact_peak : "n/a");
    tui_row_style(TUI_STYLE_HELP, 0, "KEYS: Q quit | B bans | M benchmark | A auto-tune | I diagnose | D dashboard | S stats | H help");
}

static void render_tui_help(int terminal_rows) {
    if (terminal_rows < 21) {
        tui_border(1);
        tui_row_style(TUI_STYLE_TITLE, 1, "ZVPN HELP  |  H / ? returns to dashboard");
        tui_border(1);
        tui_row_style(TUI_STYLE_SECTION, 1, "KEYS: Q quit | S stats | I diagnose | V verbose | C download compression");
        tui_row_style(TUI_STYLE_NORMAL, 1, "R reset; B bans; M benchmark; A auto-tune; T min-Zstd; +/- level; [/] flush; D dashboard.");
        tui_border(1);
        tui_row_style(TUI_STYLE_SECTION, 1, "DEFAULTS");
        tui_row_style(TUI_STYLE_NORMAL, 1, "Listen 0.0.0.0:61130 | up to 32 TCP clients | allow any IP");
#ifdef _WIN32
        tui_row_style(TUI_STYLE_NORMAL, 1, "TUN ZVPN | tunnel IP 10.0.0.2/24 | client subnet 10.0.0.0/24");
#else
        tui_row_style(TUI_STYLE_NORMAL, 1, "TUN zvpn0 | tunnel IP 10.0.0.2/24 | client subnet 10.0.0.0/24");
#endif
        tui_row_style(TUI_STYLE_NORMAL, 1, "MTU 1500 | batch 262144 bytes | flush 20 ms | min-Zstd 0 | wait-min 0 ms");
        tui_row_style(TUI_STYLE_NORMAL, 1, "Zstd ON at level 3 | verbose OFF | CPU/RSS in dashboard | log zvpn-server.log");
#if defined(__linux__) || defined(_WIN32)
        tui_row_style(TUI_STYLE_NORMAL, 1, "Automatic IPv4 network setup ON by default; root/Admin required.");
#else
        tui_row_style(TUI_STYLE_NORMAL, 1, "Automatic IPv4 network setup OFF by default on macOS.");
#endif
        tui_row_style(TUI_STYLE_MUTED, 1, "Encrypted HTTPS/TLS or QUIC payloads rarely compress further.");
        tui_border(0);
        return;
    }
    tui_border(1);
    tui_row_style(TUI_STYLE_TITLE, 1, "ZVPN HELP  |  press H or ? to return to dashboard");
    tui_border(1);
    tui_row_style(TUI_STYLE_SECTION, 1, "KEYBOARD CONTROLS");
    tui_row_style(TUI_STYLE_NORMAL, 1, "Q  Stop server and clean up settings changed by this run");
    tui_row_style(TUI_STYLE_NORMAL, 1, "S  Write traffic/statistics plus CPU/RSS diagnostics to the log");
    tui_row_style(TUI_STYLE_NORMAL, 1, "I  Write a compression diagnosis and likely cause to the log");
    tui_row_style(TUI_STYLE_NORMAL, 1, "A  Auto-test 8 profiles using current live traffic (default 120 seconds total)");
    tui_row_style(TUI_STYLE_NORMAL, 1, "T  Cycle minimum batch size for Zstd; smaller batches are sent raw");
    tui_row_style(TUI_STYLE_NORMAL, 1, "+/- Change Zstd level; [/] change flush age by 25 ms");
    tui_row_style(TUI_STYLE_NORMAL, 1, "V  Toggle verbose packet metadata logging");
    tui_row_style(TUI_STYLE_NORMAL, 1, "C  Toggle server-to-client (download) compression");
    tui_row_style(TUI_STYLE_NORMAL, 1, "R  Reset global and per-IP traffic/savings counters");
    tui_row_style(TUI_STYLE_NORMAL, 1, "B  Ban manager; 1-8 toggle peer IP; N banned list; U unban all");
    tui_row_style(TUI_STYLE_NORMAL, 1, "M benchmark; A auto-tune; I diagnostics; +/- Zstd level; [/] flush delay; D dashboard");
    tui_border(1);
    tui_row_style(TUI_STYLE_SECTION, 1, "DEFAULT CONFIGURATION");
    tui_row_style(TUI_STYLE_NORMAL, 1, "Listen: 0.0.0.0:61130 | Allowed client IP: any (up to 32 concurrent clients)");
#ifdef _WIN32
    tui_row_style(TUI_STYLE_NORMAL, 1, "TUN name: ZVPN | IPv4 address: 10.0.0.2/24 | Client subnet: 10.0.0.0/24");
#else
    tui_row_style(TUI_STYLE_NORMAL, 1, "TUN name: zvpn0 | IPv4 address: 10.0.0.2/24 | Client subnet: 10.0.0.0/24");
#endif
    tui_row_style(TUI_STYLE_NORMAL, 1, "MTU: 1500 | Max batch: 262144 bytes (256 KiB) | Download flush age: 20 ms");
    tui_row_style(TUI_STYLE_NORMAL, 1, "Download Zstd ON by default | level 3 | min-compress threshold 0 bytes");
    tui_row_style(TUI_STYLE_NORMAL, 1, "Verbose: OFF | TUI: ON when interactive | Log file: zvpn-server.log");
#if defined(__linux__) || defined(_WIN32)
    tui_row_style(TUI_STYLE_NORMAL, 1, "Automatic IPv4 forwarding/NAT/firewall: ON by default (can disable with --no-auto-network)");
#else
    tui_row_style(TUI_STYLE_NORMAL, 1, "Automatic IPv4 forwarding/NAT/firewall: OFF by default on macOS; configure manually");
#endif
    tui_border(1);
    tui_row_style(TUI_STYLE_MUTED, 1, "Compression is payload-dependent. HTTPS/TLS and QUIC data is already encrypted and rarely compresses.");
    tui_row_style(TUI_STYLE_MUTED, 1, "Higher Zstd levels and longer flush ages can cost CPU/latency; compare same workloads before choosing.");
    tui_border(0);
}

static size_t active_client_count(App *app) {
    mutex_lock(&app->clients_lock);
    size_t count = app->client_count;
    mutex_unlock(&app->clients_lock);
    return count;
}

static void render_tui_ban_manager(App *app, int terminal_rows) {
    int list_view;
    size_t offset;
    mutex_lock(&app->log_lock);
    list_view = app->ban_list_view;
    offset = app->ban_list_offset;
    mutex_unlock(&app->log_lock);
    tui_border(1);
    tui_row_style(TUI_STYLE_TITLE, 1, "ZVPN CLIENT ACCESS MANAGER  |  separate screen");
    tui_row_style(TUI_STYLE_NORMAL, 1, "Connected sessions: %zu/%u | access bans are runtime-only", active_client_count(app), (unsigned)ZVPN_MAX_CLIENTS);
    tui_border(1);
    if (!list_view) {
        tui_row_style(TUI_STYLE_SECTION, 1, "RECENT CLIENT PEERS  |  press 1-8 to toggle ban/unban");
        tui_row_style(TUI_STYLE_MUTED, 1, "N = banned list | a ban blocks and disconnects every session from that peer IP");
        ClientStats rows[ZVPN_CLIENT_HISTORY];
        size_t count = client_stats_snapshot(app, rows);
        size_t shown = offset < count ? count - offset : 0;
        if (shown > ZVPN_TUI_CLIENT_ROWS) shown = ZVPN_TUI_CLIENT_ROWS;
        if (!shown) tui_row_style(TUI_STYLE_NORMAL, 1, "No client rows on this page. Connect a client or press [ to go back.");
        for (size_t i = 0; i < shown; ++i) {
            size_t row_index = offset + i;
            int banned = client_ip_is_banned(app, rows[row_index].ip);
            tui_row_style(banned ? TUI_STYLE_ERROR : (rows[row_index].active ? TUI_STYLE_GREEN : TUI_STYLE_NORMAL), 1,
                          "%zu) %-18.18s %-8s %-5s %.22s", i + 1, rows[row_index].ip,
                          banned ? "BANNED" : "allowed", rows[row_index].active ? "LIVE" : "idle", rows[row_index].endpoint);
        }
        if (count > ZVPN_TUI_CLIENT_ROWS)
            tui_row_style(TUI_STYLE_MUTED, 1, "Showing %zu-%zu of %zu recent client sessions", offset + 1,
                          offset + shown, count);
    } else {
        char bans[ZVPN_MAX_BANNED][INET6_ADDRSTRLEN];
        size_t count = banned_ips_snapshot(app, bans);
        tui_row_style(TUI_STYLE_SECTION, 1, "BANNED PEER IPs  |  press 1-8 to unban an entry");
        tui_row_style(TUI_STYLE_MUTED, 1, "[ / ] = previous/next page | N = recent clients | U = clear all bans");
        if (!count) tui_row_style(TUI_STYLE_NORMAL, 1, "No client IPs are currently banned.");
        size_t shown = offset < count ? count - offset : 0;
        if (shown > ZVPN_TUI_CLIENT_ROWS) shown = ZVPN_TUI_CLIENT_ROWS;
        for (size_t i = 0; i < shown; ++i)
            tui_row_style(TUI_STYLE_ERROR, 1, "%zu) %s", i + 1, bans[offset + i]);
        if (count > ZVPN_TUI_CLIENT_ROWS)
            tui_row_style(TUI_STYLE_MUTED, 1, "Showing %zu-%zu of %zu banned addresses", offset + 1,
                          offset + shown, count);
    }
    tui_border(1);
    tui_row_style(TUI_STYLE_HELP, 1, "KEYS: [1-8] toggle item  [N] switch list  [[] previous page  [] next page  [U] unban all  [D] dashboard  [M] benchmark");
    tui_row_style(TUI_STYLE_MUTED, 0, "Security note: ZVPN v1 has no authentication; peer IP bans are not a substitute for authenticated encryption.");
    (void)terminal_rows;
}

static void render_tui_benchmark(App *app) {
    Stats s = stats_snapshot(app);
    ResourceUsage ru = resource_usage_snapshot(app);
    uint64_t now = monotonic_ms();
    RuntimeSettings cfg = runtime_settings_snapshot(app);
    uint64_t benchmark_started_ms = cfg.started_ms;
    int auto_active = cfg.auto_benchmark_active;
    int auto_done = cfg.auto_benchmark_done;
    int auto_index = cfg.auto_profile_index;
    int auto_count = cfg.auto_profile_count;
    int level = cfg.compression_level;
    int compression_enabled = cfg.compression_enabled;
    size_t min_compress = cfg.min_compress_batch_bytes;
    uint64_t elapsed_ms = now > benchmark_started_ms ? now - benchmark_started_ms : 0;
    uint64_t up_original = s.payload_original_bytes_received;
    uint64_t up_encoded = s.payload_encoded_bytes_received;
    uint64_t up_saved = s.payload_saved_bytes_received;
    uint64_t down_original = s.payload_original_bytes_sent;
    uint64_t down_encoded = s.payload_encoded_bytes_sent;
    uint64_t down_saved = s.payload_saved_bytes_sent;
    uint64_t total_original = up_original + down_original;
    uint64_t total_encoded = up_encoded + down_encoded;
    uint64_t total_saved = up_saved + down_saved;
    double saved_pct = total_original ? 100.0 * (double)total_saved / (double)total_original : 0.0;
    double down_pct = down_original ? 100.0 * (double)down_saved / (double)down_original : 0.0;
    double up_pct = up_original ? 100.0 * (double)up_saved / (double)up_original : 0.0;
    double saved_rate = elapsed_ms ? (double)total_saved * 1000.0 / (double)elapsed_ms : 0.0;
    double down_avg = s.batches_sent ? (double)down_original / (double)s.batches_sent : 0.0;
    double up_avg = s.batches_received ? (double)up_original / (double)s.batches_received : 0.0;
    double tx_compressed_pct = s.batches_sent ? 100.0 * (double)s.compressed_batches_sent / (double)s.batches_sent : 0.0;
    double rx_compressed_pct = s.batches_received ? 100.0 * (double)s.compressed_batches_received / (double)s.batches_received : 0.0;
    double avg_compress_ms = s.compression_attempts_sent ?
        ((double)s.compression_time_us_sent / 1000.0) / (double)s.compression_attempts_sent : 0.0;
    char up_o[32], up_e[32], up_s[32], dn_o[32], dn_e[32], dn_s[32], rss[32], peak[32];
    format_bytes(up_original, up_o, sizeof(up_o)); format_bytes(up_encoded, up_e, sizeof(up_e)); format_bytes(up_saved, up_s, sizeof(up_s));
    format_bytes(down_original, dn_o, sizeof(dn_o)); format_bytes(down_encoded, dn_e, sizeof(dn_e)); format_bytes(down_saved, dn_s, sizeof(dn_s));
    format_bytes(ru.rss_bytes, rss, sizeof(rss)); format_bytes(ru.peak_rss_bytes, peak, sizeof(peak));
    tui_border(1);
    tui_row_style(TUI_STYLE_TITLE, 1, "ZVPN BENCHMARK & DIAGNOSTICS | counters since startup/reset");
    tui_row_style(TUI_STYLE_NORMAL, 1, "Runtime %.1fm | target %zuB/cap %zuB | flush %dms | lvl %d | Zstd %s",
                  (double)elapsed_ms / 60000.0, cfg.out_batch_target_bytes,
                  cfg.max_batch_bytes, cfg.flush_timeout_ms,
                  level, compression_enabled ? "ON" : "OFF");
    char auto_status[32];
    if (auto_active && auto_index == 0) (void)snprintf(auto_status, sizeof(auto_status), "WAITING traffic");
    else if (auto_active) (void)snprintf(auto_status, sizeof(auto_status), "%d/%d", auto_index, auto_count);
    else (void)snprintf(auto_status, sizeof(auto_status), "%s", auto_done ? "FINISHED" : "idle (A)");
    tui_row_style(TUI_STYLE_NORMAL, 1, "Min Zstd %zu bytes | wait-under-min %dms (0=off) | auto-tune: %s",
                  min_compress, cfg.min_batch_wait_ms, auto_status);
    tui_border(1);
    tui_row_style(TUI_STYLE_SECTION, 1, "UPLOAD / CLIENT -> SERVER (client performs compression)");
    tui_row_style(TUI_STYLE_NORMAL, 1, "O %s | E %s | saved %s | savings %.2f%%", up_o, up_e, up_s, up_pct);
    tui_row_style(TUI_STYLE_NORMAL, 1, "Batches %" PRIu64 " | avg %.1fKiB | compressed %.1f%% | decode %.2fms",
                  s.batches_received, up_avg / 1024.0, rx_compressed_pct, (double)s.decompression_time_us_received / 1000.0);
    tui_border(1);
    tui_row_style(TUI_STYLE_SECTION, 1, "DOWNLOAD / SERVER -> CLIENT (server performs compression)");
    tui_row_style(TUI_STYLE_NORMAL, 1, "O %s | E %s | saved %s | savings %.2f%%", dn_o, dn_e, dn_s, down_pct);
    tui_row_style(TUI_STYLE_NORMAL, 1, "Batches %" PRIu64 " | avg %.1fKiB | compressed %.1f%%",
                  s.batches_sent, down_avg / 1024.0, tx_compressed_pct);
    tui_row_style(TUI_STYLE_NORMAL, 1, "Zstd attempts %" PRIu64 " | small batches skipped %" PRIu64 " | avg compress %.2fms",
                  s.compression_attempts_sent, s.small_batches_skipped_compression, avg_compress_ms);
    tui_border(1);
    char all_o[32], all_e[32], all_s[32];
    format_bytes(total_original, all_o, sizeof(all_o));
    format_bytes(total_encoded, all_e, sizeof(all_e));
    format_bytes(total_saved, all_s, sizeof(all_s));
    tui_row_style(TUI_STYLE_GREEN, 1, "COMBINED: O %s | E %s | saved %s | %.2f%%",
                  all_o, all_e, all_s, saved_pct);
    tui_row_style(TUI_STYLE_SAVED, 1, "Saved-data rate %.2fKiB/s (%.3fMbit/s); payload-only estimate",
                  saved_rate / 1024.0, saved_rate * 8.0 / 1000000.0);
    tui_border(1);
    tui_row_style(TUI_STYLE_BLUE, 1, "PROCESS RESOURCES: CPU %s%.1f%%/one core | RSS %s | peak RSS %s",
                  ru.cpu_valid ? "" : "warming-up ", ru.cpu_percent,
                  ru.memory_valid ? rss : "n/a", ru.memory_valid ? peak : "n/a");
    tui_row_style(TUI_STYLE_NORMAL, 1, "TX batch sizes: <=4K %" PRIu64 " | 4-16K %" PRIu64 " | 16-64K %" PRIu64,
                  s.tx_batch_hist[0], s.tx_batch_hist[1], s.tx_batch_hist[2]);
    tui_row_style(TUI_STYLE_NORMAL, 1, "TX batch sizes: 64-256K %" PRIu64 " | 256K-1M %" PRIu64 " | 1-4M %" PRIu64,
                  s.tx_batch_hist[3], s.tx_batch_hist[4], s.tx_batch_hist[5]);
    if (!compression_enabled) {
        tui_row_style(TUI_STYLE_YELLOW, 1, "DIAGNOSIS: server download compression is OFF; press C to enable Zstd.");
    } else if (down_original < 256u * 1024u || s.batches_sent < 4u) {
        tui_row_style(TUI_STYLE_YELLOW, 1, "DIAGNOSIS: too little download traffic (<256KiB or <4 batches); repeat a steady test.");
    } else if (s.small_batches_skipped_compression > s.batches_sent / 2u) {
        tui_row_style(TUI_STYLE_YELLOW, 1, "DIAGNOSIS: many small batches skip Zstd; lower min-Zstd threshold (T) to try more.");
    } else if (down_pct < 10.0 && down_avg < 64.0 * 1024.0) {
        tui_row_style(TUI_STYLE_YELLOW, 1, "DIAGNOSIS: low savings + avg batch <64KiB; try longer flush, accepting more latency.");
    } else if (down_pct < 10.0) {
        tui_row_style(TUI_STYLE_YELLOW, 1, "DIAGNOSIS: batches are larger but savings stay low; HTTPS/TLS/QUIC data is likely encrypted.");
    } else if (ru.cpu_valid && ru.cpu_percent > 80.0 && avg_compress_ms > 2.0) {
        tui_row_style(TUI_STYLE_YELLOW, 1, "DIAGNOSIS: high CPU + >2ms compression; compare Zstd levels 1/3/5.");
    } else {
        tui_row_style(TUI_STYLE_GREEN, 1, "DIAGNOSIS: no obvious issue in current counters; verify with a repeatable workload.");
    }
    tui_row_style(TUI_STYLE_MUTED, 1, "Savings exclude frame/TCP/IP overhead, retransmissions and physical-NIC bytes.");
    tui_row_style(TUI_STYLE_MUTED, 1, "Auto-tune is a live sequential screen; changing traffic can bias its winner.");
    tui_row_style(TUI_STYLE_HELP, 0, "KEYS: A auto-tune | I diagnose | T min-Zstd | +/- level | [] flush | R reset | D back");
}

static void render_tui(App *app) {
    Stats s = stats_snapshot(app);
    char a[32], b[32], c[32], d[32], e[32], f[32];
    char rx_original[32], rx_encoded[32], rx_saved[32];
    char tx_original[32], tx_encoded[32], tx_saved[32];
    char all_original[32], all_encoded[32], all_saved[32];
    format_bytes(s.client_ip_bytes_in, a, sizeof(a));
    format_bytes(s.client_ip_bytes_out, b, sizeof(b));
    format_bytes(s.transport_bytes_received, c, sizeof(c));
    format_bytes(s.transport_bytes_sent, d, sizeof(d));
    uint64_t raw_total = s.client_ip_bytes_in + s.client_ip_bytes_out;
    uint64_t wire_total = s.transport_bytes_received + s.transport_bytes_sent;
    format_bytes(raw_total, e, sizeof(e));
    format_bytes(wire_total, f, sizeof(f));
    format_bytes(s.payload_original_bytes_received, rx_original, sizeof(rx_original));
    format_bytes(s.payload_encoded_bytes_received, rx_encoded, sizeof(rx_encoded));
    format_bytes(s.payload_saved_bytes_received, rx_saved, sizeof(rx_saved));
    format_bytes(s.payload_original_bytes_sent, tx_original, sizeof(tx_original));
    format_bytes(s.payload_encoded_bytes_sent, tx_encoded, sizeof(tx_encoded));
    format_bytes(s.payload_saved_bytes_sent, tx_saved, sizeof(tx_saved));
    uint64_t payload_original = s.payload_original_bytes_received + s.payload_original_bytes_sent;
    uint64_t payload_encoded = s.payload_encoded_bytes_received + s.payload_encoded_bytes_sent;
    uint64_t payload_saved = s.payload_saved_bytes_received + s.payload_saved_bytes_sent;
    format_bytes(payload_original, all_original, sizeof(all_original));
    format_bytes(payload_encoded, all_encoded, sizeof(all_encoded));
    format_bytes(payload_saved, all_saved, sizeof(all_saved));
    double saved_pct = payload_original ? 100.0 * (double)payload_saved / (double)payload_original : 0.0;

    char last[512];
    int verbose_display, compression_display;
    mutex_lock(&app->log_lock);
    (void)snprintf(last, sizeof(last), "%.511s", app->last_log);
    verbose_display = app->config.verbose;
    compression_display = app->config.compression_enabled;
    mutex_unlock(&app->log_lock);

    int columns, rows;
    terminal_dimensions(&columns, &rows);
    /* Do not let line wrapping or a dashboard taller than the terminal scroll the screen. */
    if (columns < 80 || rows < 16) {
        tui_small_message(columns, rows);
        return;
    }
    printf("\033[2J\033[H");
    mutex_lock(&app->log_lock);
    int help_visible = app->help_visible;
    mutex_unlock(&app->log_lock);
    if (help_visible) {
        render_tui_help(rows);
        fflush(stdout);
        return;
    }
    int page;
    mutex_lock(&app->log_lock);
    page = app->tui_page;
    mutex_unlock(&app->log_lock);
    if (page == 1) {
        render_tui_ban_manager(app, rows);
        fflush(stdout);
        return;
    }
    if (page == 2) {
        render_tui_benchmark(app);
        fflush(stdout);
        return;
    }
    if (rows < 32) {
        render_tui_compact(app, s, compression_display, verbose_display,
                           raw_total, wire_total, saved_pct, rows);
        fflush(stdout);
        return;
    }

    tui_border(1);
    tui_row_style(TUI_STYLE_TITLE, 1, "ZVPN SERVER  |  ZVPN v1  |  Zstd %s  |  %s",
                  ZSTD_versionString(), app_running() ? "RUNNING" : "STOPPING");
    tui_row_style(TUI_STYLE_NORMAL, 1, "Listen: %-20.20s:%-5d   TUN: %-30.30s",
                  app->config.bind_address, app->config.port, app->tun.name);
    tui_row_style(TUI_STYLE_BLUE, 1, "Client sessions: %zu/%u | return traffic routes by VPN IPv4",
                  active_client_count(app), (unsigned)ZVPN_MAX_CLIENTS);
    tui_row_style(TUI_STYLE_MUTED, 1, "Last log: %s", last);
    tui_border(1);
    tui_row_style(TUI_STYLE_SECTION, 1, "%-27s | %-15s | %-19s",
                  "TRAFFIC DIRECTION", "IP PACKET BYTES", "TCP TRANSPORT BYTES");
    tui_row_style(TUI_STYLE_NORMAL, 1, "%-27s | %15s | %19s", "Client -> server TUN", a, c);
    tui_row_style(TUI_STYLE_NORMAL, 1, "%-27s | %15s | %19s", "Server TUN -> client", b, d);
    tui_row_style(TUI_STYLE_GREEN, 1, "%-27s | %15s | %19s", "Combined", e, f);
    tui_border(1);
    tui_row_style(TUI_STYLE_SECTION, 1, "COMPRESSION SAVINGS  |  %.2f%% overall | frame/TCP/IP headers excluded", saved_pct);
    tui_row_style(TUI_STYLE_SECTION, 1, "%-21s | %14s | %15s | %12s",
                  "Direction", "Original bytes", "Encoded payload", "Saved");
    tui_row_style(TUI_STYLE_NORMAL, 1, "%-21s | %14s | %15s | %12s",
                  "Client -> server", rx_original, rx_encoded, rx_saved);
    tui_row_style(TUI_STYLE_NORMAL, 1, "%-21s | %14s | %15s | %12s",
                  "Server -> client", tx_original, tx_encoded, tx_saved);
    tui_row_style(TUI_STYLE_GREEN, 1, "%-21s | %14s | %15s | %12s",
                  "Combined", all_original, all_encoded, all_saved);
    tui_row_style(TUI_STYLE_SAVED, 1, "Exact O/E/S: %" PRIu64 "/%" PRIu64 "/%" PRIu64,
                  payload_original, payload_encoded, payload_saved);
    tui_border(1);
    tui_row_style(TUI_STYLE_BLUE, 1,
                  "Batches RX/TX: %-8" PRIu64 "/%-8" PRIu64 "  compressed RX/TX: %-8" PRIu64 "/%-8" PRIu64,
                  s.batches_received, s.batches_sent,
                  s.compressed_batches_received, s.compressed_batches_sent);
    tui_row_style(TUI_STYLE_NORMAL, 1,
                  "Packets RX/TX: %-8" PRIu64 "/%-8" PRIu64 "  rejected: %-8" PRIu64,
                  s.packets_received_from_client, s.packets_sent_to_client, s.rejected_packets);
    RuntimeSettings dashboard_cfg = runtime_settings_snapshot(app);
    tui_row_style(TUI_STYLE_MUTED, 1,
                  "Config: level=%-2d compression=%-3s target=%-8zu min-Zstd=%-7zu wait=%-5dms flush=%-5dms",
                  dashboard_cfg.compression_level, compression_display ? "on" : "off",
                  dashboard_cfg.out_batch_target_bytes, dashboard_cfg.min_compress_batch_bytes,
                  dashboard_cfg.min_batch_wait_ms, dashboard_cfg.flush_timeout_ms);
    ResourceUsage ru = resource_usage_snapshot(app);
    char rss_text[32], peak_text[32];
    format_bytes(ru.rss_bytes, rss_text, sizeof(rss_text));
    format_bytes(ru.peak_rss_bytes, peak_text, sizeof(peak_text));
    tui_row_style(TUI_STYLE_BLUE, 1, "Process resources: CPU %s%.1f%% | RSS %s | peak RSS %s",
                  ru.cpu_valid ? "" : "warming-up ", ru.cpu_percent,
                  ru.memory_valid ? rss_text : "n/a", ru.memory_valid ? peak_text : "n/a");
    tui_border(1);
    tui_row_style(TUI_STYLE_SECTION, 1, "CLIENT MONITOR  |  recent peer IPs (each client must use a unique VPN IPv4)");
    tui_row_style(TUI_STYLE_MUTED, 1, "IP                 | State | DL original/saved       | UL original/saved");
    ClientStats client_rows[ZVPN_CLIENT_HISTORY];
    size_t client_count = client_stats_snapshot(app, client_rows);
    if (client_count == 0) {
        tui_row_style(TUI_STYLE_NORMAL, 1, "No client sessions yet.");
    } else {
        size_t shown = client_count < ZVPN_TUI_CLIENT_ROWS ? client_count : ZVPN_TUI_CLIENT_ROWS;
        for (size_t i = 0; i < shown; ++i) {
            char dl_original[32], dl_saved[32], ul_original[32], ul_saved[32];
            format_bytes(client_rows[i].download_original, dl_original, sizeof(dl_original));
            format_bytes(client_rows[i].download_saved, dl_saved, sizeof(dl_saved));
            format_bytes(client_rows[i].upload_original, ul_original, sizeof(ul_original));
            format_bytes(client_rows[i].upload_saved, ul_saved, sizeof(ul_saved));
            tui_row_style(client_rows[i].active ? TUI_STYLE_GREEN : TUI_STYLE_NORMAL, 1,
                "%-18.18s | %-5s | DL %9s/%9s | UL %9s/%9s",
                client_rows[i].ip, client_rows[i].active ? "LIVE" : "idle",
                dl_original, dl_saved, ul_original, ul_saved);
        }
    }
#if defined(__linux__) || defined(_WIN32)
    tui_row_style(TUI_STYLE_BLUE, 1, "Network: IPv4 auto-config %s | IPv6 forwarding/NAT disabled | log: %s",
                  app->config.auto_network ? "ON" : "OFF",
                  app->config.log_file_path[0] ? app->config.log_file_path : "console");
#else
    tui_row_style(TUI_STYLE_BLUE, 1, "Network: OS forwarding/NAT configured separately | log: %s",
                  app->config.log_file_path[0] ? app->config.log_file_path : "console");
#endif
    tui_row_style(TUI_STYLE_HELP, 1, "KEYS: [Q] quit [B] bans [M] benchmark [A] auto-tune [I] diagnose [T] min-Zstd [S] stats [V] verbose [C] compression [R] reset [H] help");
    tui_border(0); /* Final row intentionally has no newline: avoids scrolling at terminal bottom. */
    fflush(stdout);
}
static int tui_current_page(App *app) {
    mutex_lock(&app->log_lock);
    int page = app->tui_page;
    mutex_unlock(&app->log_lock);
    return page;
}

static void handle_console_key(App *app, int ch) {
    int page = tui_current_page(app);
    if (ch == 'q' || ch == 'Q') {
        log_message(app, LOG_INFO, "[CLI] shutdown requested by keyboard");
        app_stop_signal();
        return;
    }
    mutex_lock(&app->log_lock);
    int auto_is_active = app->auto_benchmark_active;
    mutex_unlock(&app->log_lock);
    if (auto_is_active && (ch == 'c' || ch == 'C' || ch == 'r' || ch == 'R' ||
        ch == 't' || ch == 'T' || ch == '+' || ch == '=' || ch == '-' ||
        ch == '[' || ch == ']' || ch == 'v' || ch == 'V')) {
        log_message(app, LOG_WARN, "[AUTO] configuration/reset keys are disabled while automatic benchmarking is running");
        return;
    }
    if (ch == 'd' || ch == 'D') {
        mutex_lock(&app->log_lock); app->tui_page = 0; app->help_visible = 0; mutex_unlock(&app->log_lock);
        return;
    }
    if (ch == 'b' || ch == 'B') {
        mutex_lock(&app->log_lock); app->tui_page = 1; app->ban_list_view = 0; app->ban_list_offset = 0; app->help_visible = 0; mutex_unlock(&app->log_lock);
        return;
    }
    if (ch == 'm' || ch == 'M' || ch == 'e' || ch == 'E') {
        mutex_lock(&app->log_lock); app->tui_page = 2; app->help_visible = 0; mutex_unlock(&app->log_lock);
        return;
    }
    if (page == 1 && ch >= '1' && ch <= '8') {
        size_t selected = (size_t)(ch - '1');
        int list_view;
        size_t offset;
        mutex_lock(&app->log_lock); list_view = app->ban_list_view; offset = app->ban_list_offset; mutex_unlock(&app->log_lock);
        if (!list_view) {
            ClientStats rows[ZVPN_CLIENT_HISTORY];
            size_t count = client_stats_snapshot(app, rows);
            if (offset + selected < count) toggle_client_ban(app, rows[offset + selected].ip);
            else log_message(app, LOG_INFO, "[ACCESS] No client row %zu to select", selected + 1);
        } else {
            char bans[ZVPN_MAX_BANNED][INET6_ADDRSTRLEN];
            size_t count = banned_ips_snapshot(app, bans);
            if (offset + selected < count) toggle_client_ban(app, bans[offset + selected]);
            else log_message(app, LOG_INFO, "[ACCESS] No banned-IP row %zu on this page", selected + 1);
        }
        return;
    }
    if (page == 1 && (ch == 'n' || ch == 'N')) {
        mutex_lock(&app->log_lock);
        app->ban_list_view = !app->ban_list_view;
        app->ban_list_offset = 0;
        mutex_unlock(&app->log_lock);
        return;
    }
    if (page == 1 && (ch == 'u' || ch == 'U')) { clear_all_bans(app); return; }
    if (page == 1 && (ch == ']')) {
        size_t count;
        int list_view;
        mutex_lock(&app->log_lock); list_view = app->ban_list_view; mutex_unlock(&app->log_lock);
        if (list_view) {
            char bans[ZVPN_MAX_BANNED][INET6_ADDRSTRLEN];
            count = banned_ips_snapshot(app, bans);
        } else {
            ClientStats rows[ZVPN_CLIENT_HISTORY];
            count = client_stats_snapshot(app, rows);
        }
        mutex_lock(&app->log_lock);
        if (app->ban_list_offset + ZVPN_TUI_CLIENT_ROWS < count) app->ban_list_offset += ZVPN_TUI_CLIENT_ROWS;
        mutex_unlock(&app->log_lock);
        return;
    }
    if (page == 1 && (ch == '[')) {
        mutex_lock(&app->log_lock);
        if (app->ban_list_offset >= ZVPN_TUI_CLIENT_ROWS) app->ban_list_offset -= ZVPN_TUI_CLIENT_ROWS;
        else app->ban_list_offset = 0;
        mutex_unlock(&app->log_lock);
        return;
    }
    if (ch == 'a' || ch == 'A') {
        mutex_lock(&app->log_lock); int seconds = app->config.auto_benchmark_seconds; mutex_unlock(&app->log_lock);
        start_auto_benchmark(app, seconds > 0 ? seconds : 120); return;
    }
    if (ch == 'i' || ch == 'I') { log_diagnostics(app); return; }
    if (ch == 't' || ch == 'T') {
        static const size_t thresholds[] = {0, 4u * 1024u, 16u * 1024u, 64u * 1024u, 256u * 1024u};
        mutex_lock(&app->log_lock);
        size_t current = app->config.min_compress_batch_bytes;
        size_t next = 0;
        for (size_t i = 0; i < sizeof(thresholds)/sizeof(thresholds[0]); ++i) {
            if (thresholds[i] > current && thresholds[i] <= app->config.max_batch_bytes) { next = thresholds[i]; break; }
        }
        app->config.min_compress_batch_bytes = next;
        mutex_unlock(&app->log_lock);
        log_message(app, LOG_INFO, "[CLI] minimum Zstd batch threshold is now %zu bytes (smaller batches go raw)", next); return;
    }
    if (ch == '+' || ch == '=') {
        mutex_lock(&app->log_lock);
        if (app->config.compression_level < ZSTD_maxCLevel()) app->config.compression_level++;
        int level_now = app->config.compression_level;
        mutex_unlock(&app->log_lock);
        log_message(app, LOG_INFO, "[CLI] server-to-client Zstd level is now %d", level_now); return;
    }
    if (ch == '-') {
        mutex_lock(&app->log_lock);
        if (app->config.compression_level > 1) app->config.compression_level--;
        int level_now = app->config.compression_level;
        mutex_unlock(&app->log_lock);
        log_message(app, LOG_INFO, "[CLI] server-to-client Zstd level is now %d", level_now); return;
    }
    if (ch == '[' || ch == ']') {
        mutex_lock(&app->clients_lock);
        if (ch == '[') app->config.flush_timeout_ms = app->config.flush_timeout_ms > 25 ? app->config.flush_timeout_ms - 25 : 0;
        else if (app->config.flush_timeout_ms < 59975) app->config.flush_timeout_ms += 25;
        int flush_now = app->config.flush_timeout_ms;
        mutex_unlock(&app->clients_lock);
        log_message(app, LOG_INFO, "[CLI] download flush timeout is now %d ms", flush_now); return;
    }
    if (ch == 's' || ch == 'S') { log_stats_snapshot(app, "[STATS] live snapshot"); log_diagnostics(app); return; }
    if (ch == 'v' || ch == 'V') {
        mutex_lock(&app->log_lock); app->config.verbose = !app->config.verbose; int enabled = app->config.verbose; mutex_unlock(&app->log_lock);
        log_message(app, LOG_INFO, "[CLI] verbose logging %s", enabled ? "ENABLED" : "DISABLED"); return;
    }
    if (ch == 'c' || ch == 'C') {
        mutex_lock(&app->log_lock); app->config.compression_enabled = !app->config.compression_enabled; int enabled = app->config.compression_enabled; mutex_unlock(&app->log_lock);
        log_message(app, LOG_INFO, "[CLI] server-to-client Zstandard compression %s", enabled ? "ENABLED" : "DISABLED"); return;
    }
    if (ch == 'r' || ch == 'R') {
        mutex_lock(&app->stats.lock); memset(&app->stats.stats, 0, sizeof(app->stats.stats)); mutex_unlock(&app->stats.lock);
        client_stats_reset(app);
        mutex_lock(&app->log_lock); /* reset the benchmark average-rate time origin */
        app->started_ms = monotonic_ms();
        mutex_unlock(&app->log_lock);
        log_message(app, LOG_INFO, "[CLI] traffic counters reset; benchmark time restarted"); return;
    }
    if (ch == 'h' || ch == 'H' || ch == '?') {
        mutex_lock(&app->log_lock); app->help_visible = !app->help_visible; int shown = app->help_visible; mutex_unlock(&app->log_lock);
        log_message(app, LOG_INFO, "[CLI] TUI help %s (press H or ? to return)", shown ? "opened" : "closed"); return;
    }
    if (ch == '\r' || ch == '\n' || ch == 0) return;
    log_message(app, LOG_INFO, "[CLI] unknown key '%c'; press H for help", (ch >= 32 && ch <= 126) ? ch : '?');
}

THREAD_ENTRY(command_worker) {
    App *app = (App *)opaque;
    log_message(app, LOG_INFO, "[CLI] interactive controls ready (H for help)");
    while (app_running()) {
#ifdef _WIN32
        if (_kbhit()) {
            int ch = _getch();
            if (ch == 0 || ch == 224) { (void)_getch(); continue; }
            handle_console_key(app, ch);
        } else {
            sleep_ms(40);
        }
#else
        struct pollfd pfd;
        pfd.fd = STDIN_FILENO;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int rc;
        do { rc = poll(&pfd, 1, 100); } while (rc < 0 && errno == EINTR && app_running());
        if (rc > 0 && (pfd.revents & POLLIN)) {
            unsigned char ch;
            ssize_t n = read(STDIN_FILENO, &ch, 1);
            if (n == 1) handle_console_key(app, ch);
        } else if (rc < 0 && app_running()) {
            log_message(app, LOG_WARN, "[CLI] input poll failed: %s", strerror(errno));
            break;
        }
#endif
    }
    THREAD_DONE;
}

THREAD_ENTRY(tui_worker) {
    App *app = (App *)opaque;
#ifdef _WIN32
    HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD original_mode = 0;
    int restore_console_mode = 0;
    if (hout != INVALID_HANDLE_VALUE && GetConsoleMode(hout, &original_mode)) {
        if (SetConsoleMode(hout, original_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
            restore_console_mode = 1;
    }
#endif
    /* Alternate screen keeps dashboard redraws out of the scrollback buffer. */
    fputs("\033[?1049h\033[?25l\033[2J\033[H", stdout);
    fflush(stdout);
    while (app_running()) {
        render_tui(app);
        sleep_ms(500);
    }
    render_tui(app);
    fputs("\033[0m\033[?25h\033[?1049l", stdout);
    fflush(stdout);
#ifdef _WIN32
    if (restore_console_mode && hout != INVALID_HANDLE_VALUE)
        (void)SetConsoleMode(hout, original_mode);
#endif
    THREAD_DONE;
}

static int initialize_networking(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return -1;
#endif
    return 0;
}

static void cleanup_networking(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

int main(int argc, char **argv) {
    App app;
    memset(&app, 0, sizeof(app));
    app.listener = INVALID_SOCK;
#ifdef _WIN32
    app.tun.module = NULL;
    app.tun.adapter = NULL;
    app.tun.session = NULL;
#else
    app.tun.fd = -1;
#endif
    config_defaults(&app.config);
    if (parse_args(argc, argv, &app.config) < 0) {
        print_usage(stderr, argv[0]);
        return 2;
    }

    mutex_init(&app.log_lock);
    mutex_init(&app.stats.lock);
    mutex_init(&app.client_stats.lock);
    mutex_init(&app.clients_lock);
    mutex_init(&app.bans_lock);
    app.help_visible = 0;
    app.tui_enabled = app.config.tui;
#ifdef _WIN32
    if (app.tui_enabled && (!_isatty(_fileno(stdin)) || !_isatty(_fileno(stdout)))) {
        app.tui_enabled = 0;
        app.config.tui = 0;
        fprintf(stderr, "[INFO] No interactive console detected; using plain logs.\n");
    }
#else
    if (app.tui_enabled && (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))) {
        app.tui_enabled = 0;
        app.config.tui = 0;
        fprintf(stderr, "[INFO] No interactive terminal detected; using plain logs.\n");
    }
#endif
    (void)snprintf(app.last_log, sizeof(app.last_log), "initializing");

    if (app.config.log_file_path[0] && strcmp(app.config.log_file_path, "none") != 0) {
        app.log_file = fopen(app.config.log_file_path, "ab");
        if (!app.log_file) {
            fprintf(stderr, "Cannot open log file '%s': %s\n",
                    app.config.log_file_path, strerror(errno));
            mutex_destroy(&app.bans_lock);
            mutex_destroy(&app.clients_lock);
            mutex_destroy(&app.client_stats.lock);
            mutex_destroy(&app.stats.lock);
            mutex_destroy(&app.log_lock);
            return 2;
        }
    }

    if (initialize_networking() < 0) {
        log_message(&app, LOG_ERROR, "Network initialization failed");
        if (app.log_file) fclose(app.log_file);
        mutex_destroy(&app.bans_lock);
        mutex_destroy(&app.clients_lock);
        mutex_destroy(&app.client_stats.lock);
        mutex_destroy(&app.stats.lock);
        mutex_destroy(&app.log_lock);
        return 2;
    }
    /* inet_pton on Windows requires Winsock to be initialized first. */
    if (!app.config.allow_any_client &&
        !is_numeric_ip_address(app.config.allowed_client)) {
        log_message(&app, LOG_ERROR,
            "Invalid --allow-client address '%s': use numeric IPv4 or IPv6",
            app.config.allowed_client);
        cleanup_networking();
        if (app.log_file) fclose(app.log_file);
        mutex_destroy(&app.bans_lock);
        mutex_destroy(&app.clients_lock);
        mutex_destroy(&app.client_stats.lock);
        mutex_destroy(&app.stats.lock);
        mutex_destroy(&app.log_lock);
        return 2;
    }

#ifdef _WIN32
    (void)SetConsoleCtrlHandler(console_control_handler, TRUE);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGINT, &sa, NULL);
    (void)sigaction(SIGTERM, &sa, NULL);
    /* macOS has no MSG_NOSIGNAL; a closed client must not kill the process. */
    (void)signal(SIGPIPE, SIG_IGN);
#endif
    log_message(&app, LOG_INFO,
                "Starting ZVPN server: bind=%s port=%d batch-ceiling=%zu download-target=%zu min-Zstd=%zu min-wait=%dms flush=%dms zstd-level=%d compression=%s auto-network=%s mtu=%d",
                app.config.bind_address, app.config.port, app.config.max_batch_bytes,
                app.config.out_batch_target_bytes, app.config.min_compress_batch_bytes,
                app.config.min_batch_wait_ms, app.config.flush_timeout_ms, app.config.compression_level,
                app.config.compression_enabled ? "on" : "off",
                app.config.auto_network ? "on" : "off", app.config.mtu);

    if (tun_open(&app) < 0) {
        log_message(&app, LOG_ERROR, "Could not initialize TUN interface; see platform setup in README.md");
        cleanup_networking();
        if (app.log_file) fclose(app.log_file);
        mutex_destroy(&app.bans_lock);
        mutex_destroy(&app.clients_lock);
        mutex_destroy(&app.client_stats.lock);
        mutex_destroy(&app.stats.lock);
        mutex_destroy(&app.log_lock);
        return 1;
    }

    if (platform_network_setup(&app) < 0) {
        log_message(&app, LOG_ERROR, "Automatic network setup failed; server will not accept connections with a broken return path");
        platform_network_cleanup(&app);
        tun_close(&app);
        cleanup_networking();
        if (app.log_file) fclose(app.log_file);
        mutex_destroy(&app.bans_lock);
        mutex_destroy(&app.clients_lock);
        mutex_destroy(&app.client_stats.lock);
        mutex_destroy(&app.stats.lock);
        mutex_destroy(&app.log_lock);
        return 1;
    }

    app.listener = create_listener(&app);
    if (app.listener == INVALID_SOCK) {
        platform_network_cleanup(&app);
        tun_close(&app);
        cleanup_networking();
        if (app.log_file) fclose(app.log_file);
        mutex_destroy(&app.bans_lock);
        mutex_destroy(&app.clients_lock);
        mutex_destroy(&app.client_stats.lock);
        mutex_destroy(&app.stats.lock);
        mutex_destroy(&app.log_lock);
        return 1;
    }

    app.started_ms = monotonic_ms();
    log_message(&app, LOG_INFO, "Listening on %s:%d; TUN='%s'", app.config.bind_address,
                app.config.port, app.tun.name);
#ifdef __linux__
    if (app.config.auto_network)
        log_message(&app, LOG_INFO, "[ROUTE] Linux IPv4 forwarding/NAT/firewall are managed by this process; IPv6 forwarding/NAT is disabled");
    else
        log_message(&app, LOG_WARN, "[ROUTE] Automatic networking is disabled; TUN address, forwarding, routes, firewall, and NAT must be configured separately");
#elif defined(_WIN32)
    if (app.config.auto_network)
        log_message(&app, LOG_INFO, "[ROUTE] Windows IPv4 forwarding/NAT/firewall are managed by this process (WinNAT may conflict with an existing NAT)");
    else
        log_message(&app, LOG_WARN, "[ROUTE] Windows auto-network is disabled; Wintun routing/NAT/firewall must be configured separately");
#else
    log_message(&app, LOG_WARN, "[ROUTE] macOS forwarding/NAT/firewall are not configured by this build; configure utun networking separately");
#endif
    log_message(&app, LOG_WARN, "[SECURITY] ZVPN v1 has no authentication/encryption; bind to a trusted interface or protect it with an authenticated secure transport.");

    thread_t tun_reader_thread;
    if (thread_start(&tun_reader_thread, tun_to_clients_worker, &app) != 0) {
        log_message(&app, LOG_ERROR, "Could not start shared TUN reader thread; cannot route multiple clients safely");
        socket_close(app.listener);
        app.listener = INVALID_SOCK;
        platform_network_cleanup(&app);
        tun_close(&app);
        cleanup_networking();
        if (app.log_file) fclose(app.log_file);
        mutex_destroy(&app.bans_lock);
        mutex_destroy(&app.clients_lock);
        mutex_destroy(&app.client_stats.lock);
        mutex_destroy(&app.stats.lock);
        mutex_destroy(&app.log_lock);
        return 1;
    }


    thread_t ui_thread;
    thread_t input_thread;
    int ui_started = 0;
    int input_started = 0;
    int interactive_input_supported = 1;
#ifndef _WIN32
    struct termios saved_stdin_termios;
    int terminal_raw_enabled = 0;
    if (app.tui_enabled) {
        if (tcgetattr(STDIN_FILENO, &saved_stdin_termios) == 0) {
            struct termios raw = saved_stdin_termios;
            raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);
            raw.c_cc[VMIN] = 0;
            raw.c_cc[VTIME] = 0;
            if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0)
                terminal_raw_enabled = 1;
        }
        if (!terminal_raw_enabled) {
            interactive_input_supported = 0;
            log_message(&app, LOG_WARN,
                "[CLI] Could not enable raw terminal input; keyboard commands are unavailable (Ctrl+C still works)");
        }
    }
#endif
    if (app.tui_enabled) {
        if (thread_start(&ui_thread, tui_worker, &app) == 0) ui_started = 1;
        else {
            app.tui_enabled = 0;
            app.config.tui = 0;
#ifndef _WIN32
            if (terminal_raw_enabled) {
                (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved_stdin_termios);
                terminal_raw_enabled = 0;
            }
#endif
            log_message(&app, LOG_WARN, "Could not start TUI thread; switching to plain logs");
        }
    }
    if (app.tui_enabled && interactive_input_supported) {
        if (thread_start(&input_thread, command_worker, &app) == 0) input_started = 1;
        else {
#ifndef _WIN32
            if (terminal_raw_enabled) {
                (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved_stdin_termios);
                terminal_raw_enabled = 0;
            }
#endif
            log_message(&app, LOG_WARN, "Could not start interactive input worker; use Ctrl+C to stop");
        }
    }


    if (app.config.auto_benchmark_seconds > 0)
        start_auto_benchmark(&app, app.config.auto_benchmark_seconds);

    while (app_running()) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(app.listener, &rfds);
        struct timeval tv = {0, 250000};
#ifdef _WIN32
        int ready = select(0, &rfds, NULL, NULL, &tv);
#else
        int ready = select(app.listener + 1, &rfds, NULL, NULL, &tv);
#endif
        if (ready < 0) {
#ifdef _WIN32
            int e = WSAGetLastError();
            if (socket_interrupted(e)) continue;
            if (!app_running()) break;
            log_message(&app, LOG_ERROR, "Listener select error=%d", e);
#else
            if (errno == EINTR) continue;
            if (!app_running()) break;
            log_message(&app, LOG_ERROR, "Listener select failed: %s", strerror(errno));
#endif
            break;
        }
        if (ready == 0) continue;

        struct sockaddr_storage peer_addr;
#ifdef _WIN32
        int peer_len = sizeof(peer_addr);
#else
        socklen_t peer_len = sizeof(peer_addr);
#endif
        socket_t client_socket = accept(app.listener, (struct sockaddr *)&peer_addr, &peer_len);
        if (client_socket == INVALID_SOCK) {
#ifdef _WIN32
            int e = WSAGetLastError();
            if (!app_running()) break;
            log_message(&app, LOG_WARN, "accept failed: WSA error=%d", e);
#else
            if (errno == EINTR) continue;
            if (!app_running()) break;
            log_message(&app, LOG_WARN, "accept failed: %s", strerror(errno));
#endif
            continue;
        }

        char peer[INET6_ADDRSTRLEN];
        char endpoint[128];
        (void)get_peer_name((struct sockaddr *)&peer_addr, peer, sizeof(peer));
        (void)get_peer_endpoint((struct sockaddr *)&peer_addr, endpoint, sizeof(endpoint));
        if (!app.config.allow_any_client && !peer_address_matches(peer, app.config.allowed_client)) {
            log_message(&app, LOG_WARN, "Rejected client %s (does not match --allow-client %s)", peer,
                        app.config.allowed_client);
            socket_close(client_socket);
            continue;
        }
        if (client_ip_is_banned(&app, peer)) {
            log_message(&app, LOG_WARN, "Rejected banned peer %s (%s)", peer, endpoint);
            socket_close(client_socket);
            continue;
        }

        int one = 1;
#ifdef _WIN32
        if (setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one)) != 0)
            log_message(&app, LOG_DEBUG, "[NET] TCP_NODELAY could not be enabled (WSA error=%d)", WSAGetLastError());
#else
        if (setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0)
            log_message(&app, LOG_DEBUG, "[NET] TCP_NODELAY could not be enabled: %s", strerror(errno));
#endif

        Client *client = (Client *)calloc(1, sizeof(*client));
        if (!client) {
            log_message(&app, LOG_ERROR, "Cannot allocate client session for %s", peer);
            socket_close(client_socket);
            continue;
        }
        client->out_batch = (uint8_t *)malloc(app.config.max_batch_bytes);
        if (!client->out_batch) {
            log_message(&app, LOG_ERROR, "Cannot allocate %zu-byte batch buffer for client %s",
                        app.config.max_batch_bytes, peer);
            socket_close(client_socket);
            free(client);
            continue;
        }
        client->app = &app;
        client->socket = client_socket;
        (void)snprintf(client->peer, sizeof(client->peer), "%s", peer);
        (void)snprintf(client->endpoint, sizeof(client->endpoint), "%s", endpoint);
#ifdef _WIN32
        client->stop = 0;
#else
        atomic_init(&client->stop, 0);
#endif
        client->stats_record = client_stats_begin(&app, peer, endpoint);

        int registered = 0;
        mutex_lock(&app.clients_lock);
        if (app.client_count < ZVPN_MAX_CLIENTS) {
            for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i) {
                if (!app.clients[i]) {
                    app.clients[i] = client;
                    app.client_count++;
                    registered = 1;
                    break;
                }
            }
        }
        mutex_unlock(&app.clients_lock);
        if (!registered) {
            log_message(&app, LOG_WARN, "Maximum concurrent clients (%u) reached; rejected %s",
                        (unsigned)ZVPN_MAX_CLIENTS, endpoint);
            if (client->stats_record) client_stats_end(&app, client->stats_record);
            socket_close(client_socket);
            free(client->out_batch);
            free(client);
            continue;
        }

        thread_t client_thread;
        int thread_rc = thread_start(&client_thread, client_worker, client);
        if (thread_rc != 0) {
            log_message(&app, LOG_ERROR, "Could not start client thread for %s (thread error=%d)", endpoint, thread_rc);
            mutex_lock(&app.clients_lock);
            for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i) {
                if (app.clients[i] == client) {
                    app.clients[i] = NULL;
                    if (app.client_count) app.client_count--;
                    break;
                }
            }
            mutex_unlock(&app.clients_lock);
            if (client->stats_record) client_stats_end(&app, client->stats_record);
            socket_close(client_socket);
            free(client->out_batch);
            free(client);
            continue;
        }
        thread_detach(client_thread);
        log_message(&app, LOG_INFO, "Accepted concurrent client %s (%zu/%u connected)",
                    endpoint, active_client_count(&app), (unsigned)ZVPN_MAX_CLIENTS);
    }

    app_stop_signal();
    if (app.listener != INVALID_SOCK) {
        socket_close(app.listener);
        app.listener = INVALID_SOCK;
    }
    /* Wake all receive loops before waiting for their detached handlers to clean up. */
    mutex_lock(&app.clients_lock);
    for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i)
        if (app.clients[i]) client_request_stop(app.clients[i]);
    mutex_unlock(&app.clients_lock);
    thread_join(tun_reader_thread);
    for (;;) {
        mutex_lock(&app.clients_lock);
        size_t remaining_clients = app.client_count;
        for (size_t i = 0; i < ZVPN_MAX_CLIENTS; ++i)
            if (app.clients[i]) client_request_stop(app.clients[i]);
        mutex_unlock(&app.clients_lock);
        if (!remaining_clients) break;
        sleep_ms(25);
    }
    if (input_started) thread_join(input_thread);
    /* Joining after the input worker prevents a late A-key request from racing
     * with shutdown and creating an unjoined benchmark thread. */
    if (app.auto_benchmark_thread_started) thread_join(app.auto_benchmark_thread);
    if (ui_started) thread_join(ui_thread);
#ifndef _WIN32
    if (terminal_raw_enabled)
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved_stdin_termios);
#endif
    platform_network_cleanup(&app);
    tun_close(&app);
    cleanup_networking();
    log_message(&app, LOG_INFO, "Server stopped");
    if (app.log_file) fclose(app.log_file);
    mutex_destroy(&app.bans_lock);
    mutex_destroy(&app.clients_lock);
    mutex_destroy(&app.client_stats.lock);
    mutex_destroy(&app.stats.lock);
    mutex_destroy(&app.log_lock);
    return 0;
}
