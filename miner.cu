// UNICRED hash engine. One binary, two builds:
//   GPU: nvcc -O3 -std=c++17 -arch=native -o miner miner.cu -lpthread  (every visible NVIDIA GPU, one host thread each)
//   CPU: clang++ -O3 -std=c++17 -x c++ -o miner_cpu miner.cu -lpthread  (same protocol, for local tests)
//
// Line protocol (stdin -> engine):
//   JOB <jobId> <hex of msg bytes 0..183> <thr64 hex>   start grinding; msg = abi.encode(DOMAIN, chainId, contract,
//                                                        challenge, miner, nonce) minus the nonce's low 8 bytes
//   THR <jobId> <thr64 hex>                              new candidate threshold for that job
//   IDLE                                                 stop grinding, keep running
//   QUIT (or EOF)                                        exit
// Engine -> stdout (one line each, flushed):
//   READY <n> <name|name...>   SELFTEST OK|FAIL ...   HIT <jobId> <nonceLow64> <top64>   RATE <total> <per-device...>   ERR ...
// A HIT means the digest's top 64 bits are below the threshold; the caller verifies the full 256-bit digest.
#include "keccak_core.h"

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#ifdef __CUDACC__
#include <cuda_runtime.h>
#define ENGINE_GPU 1
#else
#define ENGINE_GPU 0
#endif

#define HIT_CAP 64
#define MAX_DEV 64

static std::mutex g_out_mu;
static void emit(const char *fmt, ...) {
  std::lock_guard<std::mutex> lk(g_out_mu);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);
  fputc('\n', stdout);
  fflush(stdout);
}

struct Job {
  uint64_t gen = 0;
  bool active = false;
  uint32_t id = 0;
  uint64_t base[25] = {0};
};
static std::mutex g_job_mu;
static Job g_job;
static std::atomic<uint64_t> g_gen{0};
static std::atomic<uint64_t> g_thr{0};
static std::atomic<bool> g_quit{false};
static std::atomic<uint64_t> g_dev_hashes[MAX_DEV];
static int g_ndev = 0;

static uint64_t now_ns() {
  return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch()).count();
}
static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  c |= 32;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}
static bool parse_hex_bytes(const char *h, uint8_t *out, size_t n) {
  if (h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) h += 2;
  if (strlen(h) < 2 * n) return false;
  for (size_t i = 0; i < n; i++) {
    int a = hexval(h[2 * i]), b = hexval(h[2 * i + 1]);
    if (a < 0 || b < 0) return false;
    out[i] = (uint8_t)(a << 4 | b);
  }
  return true;
}
static Job snapshot_job() {
  std::lock_guard<std::mutex> lk(g_job_mu);
  return g_job;
}
static uint64_t seed_mix(uint64_t salt) {
  std::random_device rd;
  uint64_t s = ((uint64_t)rd() << 32) ^ rd() ^ now_ns() ^ (salt * 0x9E3779B97F4A7C15ULL);
  return s;
}

#if ENGINE_GPU
// ------------------------------------------------------------------ GPU
struct KParams {
  uint64_t base[25];
  uint64_t thr;
  uint64_t start;
  uint32_t iters;
};

__global__ void __launch_bounds__(256) k_mine(const KParams p, unsigned int *cnt, unsigned long long *hn,
                                              unsigned long long *ht) {
  const uint64_t tid = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
  const uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
  uint64_t nonce = p.start + tid;
  for (uint32_t it = 0; it < p.iters; it++, nonce += stride) {
    KECCAK_VARS;
    KECCAK_LOAD(p.base);
    a6 ^= kbswap64(nonce);
    KECCAK_F_VARS();
    const uint64_t top = kbswap64(a0);
    if (top < p.thr) {
      unsigned int k = atomicAdd(cnt, 1u);
      if (k < HIT_CAP) {
        hn[k] = (unsigned long long)nonce;
        ht[k] = (unsigned long long)top;
      }
    }
  }
}

#define CK(x)                                                                                   \
  do {                                                                                          \
    cudaError_t e_ = (x);                                                                       \
    if (e_ != cudaSuccess) {                                                                    \
      emit("ERR dev %d %s: %s (line %d)", dev, #x, cudaGetErrorString(e_), __LINE__);           \
      return false;                                                                             \
    }                                                                                           \
  } while (0)

struct Dev {
  int dev = 0;
  int grid = 0;
  unsigned int *d_cnt = nullptr;
  unsigned long long *d_hn = nullptr, *d_ht = nullptr;
  char name[256] = {0};
};
static Dev g_devs[MAX_DEV];

static bool dev_init(Dev &d) {
  int dev = d.dev;
  CK(cudaSetDevice(dev));
  cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);  // don't spin a CPU core per GPU; ignore if the context is already live
  cudaGetLastError();
  cudaDeviceProp prop;
  CK(cudaGetDeviceProperties(&prop, dev));
  snprintf(d.name, sizeof d.name, "%s", prop.name);
  for (char *c = d.name; *c; c++)
    if (*c == ' ') *c = '_';
  CK(cudaMalloc(&d.d_cnt, sizeof(unsigned int)));
  CK(cudaMalloc(&d.d_hn, sizeof(unsigned long long) * HIT_CAP));
  CK(cudaMalloc(&d.d_ht, sizeof(unsigned long long) * HIT_CAP));
  CK(cudaMemset(d.d_cnt, 0, sizeof(unsigned int)));
  int per_sm = 0;
  CK(cudaOccupancyMaxActiveBlocksPerMultiprocessor(&per_sm, k_mine, 256, 0));
  if (per_sm < 1) per_sm = 1;
  d.grid = prop.multiProcessorCount * per_sm * 4;
  return true;
}

// Runs the real mining kernel with thr = max, so every nonce is a hit, and compares with the CPU reference.
static bool dev_selftest(Dev &d, std::string &why) {
  int dev = d.dev;
  CK(cudaSetDevice(dev));
  std::mt19937_64 rng(seed_mix(100 + dev));
  uint8_t msg[184];
  for (int i = 0; i < 184; i++) msg[i] = (uint8_t)rng();
  KParams p;
  unicred_prepare(msg, p.base);
  p.thr = ~0ULL;
  p.start = rng();
  p.iters = 1;
  CK(cudaMemset(d.d_cnt, 0, sizeof(unsigned int)));
  k_mine<<<1, HIT_CAP>>>(p, d.d_cnt, d.d_hn, d.d_ht);
  CK(cudaGetLastError());
  unsigned int cnt = 0;
  unsigned long long hn[HIT_CAP], ht[HIT_CAP];
  CK(cudaMemcpy(&cnt, d.d_cnt, sizeof cnt, cudaMemcpyDeviceToHost));
  CK(cudaMemcpy(hn, d.d_hn, sizeof hn, cudaMemcpyDeviceToHost));
  CK(cudaMemcpy(ht, d.d_ht, sizeof ht, cudaMemcpyDeviceToHost));
  CK(cudaMemset(d.d_cnt, 0, sizeof(unsigned int)));
  if (cnt != HIT_CAP) {
    char b[128];
    snprintf(b, sizeof b, "dev%d count %u != %d", dev, cnt, HIT_CAP);
    why = b;
    return true;
  }
  for (int i = 0; i < HIT_CAP; i++) {
    uint64_t want = unicred_top64(p.base, (uint64_t)hn[i]);
    if (want != (uint64_t)ht[i] || (uint64_t)hn[i] < p.start || (uint64_t)hn[i] >= p.start + HIT_CAP) {
      char b[160];
      snprintf(b, sizeof b, "dev%d nonce %016llx gpu %016llx cpu %016llx", dev, hn[i], ht[i], (unsigned long long)want);
      why = b;
      return true;
    }
  }
  return true;
}

static void dev_worker(Dev *dp) {
  Dev &d = *dp;
  int dev = d.dev;
  if (cudaSetDevice(dev) != cudaSuccess) {
    emit("ERR dev %d cudaSetDevice failed", dev);
    return;
  }
  std::mt19937_64 rng(seed_mix(1000 + dev));
  uint64_t my_gen = ~0ULL, cursor = 0;
  uint32_t iters = 4;
  Job job;
  unsigned long long hn[HIT_CAP], ht[HIT_CAP];
  while (!g_quit.load()) {
    if (g_gen.load() != my_gen) {
      job = snapshot_job();
      my_gen = job.gen;
      cursor = rng();
    }
    if (!job.active) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      continue;
    }
    KParams p;
    memcpy(p.base, job.base, sizeof p.base);
    p.thr = g_thr.load();
    p.start = cursor;
    p.iters = iters;
    uint64_t t0 = now_ns();
    k_mine<<<d.grid, 256>>>(p, d.d_cnt, d.d_hn, d.d_ht);
    cudaError_t e = cudaGetLastError();
    unsigned int cnt = 0;
    if (e == cudaSuccess) e = cudaMemcpy(&cnt, d.d_cnt, sizeof cnt, cudaMemcpyDeviceToHost);
    if (e != cudaSuccess) {
      emit("ERR dev %d kernel: %s", dev, cudaGetErrorString(e));
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
      continue;
    }
    double ms = (now_ns() - t0) / 1e6;
    uint64_t done = (uint64_t)d.grid * 256ULL * iters;
    cursor += done;
    g_dev_hashes[dev].fetch_add(done);
    if (cnt) {
      unsigned int n = cnt < HIT_CAP ? cnt : HIT_CAP;
      cudaMemcpy(hn, d.d_hn, sizeof(unsigned long long) * n, cudaMemcpyDeviceToHost);
      cudaMemcpy(ht, d.d_ht, sizeof(unsigned long long) * n, cudaMemcpyDeviceToHost);
      cudaMemset(d.d_cnt, 0, sizeof(unsigned int));
      if (g_gen.load() == my_gen)
        for (unsigned int i = 0; i < n; i++) emit("HIT %u %016llx %016llx", job.id, hn[i], ht[i]);
      if (cnt > HIT_CAP) emit("ERR dev %d hit buffer overflow (%u hits); threshold too loose", dev, cnt);
    }
    // keep each launch around 60 ms: short enough to switch jobs fast, long enough to amortise the launch
    if (ms < 40 && iters < (1u << 16)) iters *= 2;
    else if (ms > 120 && iters > 1) iters /= 2;
  }
}

static int engine_init(std::string &names) {
  int n = 0;
  if (cudaGetDeviceCount(&n) != cudaSuccess || n <= 0) {
    emit("ERR no CUDA devices");
    return 0;
  }
  if (n > MAX_DEV) n = MAX_DEV;
  for (int i = 0; i < n; i++) {
    g_devs[i].dev = i;
    if (!dev_init(g_devs[i])) return 0;
    if (i) names += "|";
    names += g_devs[i].name;
  }
  return n;
}
static bool engine_selftest(std::string &why) {
  for (int i = 0; i < g_ndev; i++) {
    std::string w;
    if (!dev_selftest(g_devs[i], w)) {
      why = "cuda error on dev " + std::to_string(i);
      return false;
    }
    if (!w.empty()) {
      why = w;
      return false;
    }
  }
  return true;
}
static std::vector<std::thread> engine_start() {
  std::vector<std::thread> ts;
  for (int i = 0; i < g_ndev; i++) ts.emplace_back(dev_worker, &g_devs[i]);
  return ts;
}

#else
// ------------------------------------------------------------------ CPU (local tests)
static int g_threads = 0;
static void cpu_worker(int t) {
  std::mt19937_64 rng(seed_mix(2000 + t));
  uint64_t my_gen = ~0ULL, cursor = 0;
  Job job;
  const uint32_t CHUNK = 1 << 15;
  while (!g_quit.load()) {
    if (g_gen.load() != my_gen) {
      job = snapshot_job();
      my_gen = job.gen;
      cursor = rng();
    }
    if (!job.active) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      continue;
    }
    const uint64_t thr = g_thr.load();
    for (uint32_t i = 0; i < CHUNK; i++) {
      const uint64_t nonce = cursor + i;
      KECCAK_VARS;
      KECCAK_LOAD(job.base);
      a6 ^= kbswap64(nonce);
      KECCAK_F_VARS();
      const uint64_t top = kbswap64(a0);
      if (top < thr && g_gen.load() == my_gen)
        emit("HIT %u %016llx %016llx", job.id, (unsigned long long)nonce, (unsigned long long)top);
    }
    cursor += CHUNK;
    g_dev_hashes[t].fetch_add(CHUNK);
  }
}
static int engine_init(std::string &names) {
  int n = g_threads > 0 ? g_threads : (int)std::thread::hardware_concurrency();
  if (n < 1) n = 1;
  if (n > MAX_DEV) n = MAX_DEV;
  names = "cpu_x" + std::to_string(n);
  return n;
}
static bool engine_selftest(std::string &why) {
  // the unrolled-variable path (what the workers run) against the array path
  std::mt19937_64 rng(seed_mix(7));
  uint8_t msg[184];
  for (int i = 0; i < 184; i++) msg[i] = (uint8_t)rng();
  uint64_t base[25];
  unicred_prepare(msg, base);
  for (int k = 0; k < 64; k++) {
    uint64_t nonce = rng();
    KECCAK_VARS;
    KECCAK_LOAD(base);
    a6 ^= kbswap64(nonce);
    KECCAK_F_VARS();
    if (kbswap64(a0) != unicred_top64(base, nonce)) {
      why = "unrolled path mismatch";
      return false;
    }
  }
  return true;
}
static std::vector<std::thread> engine_start() {
  std::vector<std::thread> ts;
  for (int i = 0; i < g_ndev; i++) ts.emplace_back(cpu_worker, i);
  return ts;
}
#endif

// ------------------------------------------------------------------ shared driver
static void set_job(uint32_t id, const uint8_t *msg184, uint64_t thr) {
  Job j;
  j.active = true;
  j.id = id;
  unicred_prepare(msg184, j.base);
  std::lock_guard<std::mutex> lk(g_job_mu);
  j.gen = g_job.gen + 1;
  g_job = j;
  g_thr.store(thr);
  g_gen.store(j.gen);
}
static void set_idle() {
  std::lock_guard<std::mutex> lk(g_job_mu);
  g_job.active = false;
  g_job.gen++;
  g_gen.store(g_job.gen);
}

static void rate_loop(bool bench) {
  std::vector<uint64_t> last(g_ndev, 0);
  uint64_t t_last = now_ns();
  while (!g_quit.load()) {
    for (int i = 0; i < 20 && !g_quit.load(); i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    uint64_t t = now_ns();
    double dt = (t - t_last) / 1e9;
    t_last = t;
    double total = 0;
    std::string per;
    for (int i = 0; i < g_ndev; i++) {
      uint64_t h = g_dev_hashes[i].load();
      double r = (h - last[i]) / dt;
      last[i] = h;
      total += r;
      char b[48];
      snprintf(b, sizeof b, " %.0f", r);
      per += b;
    }
    if (!bench) emit("RATE %.0f%s", total, per.c_str());
  }
}

static int run_bench(double seconds) {
  std::mt19937_64 rng(seed_mix(42));
  uint8_t msg[184];
  for (int i = 0; i < 184; i++) msg[i] = (uint8_t)rng();
  set_job(1, msg, 0);  // threshold 0: no hits, pure hashing
  std::vector<std::thread> ts = engine_start();
  std::this_thread::sleep_for(std::chrono::milliseconds(1500));  // warm up / let launch sizes settle
  std::vector<uint64_t> h0(g_ndev);
  for (int i = 0; i < g_ndev; i++) h0[i] = g_dev_hashes[i].load();
  uint64_t t0 = now_ns();
  std::this_thread::sleep_for(std::chrono::milliseconds((long)(seconds * 1000)));
  double dt = (now_ns() - t0) / 1e9;
  double total = 0;
  for (int i = 0; i < g_ndev; i++) {
    double r = (g_dev_hashes[i].load() - h0[i]) / dt;
    total += r;
#if ENGINE_GPU
    emit("BENCH dev %d %s %.3f GH/s", i, g_devs[i].name, r / 1e9);
#else
    emit("BENCH thread %d %.2f MH/s", i, r / 1e6);
#endif
  }
  emit("BENCH total %.3f GH/s (%d %s)", total / 1e9, g_ndev, ENGINE_GPU ? "GPUs" : "CPU threads");
  g_quit.store(true);
  for (auto &t : ts) t.join();
  return 0;
}

int main(int argc, char **argv) {
  bool bench = false;
  double bench_s = 5;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--bench")) {
      bench = true;
      if (i + 1 < argc && atof(argv[i + 1]) > 0) bench_s = atof(argv[++i]);
    }
#if !ENGINE_GPU
    else if (!strcmp(argv[i], "--threads") && i + 1 < argc) g_threads = atoi(argv[++i]);
#endif
  }
  for (int i = 0; i < MAX_DEV; i++) g_dev_hashes[i].store(0);
  std::string names;
  g_ndev = engine_init(names);
  if (g_ndev <= 0) return 1;
  std::string why;
  bool ok = engine_selftest(why);
  emit("SELFTEST %s %s", ok ? "OK" : "FAIL", why.c_str());
  if (!ok) return 3;
  if (bench) return run_bench(bench_s);
  emit("READY %d %s", g_ndev, names.c_str());

  std::vector<std::thread> ts = engine_start();
  std::thread rt(rate_loop, false);
  char line[4096];
  while (fgets(line, sizeof line, stdin)) {
    char cmd[16] = {0};
    if (sscanf(line, "%15s", cmd) != 1) continue;
    if (!strcmp(cmd, "JOB")) {
      unsigned int id = 0;
      char hex[1024] = {0}, thr[64] = {0};
      uint8_t msg[184];
      if (sscanf(line, "JOB %u %1023s %63s", &id, hex, thr) != 3 || !parse_hex_bytes(hex, msg, 184)) {
        emit("ERR bad JOB line");
        continue;
      }
      set_job(id, msg, strtoull(thr, nullptr, 16));
    } else if (!strcmp(cmd, "THR")) {
      unsigned int id = 0;
      char thr[64] = {0};
      if (sscanf(line, "THR %u %63s", &id, thr) != 2) {
        emit("ERR bad THR line");
        continue;
      }
      std::lock_guard<std::mutex> lk(g_job_mu);
      if (g_job.active && g_job.id == id) g_thr.store(strtoull(thr, nullptr, 16));
    } else if (!strcmp(cmd, "IDLE")) {
      set_idle();
    } else if (!strcmp(cmd, "QUIT")) {
      break;
    } else {
      emit("ERR unknown command %s", cmd);
    }
  }
  g_quit.store(true);
  for (auto &t : ts) t.join();
  rt.join();
  return 0;
}
