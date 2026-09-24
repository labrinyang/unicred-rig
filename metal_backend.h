// Metal backend for the shared driver in miner.cu. Included only by miner_metal.mm.
#include "keccak_metal.h"
#include <algorithm>
#include <cstddef>

struct KParams {
  uint64_t base[25];
  uint64_t thr;
  uint64_t start;
  uint32_t iters;
};
struct MetalHits {
  uint32_t count;
  uint32_t padding;
  uint64_t nonces[HIT_CAP];
  uint64_t tops[HIT_CAP];
};
static_assert(sizeof(KParams) == 224 && offsetof(KParams, iters) == 216, "Metal parameter layout");
static_assert(offsetof(MetalHits, nonces) == 8 && sizeof(MetalHits) == 1032, "Metal result layout");

struct Dev {
  id<MTLDevice> device;
  id<MTLCommandQueue> queue;
  id<MTLComputePipelineState> pipeline;
  id<MTLBuffer> hits;
  NSUInteger group_size = 0;
  char name[256] = {0};
};
static Dev g_devs[1];

static void metal_error(const char *operation, NSError *error = nil) {
  NSString *detail = error ? error.localizedDescription : @"resource unavailable";
  detail = [[detail componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]
             componentsJoinedByString:@" "];
  emit("ERR Metal %s: %s", operation, detail.UTF8String);
}

static int engine_init(std::string &names) {
  Dev &d = g_devs[0];
  d.device = MTLCreateSystemDefaultDevice();
  if (!d.device || ![d.device supportsFamily:MTLGPUFamilyApple7]) {
    emit("ERR Metal requires an Apple silicon GPU");
    return 0;
  }
  NSError *error = nil;
  MTLCompileOptions *options = [MTLCompileOptions new];
  options.languageVersion = MTLLanguageVersion2_3;
  id<MTLLibrary> library = [d.device newLibraryWithSource:@(keccak_metal_source) options:options error:&error];
  if (!library) {
    metal_error("compile", error);
    return 0;
  }
  id<MTLFunction> function = [library newFunctionWithName:@"mine"];
  if (!function) {
    metal_error("find kernel");
    return 0;
  }
  d.pipeline = [d.device newComputePipelineStateWithFunction:function error:&error];
  if (!d.pipeline) {
    metal_error("create pipeline", error);
    return 0;
  }
  d.queue = [d.device newCommandQueue];
  d.hits = [d.device newBufferWithLength:sizeof(MetalHits) options:MTLResourceStorageModeShared];
  if (!d.queue || !d.hits) {
    metal_error("allocate resources");
    return 0;
  }
  d.group_size = std::min<NSUInteger>(256, d.pipeline.maxTotalThreadsPerThreadgroup);
  snprintf(d.name, sizeof d.name, "%s", d.device.name.UTF8String);
  for (char *c = d.name; *c; c++) if (*c == ' ') *c = '_';
  names = d.name;
  return 1;
}

// CPU writes precede commit; GPU results are read only after completion. One worker owns these buffers.
static bool metal_dispatch(Dev &d, const KParams &p, NSUInteger threads) {
  memset(d.hits.contents, 0, sizeof(MetalHits));
  id<MTLCommandBuffer> command = [d.queue commandBuffer];
  id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
  if (!command || !encoder) {
    metal_error("create command");
    return false;
  }
  [encoder setComputePipelineState:d.pipeline];
  [encoder setBytes:&p length:sizeof p atIndex:0];
  [encoder setBuffer:d.hits offset:0 atIndex:1];
  [encoder dispatchThreads:MTLSizeMake(threads, 1, 1)
      threadsPerThreadgroup:MTLSizeMake(std::min(threads, d.group_size), 1, 1)];
  [encoder endEncoding];
  [command commit];
  [command waitUntilCompleted];
  if (command.status != MTLCommandBufferStatusCompleted) {
    metal_error("dispatch", command.error);
    return false;
  }
  return true;
}

static bool engine_selftest(std::string &why) {
  Dev &d = g_devs[0];
  std::mt19937_64 rng(0x554e4943524544ULL);
  struct TestCase {
    uint64_t start, threshold;
    uint32_t iters;
    bool exact_threshold;
  };
  const TestCase cases[] = {
    {0, UINT64_MAX, 4, false},
    {0xfffffff0ULL, UINT64_MAX, 4, false},
    {UINT64_MAX - 31, UINT64_MAX / 2, 4, false},
    {0x123456789abcdef0ULL, 0, 4, false},
    {0, UINT64_MAX, 8, false},  // overflow must count all hits but only store HIT_CAP results
    {UINT64_MAX, 0, 4, true},  // equality is not a valid proof
  };
  for (const auto &test : cases) {
    @autoreleasepool {
      uint8_t msg[184];
      for (auto &byte : msg) byte = (uint8_t)rng();
      KParams p = {};
      unicred_prepare(msg, p.base);
      p.start = test.start;
      p.thr = test.exact_threshold ? unicred_top64(p.base, p.start) : test.threshold;
      p.iters = test.iters;
      const uint32_t attempts = 16 * p.iters;
      if (!metal_dispatch(d, p, 16)) {
        why = "Metal dispatch failed";
        return false;
      }
      auto *hits = static_cast<const MetalHits *>(d.hits.contents);
      uint32_t expected = 0;
      for (uint64_t i = 0; i < attempts; i++) expected += unicred_top64(p.base, p.start + i) < p.thr;
      if (hits->count != expected) {
        why = "Metal hit count mismatch";
        return false;
      }
      std::vector<bool> seen(attempts, false);
      for (uint32_t i = 0; i < std::min<uint32_t>(hits->count, HIT_CAP); i++) {
        uint64_t offset = hits->nonces[i] - p.start;  // unsigned subtraction also checks nonce wraparound
        uint64_t want = unicred_top64(p.base, hits->nonces[i]);
        if (offset >= attempts || seen[offset] || want != hits->tops[i] || want >= p.thr) {
          why = "Metal nonce or digest mismatch";
          return false;
        }
        seen[offset] = true;
      }
    }
  }
  return true;
}

static void metal_worker() {
  Dev &d = g_devs[0];
  constexpr uint64_t threads = 16384;
  std::mt19937_64 rng(seed_mix(3000));
  uint64_t my_gen = UINT64_MAX, cursor = 0;
  uint32_t iters = 1;
  Job job;
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
    @autoreleasepool {
      KParams p = {};
      memcpy(p.base, job.base, sizeof p.base);
      p.thr = g_thr.load();
      p.start = cursor;
      p.iters = iters;
      uint64_t t0 = now_ns();
      if (!metal_dispatch(d, p, threads)) {
        // Fail the process so the controller can restart the backend instead of silently losing it.
        std::exit(1);
      }
      double ms = (now_ns() - t0) / 1e6;
      uint64_t done = threads * iters;
      cursor += done;
      g_dev_hashes[0].fetch_add(done);
      auto *hits = static_cast<const MetalHits *>(d.hits.contents);
      if (g_gen.load() == my_gen) {
        for (uint32_t i = 0; i < std::min<uint32_t>(hits->count, HIT_CAP); i++)
          emit("HIT %u %016llx %016llx", job.id,
               (unsigned long long)hits->nonces[i], (unsigned long long)hits->tops[i]);
        if (hits->count > HIT_CAP) emit("ERR Metal hit buffer overflow (%u hits); threshold too loose", hits->count);
      }
      // Bound dispatch time for responsive JOB/THR/IDLE handling; the cap also prevents counter overflow.
      if (ms < 40 && iters < 1024) iters *= 2;
      else if (ms > 120 && iters > 1) iters /= 2;
    }
  }
}

static std::vector<std::thread> engine_start() {
  std::vector<std::thread> ts;
  ts.emplace_back(metal_worker);
  return ts;
}
