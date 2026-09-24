// CPU check of keccak_core.h: prints the digest for (msg184 hex, nonce_low hex).
#include "keccak_core.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
static int hexval(char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }
int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: test_core <msg184hex> <noncelow hex>...\n"); return 2; }
  const char *h = argv[1]; if (h[0] == '0' && h[1] == 'x') h += 2;
  if (strlen(h) != 368) { fprintf(stderr, "msg184 must be 368 hex chars\n"); return 2; }
  uint8_t m[184];
  for (int i = 0; i < 184; i++) m[i] = (uint8_t)(hexval(h[2 * i]) << 4 | hexval(h[2 * i + 1]));
  uint64_t base[25];
  unicred_prepare(m, base);
  for (int a = 2; a < argc; a++) {
    uint64_t n = strtoull(argv[a], nullptr, 16);
    uint8_t d[32];
    unicred_digest(base, n, d);
    printf("%016llx ", (unsigned long long)unicred_top64(base, n));
    for (int i = 0; i < 32; i++) printf("%02x", d[i]);
    printf("\n");
  }
  // keccak-f sanity: keccak256("") via a single padded block
  uint64_t s[25] = {0}; s[0] ^= 0x01; s[16] ^= 0x8000000000000000ULL; keccakf(s);
  fprintf(stderr, "keccak256('') = ");
  for (int i = 0; i < 4; i++) for (int k = 0; k < 8; k++) fprintf(stderr, "%02x", (unsigned)(uint8_t)(s[i] >> (8 * k)));
  fprintf(stderr, "\n");
  return 0;
}
