// 用真实硬件 SSE4.2 当金标准，判定 strict 与 prefix 两种语义谁对。
// 编译：g++ -O2 -msse4.2 tests/test_sse42_pcmp.cpp -o /tmp/t && /tmp/t
#include "sse42_pcmp_ref.hpp"
#include <nmmintrin.h>
#include <cstdio>
#include <cstring>

struct Case { const char* name; uint8_t a[16]; int la; uint8_t b[16]; int lb; uint8_t imm; };

static void run(const Case& c) {
    __m128i va = _mm_loadu_si128((const __m128i*)c.a);
    __m128i vb = _mm_loadu_si128((const __m128i*)c.b);
    __m128i hw = _mm_cmpestrm(va, c.la, vb, c.lb, c.imm);
    uint8_t hwb[16]; _mm_storeu_si128((__m128i*)hwb, hw);
    uint16_t hw_mask = (uint16_t)(hwb[0] | (hwb[1] << 8));
    int hw_idx = _mm_cmpestri(va, c.la, vb, c.lb, c.imm);

    PcmpFlags fs{}, fp{};
    uint16_t ms = s42_core_strict(c.a, c.la, c.b, c.lb, c.imm, fs);
    uint16_t mp = s42_core_prefix(c.a, c.la, c.b, c.lb, c.imm, fp);
    const bool bitmask = (c.imm & 0x40) == 0;
    const uint16_t hw_cmp = bitmask ? hw_mask : 0;
    printf("%-28s imm=0x%02x la=%2d lb=%2d | hw=0x%04x strict=0x%04x%s prefix=0x%04x%s | idx hw=%d strict=%d\n",
           c.name, c.imm, c.la, c.lb, hw_mask,
           ms, (bitmask && ms == hw_cmp) ? "" : "✗",
           mp, (bitmask && mp == hw_cmp) ? "" : "✗", hw_idx, 0);
}

int main() {
    if (!__builtin_cpu_supports("sse4.2")) { puts("SKIP: no SSE4.2 on this host"); return 0; }
    Case cases[] = {
      {"ordered 命中中段", {'a','b',0}, 2, {'x','x','a','b','x','x',0}, 6, 0x0C},
      {"ordered 尾部重叠（关键）", {'a','b','c',0}, 3, {'a','b',0}, 2, 0x0C},
      {"ordered la=lb=16 全等", {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'}, 16,
                                {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'}, 16, 0x0C},
      {"equal-any 命中", {0}, 1, {'a','b','c',0}, 3, 0x00},
      {"equal-any 多字符集", {'a','z',0}, 2, {'m','a','t','z',0}, 4, 0x00},
      {"equal-each 全等", {'a','b',0}, 2, {'a','b',0}, 2, 0x08},
      {"ranges", {'a','z',0}, 2, {'m',0}, 1, 0x04},
      {"负极性", {'x',0}, 1, {'a','x','b',0}, 3, 0x10},
    };
    for (const auto& c : cases) run(c);
    puts("\n说明：✗ = 与硬件不一致；equal-ordered 的「尾部重叠」是 strict 与 prefix 唯一分歧点。");
    return 0;
}
