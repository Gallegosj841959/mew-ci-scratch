// SSE4.2 PCMPESTRM/PCMPESTRI 参考实现（两种语义）：
//   strict —— SDM 语义：equal-ordered 要求 needle 整段落在窗口内（i+len_a<=len_b）
//   prefix —— 本仓运行时当前实现：能比多少比多少（尾部重叠也算）
// 目的：在真实 x86-64 上用硬件指令当金标准，判断哪一个与硬件一致。
#pragma once
#include <cstdint>
#include <cstring>

struct PcmpFlags { bool cf, zf, sf, of, af, pf; };

static inline int32_t s42_lane(const uint8_t* v, int idx, int fmt) {
    switch (fmt & 3) {
        case 0: return (int32_t)v[idx];
        case 2: return (int32_t)(int8_t)v[idx];
        case 1: { uint16_t x; std::memcpy(&x, v + idx * 2, 2); return (int32_t)x; }
        default:{ int16_t  x; std::memcpy(&x, v + idx * 2, 2); return (int32_t)x; }
    }
}

// strict 版 core：返回 IntRes2；bits 以 b（haystack）位置为下标
static inline uint16_t s42_core_strict(const uint8_t* a, int la, const uint8_t* b, int lb,
                                       uint8_t imm8, PcmpFlags& f) {
    const int fmt = imm8 & 3, agg = (imm8 >> 2) & 3, pol = (imm8 >> 4) & 3;
    const int N = (fmt & 1) ? 8 : 16;
    la = la < 0 ? 0 : (la > N ? N : la);
    lb = lb < 0 ? 0 : (lb > N ? N : lb);
    uint16_t r1 = 0;
    if (agg == 0) {                       // equal any
        for (int j = 0; j < lb; ++j)
            for (int i = 0; i < la; ++i)
                if (s42_lane(a, i, fmt) == s42_lane(b, j, fmt)) { r1 |= (uint16_t)(1u << j); break; }
    } else if (agg == 1) {                // ranges
        for (int j = 0; j < lb; ++j) {
            int32_t vb = s42_lane(b, j, fmt);
            for (int i = 0; i + 1 < la; i += 2) {
                int32_t lo = s42_lane(a, i, fmt), hi = s42_lane(a, i + 1, fmt);
                if (vb >= lo && vb <= hi) { r1 |= (uint16_t)(1u << j); break; }
            }
        }
    } else if (agg == 2) {                // equal each
        for (int j = 0; j < N; ++j) {
            bool va = j < la, vb = j < lb;
            if (!va && !vb) r1 |= (uint16_t)(1u << j);
            else if (va && vb && s42_lane(a, j, fmt) == s42_lane(b, j, fmt)) r1 |= (uint16_t)(1u << j);
        }
    } else {                              // equal ordered（strict：整段装得下才算）
        for (int j = 0; j < N; ++j) {
            bool ok = true;
            for (int i = 0; i < la; ++i) {
                int jb = j + i;
                if (jb >= N) break;               // SDM：超出 16B 窗口
                if (jb >= lb) { ok = false; break; }
                if (s42_lane(a, i, fmt) != s42_lane(b, jb, fmt)) { ok = false; break; }
            }
            if (ok) r1 |= (uint16_t)(1u << j);
        }
    }
    const uint16_t full = (uint16_t)((1u << N) - 1u);
    uint16_t r2 = r1 & full;
    if (pol == 1) r2 = (uint16_t)(~r1) & full;
    else if (pol == 3) {
        uint16_t valid = (lb >= N) ? full : (uint16_t)((1u << lb) - 1u);
        r2 = (uint16_t)((r1 & ~valid) | ((~r1) & valid));
    }
    f.cf = r2 != 0; f.zf = lb < N; f.sf = la < N; f.of = (r2 & 1u) != 0; f.af = f.pf = false;
    return r2;
}

// prefix 版 core：复刻本仓 runtime 的 equal-ordered（k_max = min(la, lb-j)）
static inline uint16_t s42_core_prefix(const uint8_t* a, int la, const uint8_t* b, int lb,
                                       uint8_t imm8, PcmpFlags& f) {
    const int fmt = imm8 & 3, agg = (imm8 >> 2) & 3;
    const int N = (fmt & 1) ? 8 : 16;
    la = la < 0 ? 0 : (la > N ? N : la);
    lb = lb < 0 ? 0 : (lb > N ? N : lb);
    uint16_t bits = 0;
    if (agg == 3) {
        for (int j = 0; j < lb; ++j) {
            int k_max = (la < lb - j) ? la : (lb - j);
            if (k_max <= 0) continue;
            bool ok = true;
            for (int k = 0; k < k_max; ++k)
                if (s42_lane(a, k, fmt) != s42_lane(b, j + k, fmt)) { ok = false; break; }
            if (ok) bits |= (uint16_t)(1u << j);
        }
    } else {
        return s42_core_strict(a, la, b, lb, imm8, f);
    }
    uint16_t full = (uint16_t)((1u << N) - 1u);
    uint16_t r2 = bits & full;
    const int pol = (imm8 >> 4) & 3;
    if (pol == 1) r2 = (uint16_t)(~bits) & full;
    else if (pol == 3) {
        uint16_t valid = (lb >= N) ? full : (uint16_t)((1u << lb) - 1u);
        r2 = (uint16_t)((bits & ~valid) | ((~bits) & valid));
    }
    f.cf = r2 != 0; f.zf = lb < N; f.sf = la < N; f.of = (r2 & 1u) != 0; f.af = f.pf = false;
    return r2;
}
