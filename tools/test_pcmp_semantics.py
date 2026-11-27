"""PCMPxSTRx 语义自测（纯 Python 复刻 runtime/include/x64_sse_helpers.h 的 pcmp_core）。

用途：C++ 侧没有本地编译器，语义类改动（pcmpestrm 的聚合函数 / 极性 / 长度截断）
先在这里跑一遍，避免拿主仓的一轮 stage3 当编译器用。

注意：当前实现是 **「前缀能比多少比多少」**（ce3192e，依据 46005327501 里调用点
0x140d1a451..45d 的 bsr/btr 候选枚举 + 逐位完整比对）；严格 SDM 的 equal-ordered
要求 i+la<=lb，两者在尾部重叠处不同，用例 2/7 专门把这条差异钉住。

用法：python3 tools/test_pcmp_semantics.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def pcmp_core(a: bytes, b: bytes, nA: int, nB: int, imm: int) -> int:
    """返回 IntRes2 位图（第 i 位 = haystack 第 i 个元素命中）。

    a = needle（SDM 的 xmm1，长度 EAX）；b = haystack（xmm2/m128，长度 EDX）。
    """
    fmt = imm & 3
    unit = 2 if fmt in (1, 3) else 1
    sgn = fmt >= 2
    agg = (imm >> 2) & 3
    n = 16 // unit
    nA = min(max(nA, 0), n)
    nB = min(max(nB, 0), n)

    def el(p, i):
        if unit == 1:
            v = p[i]
            return v - 256 if (sgn and v > 127) else v
        v = p[2 * i] | (p[2 * i + 1] << 8)
        if sgn and v > 32767:
            v -= 65536
        return v

    bits = 0
    for i in range(nB):
        h = el(b, i)
        hit = False
        if agg == 0:                       # equal any
            hit = any(h == el(a, j) for j in range(nA))
        elif agg == 1:                     # ranges：needle 两两成区间
            j = 0
            while j + 1 < nA:
                if el(a, j) <= h <= el(a, j + 1):
                    hit = True
                    break
                j += 2
        elif agg == 2:                     # equal each
            hit = (i < nA and h == el(a, i))
        else:                              # equal ordered（前缀语义）
            k_max = min(nA, nB - i)
            hit = k_max > 0 and all(el(b, i + k) == el(a, k) for k in range(k_max))
        if hit:
            bits |= 1 << i

    if imm & 0x10:                         # 负极性，只在有效 haystack 范围内取反
        full = (1 << n) - 1
        valid = full if nB >= n else ((1 << nB) - 1)
        bits = (bits ^ full) & valid
    return bits & ((1 << n) - 1)


def pad(s: bytes) -> bytes:
    return (s + b"\x00" * 16)[:16]


# (名字, needle, haystack, nA, nB, imm8, 期望位图)
CASES = [
    # equal-ordered：needle "ab" 在 "xxabxx" 里，命中位置 2
    ("equal-ordered 命中 bit2", b"ab", b"xxabxx", 2, 6, 0x0C, 0b100),
    # 前缀语义：needle "abc"(3) 比 haystack "ab"(2)，i=0 的前 2 个前缀全等 → 置位
    # 严格 SDM（i+la<=lb）这里应当是 0 —— 这条差异是 ce3192e 的立论基础
    ("前缀语义：尾部重叠也算命中", b"abc", b"ab", 3, 2, 0x0C, 0b1),
    # equal-any：needle {0x00} 在 "abc\0" 里命中位置 3
    ("equal-any 命中 bit3", b"\x00", b"abc\x00", 1, 4, 0x00, 0b1000),
    # equal-each：同下标逐元素相等
    ("equal-each 前两位相等", b"ab", b"ab", 2, 2, 0x08, 0b11),
    # ranges：needle 两两成区间 [a,z]，haystack "m"
    ("ranges [a,z] 命中 m", b"az", b"m", 2, 1, 0x04, 0b1),
    # 负极性：needle 'x' 不在 "axb" 的位置 0、2
    ("负极性取反", b"x", b"axb", 1, 3, 0x10, 0b101),
    # la=lb=16 全等串：只有 bit0。前缀语义比的是「needle 的前缀」，
    # i>=1 时 needle[0] 要等于 haystack[i]，全等串下就对不上
    ("la=lb=16 全等：只有 bit0", b"0123456789abcdef", b"0123456789abcdef", 16, 16, 0x0C, 0b1),
    # 长度 0：needle 空 → 无命中
    ("nA=0 无命中", b"", b"abc", 0, 3, 0x0C, 0),
]


def main() -> int:
    bad = 0
    for name, a, b, nA, nB, imm, want in CASES:
        got = pcmp_core(pad(a), pad(b), nA, nB, imm)
        ok = got == want
        print(("PASS " if ok else "FAIL ") + name + f"  got={got:#06x} want={want:#06x}")
        if not ok:
            bad += 1
    print(f"\n{len(CASES) - bad}/{len(CASES)} 通过")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
