"""ff25 thunk 形状判定的本地单测（不需要 PE / lief）。

用法：python3 tools/test_thunk_shapes.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from thunk_shapes import import_thunk_shape, tail_jump_thunk_shape  # noqa: E402

CASES = [
    # (名字, 16 字节, 期望)
    ("0x140bf4ff0 实拍（test rcx / je +7 / jmp[rip] / ret）",
     "4885c9740748ff25f4f67b00c3cccccc", True),
    ("纯尾跳（无守卫）", "48ff2511223344c3cccccccccccccc", True),
    ("jne 反向守卫", "4885c9750748ff25f4f67b00c3cccccc", True),
    ("test rdx 变体", "4885d2740748ff25f4f67b00c3cccccc", True),
    ("守卫跳出了槽（不是 thunk）", "4885c97410488b01c3cccccccccccccc", False),
    ("尾跳后面接的不是终止符", "48ff25112233448b01cccccccccccccc", False),
    ("尾跳不在槽首/槽 5（偏移 3）", "90909048ff2511223344c3cccccccccc", False),
    ("普通函数体（test+条件跳+mov）", "4885c97405488b01c3cccccccccccccc", False),
]

# tail_jump_thunk_shape 返回槽内尾跳偏移（-1 = 不是 thunk）。
# 前 8 条是 /tmp/Mewgenics.exe 里的逐字节实拍（地址写在名字里），
# 覆盖 import_thunk_shape 收不到的 D/E/F/G/H 五种形状。
TAIL_CASES = [
    # off=0：纯尾跳（0x140a91490）
    ("0x140a91490 纯尾跳", "48ff25d1dc3a00cccccccccccccccc", 0),
    # off=5：老守卫形态（0x140bf4ff0 / 0x140bf4fe0）
    ("0x140bf4ff0 守卫 + ret", "4885c9740748ff25f4f67b00c3cccccc", 5),
    ("0x140bf4fe0 守卫 + mov al,1;ret", "4885c9740748ff25fcf67b00b001c3cc", 5),
    # off=3：`mov rcx,rdx` 前缀（0x140a9b490，被 .data 引用 4 次）
    ("0x140a9b490 mov rcx,rdx 前缀", "488bca48ff253ef08500cccccccccccc", 3),
    # off=5：`mov ecx,0xc11` 前缀（0x14097a1e0，被 .rdata 引用 2 次）
    ("0x14097a1e0 mov ecx,imm 前缀", "b9110c000048ff250c564c00cccccccc", 5),
    # off=7：`xor edx,edx; mov ecx,imm` 前缀（0x140a29cf0，被 .rdata 引用）
    ("0x140a29cf0 xor edx/mov ecx 前缀", "33d2b9408d000048ff257a349900cccc", 7),
    # off=8：`test/lock inc` 守卫 + 裸 c3（0x140bf7f90，被 .rdata 引用）
    ("0x140bf7f90 lock inc 守卫", "4885c9740af0ff0148ff2519c87b00c3", 8),
    # off=8：`mov r8,rdx; mov edx,1` 前缀（0x140a55370，12 连排但无数据引用）
    ("0x140a55370 mov r8/mov edx 前缀", "4c8bc2ba0100000048ff25a1719600cc", 8),
    # off=5：守卫的空指针路径是 `xor eax,eax; ret` 而不是裸 ret（0x140a91290）
    ("0x140a91290 守卫 + 短返回体", "4885c9740748ff251c61860033c0c3cc", 5),
    # 反例：真函数序言（0x140a9b4a0），槽尾是实代码不是填充
    ("真函数序言", "48895c2408574883ec20440fb741304c", -1),
    # 反例：尾跳后面接实代码
    ("尾跳后面接实代码", "48ff25112233448b01cccccccccccccc", -1),
    # 反例：守卫的空指针路径太长（8 字节）
    ("守卫空指针路径过长", "4885c9740748ff251122334490909090", -1),
    # 反例：尾跳跨出 16 字节槽（off=10）
    ("尾跳跨出槽", "9090909090909090909048ff25cccccc", -1),
]


def _pad(hexs: str) -> bytes:
    # 真机上槽内不足 16 字节的部分一律是 cc 填充，这里同样补齐
    return (bytes.fromhex(hexs) + b"\xcc" * 16)[:16]


def main() -> int:
    bad = 0
    for name, hexs, want in CASES:
        got = import_thunk_shape(_pad(hexs), 0)
        ok = (got == want)
        print(("PASS " if ok else "FAIL ") + name + f"  got={got} want={want}")
        if not ok:
            bad += 1
    total = len(CASES)
    for name, hexs, want in TAIL_CASES:
        got = tail_jump_thunk_shape(_pad(hexs), 0)
        ok = (got == want)
        print(("PASS " if ok else "FAIL ") + name + f"  got={got} want={want}")
        if not ok:
            bad += 1
        total += 1
    print(f"\n{total - bad}/{total} 通过")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
