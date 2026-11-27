"""ff25 型 import thunk 的形状判定（可单测，不依赖 lief / PE）。

背景（run 45999239672）：0x140bf4fc0/4fd0/4fe0/4ff0 是四个 16 字节一格的
import thunk，`.text` 内、没有 .pdata。旧的挖掘规则只认 `48 85 /r` 开头的守卫形态，
于是同一串里有的收、有的漏；漏掉的那个在运行期就是一次
`[FATAL] Unmapped indirect target`。这里把判定抽成纯函数并覆盖三种实测形态。
"""
from __future__ import annotations


def import_thunk_shape(buf, p: int, size: int = 16) -> bool:
    """buf[p:p+size] 是否是 ff25 型 import thunk。

    实测形状：
      A) `48 ff 25 <rel32>` + `c3`                    纯尾跳
      B) `48 85 /r` + `74 07` + `48 ff 25 <rel32>` + `c3`
         test r,r / je 跳过尾跳 / jmp qword [rip+rel32] / ret —— 空指针守卫
      C) 同 B 但条件是 `75`（jne）—— 反向守卫，少见但一并认
    精度靠调用方再查 16 对齐 + 不在已知函数内 + 槽尾落在终止符上。
    """
    slot = buf[p:p + size]
    if len(slot) < 8:
        return False
    for off in (0, 5):
        if len(slot) < off + 7:
            continue
        if slot[off:off + 3] != b'\x48\xff\x25':
            continue
        if off == 5:                       # 守卫形态：test r,r / jcc
            if slot[0] != 0x48 or slot[1] != 0x85:
                continue
            if slot[3] not in (0x74, 0x75):
                continue
            tgt = 7 + slot[4]              # jcc 后下一条在 offset 5，再加 imm8
            if tgt < size and slot[tgt] not in (0xC3, 0xCC):
                continue
        end = off + 7
        if end < size and slot[end] not in (0xC3, 0xCC, 0x00):
            continue
        return True
    return False


def tail_jump_thunk_shape(buf, p: int, size: int = 16) -> int:
    """更宽的判定：返回 `jmp qword [rip+rel32]` 在槽内的偏移，-1 表示不是 thunk。

    为什么需要第二套判定（run 46012603858 之前扫全 .text 得到）：
    16 字节一格的 thunk **不止** A/B 两种形状，实测还有

      D) `48 8b ca`            mov rcx,rdx        + jmp[rip] + cc
      E) `b9 11 0c 00 00`      mov ecx,0xc11      + jmp[rip] + cc
      F) `33 d2 b9 40 8d 00 00`mov edx,0;mov ecx,… + jmp[rip] + cc
      G) `48 85 c9 74 0a f0 ff 01` test/lock inc + jmp[rip] + c3
      H) `48 85 c9 74 07` + jmp[rip] + `33 c0 c3`（空指针路径返回 0，不是裸 ret）

    它们都是「任意短前缀 + 尾跳 + 终止符/填充铺满 16 字节」的完整单元，
    旧的 import_thunk_shape 只认 off∈{0,5} 且前缀固定，于是漏掉 30 个；
    其中 4 个还被 .rdata/.data 当函数指针引用（0x14097a1e0 / 0x140a29cf0 /
    0x140a9b490 / 0x140bf7f90），一旦被调用就是一次 [FATAL] 未映射目标。

    判据只描述**槽自身的完整性**；「16 对齐 / 不在 .pdata 内」由调用方查，
    因为这两条依赖 PE 布局，不该塞进纯函数。
    """
    slot = buf[p:p + size]
    if len(slot) < 12:
        return -1
    for off in range(0, min(10, len(slot) - 6)):
        if slot[off:off + 3] != b'\x48\xff\x25':
            continue
        end = off + 7
        if end > len(slot):
            continue
        rest = slot[end:]
        if not rest:
            return off
        # 形态 a：尾跳之后一路是终止符/填充，铺到槽尾
        if all(b in (0xC3, 0xCC, 0x00) for b in rest):
            return off
        # 形态 b：守卫 + 一段很短的「空指针路径」以 c3 收尾，后面才是填充
        if slot[0:2] == b'\x48\x85' and slot[3] in (0x74, 0x75):
            tgt = 5 + slot[4]
            if 5 <= tgt < len(slot):
                tail = slot[tgt:]
                k = len(tail)
                while k and tail[k - 1] in (0xCC, 0x00):
                    k -= 1
                body = tail[:k]
                if 1 <= len(body) <= 5 and body[-1] == 0xC3:
                    return off
    return -1
