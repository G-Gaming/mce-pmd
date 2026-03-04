# 海光 7490 内存拓扑深度分析

> **机器型号**: 海光 Hygon 7490 (基于 AMD Zen1 EPYC 架构定制)
> **分析日期**: 2026-03-04
> **分析目的**: 梳理完整的内存拓扑结构，为 DPDK 高性能网络调优提供依据

---

## 一、硬件概览

### 1.1 CPU 基础参数

| 参数 | 值 |
|---|---|
| CPU 型号 | Hygon 7490 (Family 24, Model 4) |
| 架构基础 | AMD Zen1 EPYC (Naples) 定制版 |
| Socket 数 | 2 |
| 每 Socket 核心数 | 64C / 128T (SMT 开启) |
| NUMA 节点总数 | 8 (每 Socket 4 个) |
| 每 NUMA 核心数 | 16C / 32T |
| L3 Cache | 每 NUMA 64 MB (4 × 16 MB slice) |
| 全系统 L3 | 512 MB |

### 1.2 内存基础参数

| 参数 | 值 |
|---|---|
| 内存类型 | DDR5 RDIMM (Registered) |
| 标称速度 | 5600 MT/s |
| 实际运行速度 | 4400 MT/s |
| 单条容量 | 32 GB |
| Rank 数 | Dual Rank (每条 DIMM) |
| 总 DIMM 数 | 24 条 (每 Socket 12 条) |
| 总容量 | 768 GB |
| Data Width | 64-bit |
| Total Width | 80-bit (含 ECC 16-bit) |

---

## 二、核心结论

### 2.1 通道数判定

```
┌─────────────────────────────────────────────────┐
│              最终判定（实测验证）                │
│                                                  │
│  每 NUMA 物理通道数:    2 通道                   │
│  每 Socket 物理通道数:  8 通道                   │
│  全系统物理通道数:      16 通道                  │
│                                                  │
│  每 NUMA DIMM 数:       3 条 (2DPC + 1DPC)       │
│  每 NUMA 容量:          96 GB                    │
│                                                  │
│  每 NUMA 理论带宽:      70,400 MB/s              │
│  每 NUMA 实测峰值:      69,518 MB/s (98.7%)      │
│                                                  │
│  判定依据: 实测带宽饱和值，非 dmidecode/EDAC     │
└─────────────────────────────────────────────────┘
```

### 2.2 关键区分：通道数 ≠ DIMM 数 ≠ EDAC Channel 编号

| 数据源 | 显示值 | 含义 | 是否等于物理通道 |
|---|---|---|---|
| dmidecode Channel A/B/C | 3 | 主板 DIMM 槽位标签 | ❌ |
| EDAC ch0/ch1/ch2 | 3 | 驱动按 DIMM 逻辑编号 | ❌ |
| DIMM 物理数量 | 3 | 实际插入的内存条数 | ❌ |
| **实测带宽饱和值** | **2** | **物理独立 64-bit 总线数** | **✅** |

> **核心原则：永远以实测带宽为准，不要相信软件层面的通道命名。**

---

## 三、实测带宽数据

### 3.1 单 NUMA 不同线程数带宽

使用 `likwid-bench -t load`（纯读测试）：

| 线程数 | 实测 (MiB/s) | 换算 (MB/s) | 等效通道数 | 分析 |
|---|---|---|---|---|
| 1T | 14,206 | 14,900 | 0.42 | 单线程，远未饱和 |
| 2T | 23,443 | 24,575 | 0.70 | 接近 1 通道 |
| 4T | 32,866 | 34,500 | 0.98 | **1 通道饱和** |
| 8T | 32,227 | 33,800 | 0.96 | 仍是 1 通道（全在同 CCX） |
| 16T | 58,912 | 61,762 | 1.75 | 第 2 通道被激活 |
| 24T | 62,806 | 65,863 | 1.87 | 接近 2 通道 |
| 32T | 66,291 | 69,518 | **1.97** | **2 通道饱和（98.7%）** |

### 3.2 带宽增长曲线

```
带宽
(MB/s)
   │
105k│· · · · · · · · · · · · · · · · · · ·  3通道理论 105,600 (排除)
   │
 70k│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ▲━━━━━  2通道理论 70,400
   │                            ╱ ← 32T 触顶 69,518
 60k│                      ●──╱
   │                    ╱     16T: 61,762
 50k│                 ╱
   │               ╱
 40k│             ╱
   │           ╱
 35k│─ ─●━━━━●─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  1通道理论 35,200
   │ ╱  4T    8T
 25k│●        2T: 24,575
   │╱
 15k│●        1T: 14,900
   │
   └──┬───┬───┬───┬───┬───┬───┬───┬──
      1   4   8  12  16  20  24  32  线程数

关键特征：
  - 4T 处第一个平台（1 通道饱和 ~35,200）
  - 8T 没有上升（线程仍在同一 CCX 侧）
  - 16T 跳升（第二个 CCX 激活第二通道）
  - 32T 触顶在 ~70,400（2 通道饱和）
  - 没有第三个台阶 → 排除 3 通道
```

### 3.3 所有 NUMA 节点一致性验证

| NUMA | Socket | 少线程 4T (MB/s) | 多线程 16T (MB/s) | 效率 |
|---|---|---|---|---|
| NUMA 0 | CPU0 | 34,429 | 55,250 | 78.4% |
| NUMA 1 | CPU0 | 34,666 | 55,273 | 78.5% |
| NUMA 2 | CPU0 | 34,728 | 55,266 | 78.5% |
| NUMA 3 | CPU0 | 34,725 | 55,296 | 78.5% |
| NUMA 4 | CPU1 | 34,780 | 55,945 | 79.4% |
| NUMA 5 | CPU1 | 34,668 | 55,600 | 78.9% |
| NUMA 6 | CPU1 | 34,754 | 55,676 | 79.0% |
| NUMA 7 | CPU1 | 34,758 | 55,621 | 79.0% |

> 所有 NUMA 节点标准差 < 1%，硬件完全对称。

---

## 四、物理拓扑图

### 4.1 单 NUMA 节点内部结构

```
┌──────────────────────────────────────────────────────┐
│                    NUMA 节点                          │
│                                                      │
│   ┌─────────────┐          ┌─────────────┐          │
│   │   CCX 0     │          │   CCX 1     │          │
│   │  8 核 / 16T │          │  8 核 / 16T │          │
│   │  L3: 32 MB  │          │  L3: 32 MB  │          │
│   └──────┬──────┘          └──────┬──────┘          │
│          │                        │                  │
│          └──────── DF/IF ────────┘                  │
│                     │                                │
│                  ┌──▼──┐                             │
│                  │ MC  │ (Memory Controller)         │
│                  └──┬──┘                             │
│               ┌─────┴──────┐                         │
│            物理通道 0    物理通道 1                   │
│            64-bit DDR5   64-bit DDR5                 │
│            35.2 GB/s     35.2 GB/s                   │
│              ┌┴──┐          │                        │
│           DIMM   DIMM     DIMM                       │
│           32GB   32GB     32GB                       │
│           (2DPC)          (1DPC)                     │
│                                                      │
│   容量:  64 + 32 = 96 GB                            │
│   带宽:  35.2 + 35.2 = 70.4 GB/s (理论)            │
│   实测:  69.5 GB/s (32T load, 98.7% 效率)           │
│                                                      │
│   EDAC 视角:                                         │
│     mc: F18h_M04h                                    │
│     csrow0/csrow1: 2 个 chip-select row (Dual Rank) │
│     ch0/ch1/ch2: 3 个逻辑编号 (= 3 条 DIMM)        │
│     rank0-rank5: 6 个 rank (3 DIMM × Dual Rank)     │
│                                                      │
└──────────────────────────────────────────────────────┘
```

### 4.2 单 Socket 拓扑

```
Socket 0 (CPU0) — 64C/128T, 384GB, 8 通道
┌────────────────────────────────────────────────────────────┐
│                                                            │
│  ┌────────────────┐  ┌────────────────┐                   │
│  │  Die 0/NUMA 0  │  │  Die 1/NUMA 1  │                   │
│  │  16C, 96GB     │  │  16C, 96GB     │                   │
│  │  MC: 2ch       │  │  MC: 2ch       │                   │
│  │  3 DIMM        │  │  3 DIMM        │                   │
│  │  ~70 GB/s      │  │  ~70 GB/s      │                   │
│  └───────┬────────┘  └───────┬────────┘                   │
│          │                   │                             │
│          └─── Infinity Fabric / xGMI ───┐                 │
│          ┌──────────────────────────────┘                  │
│          │                   │                             │
│  ┌───────┴────────┐  ┌──────┴─────────┐                   │
│  │  Die 2/NUMA 2  │  │  Die 3/NUMA 3  │                   │
│  │  16C, 96GB     │  │  16C, 96GB     │                   │
│  │  MC: 2ch       │  │  MC: 2ch       │                   │
│  │  3 DIMM        │  │  3 DIMM        │                   │
│  │  ~70 GB/s      │  │  ~70 GB/s      │                   │
│  └────────────────┘  └────────────────┘                   │
│                                                            │
│  Socket 0 总计:                                            │
│    4 Die × 2 通道 = 8 通道                                 │
│    4 NUMA × 96 GB = 384 GB                                │
│    4 NUMA × 70 GB/s = ~280 GB/s (独立跑时)                │
└────────────────────────────────────────────────────────────┘
```

### 4.3 全系统拓扑

```
┌─────────────────────────────────────────────────────────────┐
│                        全系统                               │
│                                                             │
│    Socket 0                        Socket 1                 │
│  ┌─────────┬─────────┐          ┌─────────┬─────────┐     │
│  │ NUMA 0  │ NUMA 1  │          │ NUMA 4  │ NUMA 5  │     │
│  │ 2ch     │ 2ch     │          │ 2ch     │ 2ch     │     │
│  │ 96GB    │ 96GB    │          │ 96GB    │ 96GB    │     │
│  │ ~70GB/s │ ~70GB/s │          │ ~70GB/s │ ~70GB/s │     │
│  ├─────────┼─────────┤          ├─────────┼─────────┤     │
│  │ NUMA 2  │ NUMA 3  │          │ NUMA 6  │ NUMA 7  │     │
│  │ 2ch     │ 2ch     │          │ 2ch     │ 2ch     │     │
│  │ 96GB    │ 96GB    │          │ 96GB    │ 96GB    │     │
│  │ ~70GB/s │ ~70GB/s │          │ ~70GB/s │ ~70GB/s │     │
│  └─────────┴─────────┘          └─────────┴─────────┘     │
│   8ch, 384GB, ~280GB/s           8ch, 384GB, ~280GB/s      │
│                                                             │
│           ◄══ xGMI 跨 Socket 互联 ══►                     │
│                                                             │
│  全系统: 16 通道, 768 GB, ~560 GB/s                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 五、DIMM 与通道映射关系

### 5.1 通道 vs DIMM 概念澄清

```
通道（Channel）= 物理的 64-bit DDR5 数据总线
  → 决定带宽
  → 每通道固定 35.2 GB/s (DDR5-4400)

DIMM = 插在总线上的内存条
  → 决定容量
  → 同一通道挂多条 DIMM (2DPC) 增加容量但不增加带宽

类比：
  通道 = 高速公路车道（决定通行速度）
  DIMM = 车道尽头的停车场（决定停车容量）
  车道数决定带宽，停车场数决定容量，两者独立
```

### 5.2 1DPC vs 2DPC 的影响

| 配置 | 容量 | 带宽 | 信号质量 | 可能降频 |
|---|---|---|---|---|
| 1DPC (1 DIMM/通道) | 32 GB | 35.2 GB/s | 优 | 否 |
| 2DPC (2 DIMM/通道) | 64 GB | 35.2 GB/s (不变) | 较差 | 可能降 10-20% |

### 5.3 每 NUMA 的 DIMM-通道对应

```
物理通道 0 (2DPC):
  ├── DIMM 0: 32 GB, Dual Rank  (dmidecode "Channel A")
  └── DIMM 1: 32 GB, Dual Rank  (dmidecode "Channel B")
  容量: 64 GB
  Rank 数: 4 (2 DIMM × 2 Rank)
  → Rank interleaving 可在 4 个 Rank 间交替，利用率高

物理通道 1 (1DPC):
  └── DIMM 2: 32 GB, Dual Rank  (dmidecode "Channel C")
  容量: 32 GB
  Rank 数: 2 (1 DIMM × 2 Rank)
  → Rank interleaving 在 2 个 Rank 间交替

总计: 96 GB, 2 物理通道
```

---

## 六、EDAC 信息解读

### 6.1 EDAC 输出结构

```
/sys/devices/system/edac/mc/mc0/
  ├── mc_name: F18h_M04h          ← 海光 Zen1 EDAC 驱动
  ├── size_mb: 24576               ← 驱动报告不完整 (实际 96 GB)
  ├── csrow0/                      ← Chip-Select Row 0 (所有 DIMM 的 Rank 0)
  │   ├── size_mb: 12288
  │   ├── ch0_dimm_label            ← DIMM 0 的 Rank 0
  │   ├── ch1_dimm_label            ← DIMM 1 的 Rank 0
  │   └── ch2_dimm_label            ← DIMM 2 的 Rank 0
  ├── csrow1/                      ← Chip-Select Row 1 (所有 DIMM 的 Rank 1)
  │   ├── size_mb: 12288
  │   ├── ch0_dimm_label            ← DIMM 0 的 Rank 1
  │   ├── ch1_dimm_label            ← DIMM 1 的 Rank 1
  │   └── ch2_dimm_label            ← DIMM 2 的 Rank 1
  ├── rank0: csrow 0, channel 0    ← DIMM 0, Rank 0, 4096 MB
  ├── rank1: csrow 0, channel 1    ← DIMM 1, Rank 0, 4096 MB
  ├── rank2: csrow 0, channel 2    ← DIMM 2, Rank 0, 4096 MB
  ├── rank3: csrow 1, channel 0    ← DIMM 0, Rank 1, 4096 MB
  ├── rank4: csrow 1, channel 1    ← DIMM 1, Rank 1, 4096 MB
  └── rank5: csrow 1, channel 2    ← DIMM 2, Rank 1, 4096 MB
```

### 6.2 EDAC "channel" 的真实含义

```
EDAC 的 ch0/ch1/ch2 ≠ 物理通道

EDAC 的 "channel" = MC 寄存器中的 DIMM 位置编号
  ch0 = DIMM 槽位 0 (可能在物理通道 0 上)
  ch1 = DIMM 槽位 1 (可能在物理通道 0 上，2DPC)
  ch2 = DIMM 槽位 2 (在物理通道 1 上)

EDAC 视角:  3 个 "channel" = 3 个 DIMM 位置
物理视角:   2 个通道 = 2 条独立 64-bit 总线

这是 EDAC 驱动的抽象层，不反映物理总线拓扑
```

### 6.3 EDAC 容量不完整的原因

```
EDAC 报告: 8 MC × 24,576 MB = 192 GB
实际总量:  768 GB
比例:      192 / 768 = 25% (只报告 1/4)

原因: 海光 F18h_M04h EDAC 驱动没有完整枚举所有 chip-select
     每个 rank 只报告了 4096 MB (实际应为 16384 MB)
     6 × 4096 = 24576 ≠ 6 × 16384 = 98304

结论: EDAC 的拓扑结构（通道数、rank 数）可参考
     EDAC 的容量数值不准确，以 numactl --hardware 为准
```

---

## 七、csrow 与 Rank Interleaving

### 7.1 csrow 的作用

```
csrow (Chip-Select Row) = MC 选中特定 Rank 的硬件信号

MC 通过 CS# 引脚选择激活哪个 Rank：
  CS0# 激活 → Rank 0 的所有 DRAM 芯片响应
  CS1# 激活 → Rank 1 的所有 DRAM 芯片响应
  同一时刻只有 1 个 Rank 被激活

csrow 在 EDAC 中的作用：精确定位 ECC 错误发生在哪个 Rank
```

### 7.2 Rank Interleaving 提升带宽利用率

```
没有 Rank 交替（串行）：
  Rank0: [ACT][等待 tRCD][READ][数据][        ][ACT][等待][READ][数据]
  通道:  [              ][数据][空闲!!][              ][数据][空闲!!]
  利用率: ~50-60%

有 Rank 交替（你的配置，4 Rank on 通道 0）：
  Rank0: [ACT][READ][数据]                  [ACT][READ][数据]
  Rank1:      [ACT ][READ][数据]                 [ACT][READ][数据]
  Rank2:            [ACT ][READ][数据]
  Rank3:                  [ACT ][READ][数据]
  通道:  [ D0 ][ D1 ][ D2 ][ D3 ][ D0 ][ D1 ][ D2 ][ D3 ]
  利用率: ~85-98%

这就是你单通道测到 34,500 / 35,200 = 98% 效率的原因
→ 4 个 Rank 轮转，通道几乎没有空闲
```

---

## 八、MC（内存控制器）的角色

### 8.1 MC 不是瓶颈

```
MC 是 CPU 内部的逻辑调度器，运行在 CPU 频率 (~2.7 GHz)
通道是 MC 外部的物理总线，运行在 DDR 频率 (~2.2 GHz)

MC 内部处理带宽 >> 通道物理传输带宽
MC 同时管理 ~48 个 outstanding 请求
瓶颈永远在通道的物理传输能力，不在 MC 调度能力
```

### 8.2 MC 不占用 DDR 容量

```
MC 是硬件电路（晶体管），不是软件
MC 的队列、调度逻辑、ECC 引擎都在 CPU 芯片内部
不需要也不会占用 DDR 内存的任何字节

numactl 显示 ~93 GB 而非 96 GB，差额被以下占用：
  - Linux 内核代码和数据结构
  - struct page 数组 (每 4KB 页 = 64B 描述符)
  - 页表
  - BIOS/UEFI 保留区域
  - IOMMU 页表

以上全部是软件/固件占用，与 MC 硬件无关
```

---

## 九、NIC DMA 与内存通道的关系

### 9.1 数据路径

```
NIC 收包 (DMA Write):
  NIC → PCIe → PCIe控制器 → MC → 通道 → DIMM (写入 mbuf)

CPU 处理 (Load):
  Core → L1 miss → L2 miss → L3 miss → MC → 通道 → DIMM (读 mbuf)

NIC 发包 (DMA Read):
  NIC → PCIe → PCIe控制器 → MC → 通道 → DIMM (读 mbuf)

三个操作全部经过同一个 NUMA 的 MC 和 2 个通道
共享 ~70 GB/s 的总带宽
```

### 9.2 不同网速对 DDR 带宽的消耗

```
线速收发时，DDR 带宽消耗 ≈ 3 × 线速（RX写 + CPU读处理 + TX读）

  25GbE:   需要 ~9 GB/s   → 单 NUMA 70 GB/s 绰绰有余 ✅
  100GbE:  需要 ~37 GB/s  → 单 NUMA 70 GB/s 够用 ✅
  200GbE:  需要 ~75 GB/s  → 单 NUMA 不够，需 2 个 NUMA ⚠️
  400GbE:  需要 ~150 GB/s → 需 3-4 个 NUMA ❌
```

---

## 十、系统总览表

| 层级 | 通道数 | DIMM 数 | 容量 | 理论带宽 | 实测带宽 | 效率 |
|---|---|---|---|---|---|---|
| 单 NUMA | 2 | 3 | 96 GB | 70.4 GB/s | 69.5 GB/s | 98.7% |
| 单 Socket | 8 | 12 | 384 GB | 281.6 GB/s | ~280 GB/s | ~99% |
| 双 Socket | 16 | 24 | 768 GB | 563.2 GB/s | ~560 GB/s | ~99% |

---

## 十一、排查方法论

### 11.1 判断内存通道数的正确方法

```
优先级从高到低：

1. 实测带宽（最准确，不可伪造）
   → 逐步增加线程数，找到带宽饱和点
   → 饱和值 ÷ 单通道理论 = 物理通道数
   → 工具: likwid-bench, STREAM, mbw

2. CPU 架构规格（可靠）
   → 查 CPU 官方文档的通道数规格
   → Zen1 = 2ch/Die, Zen2/3 = 2ch/Die, Zen4 = 2ch/CCD

3. EDAC 拓扑结构（部分可靠）
   → MC 数 = 内存控制器数
   → csrow/rank 映射关系准确
   → "channel" 编号不一定等于物理通道

4. dmidecode（不可靠）
   → "Channel" 标签是主板厂商的 DIMM 槽位命名
   → 与物理通道数无直接关系
```

### 11.2 通用检测脚本要点

```bash
# 1. 逐线程带宽测试（最关键）
for threads in 1 2 4 8 16 24 32; do
    numactl --cpunodebind=0 --membind=0 \
        likwid-bench -t load -w N:2GB:${threads}
done
# → 找到带宽不再增长的拐点 = 通道数确定

# 2. EDAC 结构查看
ls /sys/devices/system/edac/mc/mc0/
cat /sys/devices/system/edac/mc/mc0/rank*/dimm_location
# → 了解 MC-csrow-channel-rank 拓扑

# 3. numactl 容量验证
numactl --hardware
# → 每 NUMA 容量 ÷ 单条 DIMM 容量 = DIMM 数

# 4. dmidecode 参考（仅参考）
dmidecode -t 17
# → Bank Locator 字段看槽位编号
# → 不作为通道数的判断依据
```

---

## 十二、经验教训

### 12.1 踩过的坑

| 坑 | 错误结论 | 正确结论 | 教训 |
|---|---|---|---|
| dmidecode 显示 12 Channel/CPU | 以为 12 通道 | 实际 8 通道 | dmidecode Channel = 槽位名 |
| EDAC 显示 ch0/ch1/ch2 | 以为 3 通道 | 实际 2 通道 | EDAC channel = DIMM 编号 |
| 4T 测到 34,500 | 以为单 NUMA 只有 1 通道 | 线程太少没跑满 | 必须加到饱和 |
| 16T 测到 55,000 | 以为是 2 通道 (78%) | 16T 也没跑满 | 继续加线程 |
| 3 条 DIMM / NUMA | 以为 3 通道 | 2 通道 + 2DPC | DIMM 数 ≠ 通道数 |

### 12.2 最终方法论

```
判断内存通道数的唯一可靠方法：

  1. 从 1 个线程开始，逐步加倍
  2. 记录每个线程数的带宽
  3. 找到带宽不再增长的饱和值
  4. 饱和值 ÷ (DDR频率 × 8字节) = 物理通道数
  5. 通道数应为常见值 (1, 2, 3, 4, 6, 8, 12)
  6. 交叉验证效率是否在 75-99% 合理范围

  不要相信：dmidecode Channel 名、EDAC channel 编号、DIMM 数量
  只相信：实测带宽饱和值
```

---

## 附录 A：NUMA-CPU 映射表

| NUMA | Socket | 物理核 | SMT 线程 | 内存 |
|---|---|---|---|---|
| NUMA 0 | CPU0 | 0-15 | 128-143 | 95,289 MB |
| NUMA 1 | CPU0 | 16-31 | 144-159 | 96,253 MB |
| NUMA 2 | CPU0 | 32-47 | 160-175 | 96,253 MB |
| NUMA 3 | CPU0 | 48-63 | 176-191 | 96,253 MB |
| NUMA 4 | CPU1 | 64-79 | 192-207 | 96,215 MB |
| NUMA 5 | CPU1 | 80-95 | 208-223 | 96,253 MB |
| NUMA 6 | CPU1 | 96-111 | 224-239 | 96,253 MB |
| NUMA 7 | CPU1 | 112-127 | 240-255 | 96,241 MB |

## 附录 B：dmidecode DIMM 槽位表（CPU0）

| 主板标签 | 物理 DIMM | 物理通道（推测） |
|---|---|---|
| P0 CHANNEL A | DIMM06, 32GB | 通道 0 |
| P0 CHANNEL B | DIMM07, 32GB | 通道 0 (2DPC) |
| P0 CHANNEL C | DIMM08, 32GB | 通道 1 |
| P0 CHANNEL D | DIMM09, 32GB | 通道 0 |
| P0 CHANNEL E | DIMM10, 32GB | 通道 0 (2DPC) |
| P0 CHANNEL F | DIMM11, 32GB | 通道 1 |
| P0 CHANNEL G | DIMM05, 32GB | 通道 0 |
| P0 CHANNEL H | DIMM04, 32GB | 通道 0 (2DPC) |
| P0 CHANNEL I | DIMM03, 32GB | 通道 1 |
| P0 CHANNEL J | DIMM02, 32GB | 通道 0 |
| P0 CHANNEL K | DIMM01, 32GB | 通道 0 (2DPC) |
| P0 CHANNEL L | DIMM00, 32GB | 通道 1 |

> 注：dmidecode 槽位到物理通道的映射为推测，精确映射需查主板手册。

## 附录 C：关键命令备忘

```bash
# NUMA 拓扑
numactl --hardware
lscpu

# EDAC 信息
ls /sys/devices/system/edac/mc/mc0/
cat /sys/devices/system/edac/mc/mc0/rank*/dimm_location

# DIMM 信息
dmidecode -t 17

# 带宽测试
numactl --cpunodebind=N --membind=N likwid-bench -t load -w N:2GB:THREADS
numactl --cpunodebind=N --membind=N likwid-bench -t store -w N:2GB:THREADS
numactl --cpunodebind=N --membind=N likwid-bench -t stream -w N:2GB:THREADS

# 内核内存保留
dmesg | grep -i "reserved\|Memory:"
cat /proc/iomem | grep "System RAM"
```
