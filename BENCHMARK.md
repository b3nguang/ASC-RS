# ASC 与 ASC-RS 对比测试

测试日期：2026-09-11

## 环境

- Windows 11 Pro 10.0.26200
- Intel Core i9-13980HX，24 核 / 32 线程
- 内存 63.6 GiB
- 原版 ASC：提交 `47663fd`，Python 3.12.13，Androguard 4.1.4，mutf8 1.1.0
- ASC-RS：release 构建，rustc 1.97.1
- APK：`教程demo(更新).apk`，7,170,387 字节，1 个 DEX
- DEX 内容：6,906 个类，60,485 个方法

原版使用隔离环境 `.venv-asc-original312`。原版引用扫描使用了 Python
3.11 才支持的原子正则组，因此不能在本机原有的 Python 3.10 下运行。

## 性能

每个命令先预热一次，再交替执行两个实现各 7 次。表中为新进程执行的
墙钟时间中位数；系统文件缓存保持预热状态，命令输出被丢弃。线程数均
使用默认值 8。

| 用例 | 原版中位数 | ASC-RS 中位数 | 较快实现 | 7 次范围（原版 / Rust） |
|---|---:|---:|---:|---:|
| `getclass MainActivity` | 224.052 ms | 90.635 ms | Rust 2.47× | 222.567–312.581 / 80.799–124.986 ms |
| `findrefs string FIRST_START` | 448.155 ms | 95.612 ms | Rust 4.69× | 409.216–471.673 / 83.264–104.056 ms |
| `findrefs type SPUtils` | 514.194 ms | 99.727 ms | Rust 5.16× | 496.024–571.285 / 93.579–117.286 ms |
| `findrefs method saveString` | 540.797 ms | 97.856 ms | Rust 5.53× | 508.764–596.709 / 91.334–111.772 ms |
| `findrefs field INSTANCE` | 455.920 ms | 94.558 ms | Rust 4.82× | 448.017–489.600 / 85.561–101.357 ms |

ASC-RS 现已移植原版 `DexManager -> DvmInterpreter/IndexHandler ->
DexHollower -> DexIndexMapper -> DexBuilder` 链路。带内部计时的单次
`getclass` 为：APK 定位与按需类探测约 31.2 ms、抽取与重建约 17.1 ms、
纯 Rust 反编译约 8.1 ms、总计约 56.4 ms；新进程墙钟中位数为 90.6 ms。

原始 `classes.dex` 为 9,054,156 字节。原版最小 DEX 为 6,704 字节，
Rust 最小 DEX 为 6,580 字节。Rust 输出包含 136 个字符串、58 个类型、
41 个原型、7 个字段、49 个方法和 1 个类。旧实现按发现路径分别加入原始
和合成类型，曾产生 31 个重复类型；当前输出会按照 DEX 规范对所有 ID 表
统一排序和去重。它还保留完整中文字符串，写入标准 SHA-1 签名、Adler-32
校验和，修正新 `debug_info_off`，并验证固定表与 data 区互不重叠。

兼容性回归从完整 6,906 个类中等距抽样 100 个类。100 个类均成功完成
规范化最小 DEX 重建、结构校验、独立解析和实际反编译，失败数为 0。

## 引用搜索精准性

以下比较把 ASC-RS 的完整签名归一为原版的“类 + 成员名”表示，再比较去重
后的调用方法集合；ASC-RS 当前输出会继续保留参数、返回类型和字段类型：

| 查询 | 原版 | ASC-RS | 交集 | 差异 |
|---|---:|---:|---:|---:|
| string `FIRST_START` | 1 | 1 | 1 | 0 |
| type `Lcom/zj/wuaipojie/util/SPUtils;` | 1 | 1 | 1 | 0 |
| method `saveString` in `SPUtils` | 1 | 1 | 1 | 0 |
| field `INSTANCE` in `SPUtils` | 7 | 7 | 7 | 0 |
| type `android/content/Context` | 53 | 53 | 53 | 0 |
| method `onCreate` | 107 | 107 | 107 | 0 |
| field `binding` | 7 | 7 | 7 | 0 |

宽字符串查询 `id` 涉及包含换行符的大型正则常量，不能可靠地按物理文本行
比较完整 `matched=(...)` 内容。去掉匹配载荷后，两边均得到完全相同的 835
个调用方法，交集 835，单边差异均为 0。

因此，在这个 APK 上，引用搜索的调用方法集合未发现召回率或误报差异。
ASC-RS 使用真实指令边界遍历；原版使用字节正则扫描后再校验所属方法。

## 会话缓存优化验证

参考 Garlic 的直接缓冲区处理方式和 DexKit 的惰性特征索引后，引用搜索改为
直接读取 DEX 小端 code unit，并在 `AscSession` 内缓存解析元数据、方法描述符
及按引用类型构建的索引。缓存和解压数据使用同一个 LRU 生命周期，并以每个
DEX 独立的加载锁合并并发请求。

优化前后的 release 可执行文件在同一 APK 上交替执行 5 次，首次进程的墙钟
中位数如下。四类搜索均处于约 ±3% 的运行抖动范围，没有以冷启动换取热查询：

| 查询 | 优化前 | 优化后 |
|---|---:|---:|
| string `FIRST_START` | 149.040 ms | 138.720 ms |
| type `SPUtils` | 142.410 ms | 142.160 ms |
| method `saveString` | 146.070 ms | 147.480 ms |
| field `INSTANCE` | 141.130 ms | 144.790 ms |

同一个 release `AscSession` 连续执行相同字符串引用查询时，内部计时的代表性
结果为首次 76.701 ms、热查询 1.117 ms，约快 68.7 倍。窄/宽字符串、类型、
方法和字段共 7 组查询也与优化前版本做了完整文本比较，输出全部逐字一致。

## 批量字符串搜索

新增的 `findrefs ... strings VALUE...` 和 `find_string_references_batch` 使用
Aho-Corasick 在一次 DEX 字符串表遍历中同时匹配多个模式，并复用同一份惰性
字符串引用索引。重复、重叠和空模式仍分别保留结果组。

在同一份已预热的 `AscSession` 中，以 64 个确定不命中的不同模式隔离字符串
匹配成本，批量调用与 64 次逐条调用各交替测量 5 次。批量中位数为
3.018 ms，逐条调用总和中位数为 39.178 ms，批量约快 13.0 倍。该收益会随
模式数量增加；只有一个或少量模式时仍可直接使用原有的 `string` 命令。

## 字符串和反编译质量

- 查询中文字符串 `请先注册id` 时，两边都定位到
  `MainActivity->alertFirst`。
- 原版引用结果把匹配值输出成 `����`；ASC-RS 输出完整中文。
- 原版反编译源码把 `请先注册id` 截断为 `\u8bf7\u5148`（“请先”）；
  ASC-RS 保留完整字符串。
- 原始 DEX 中 `MainActivity` 定义 7 个方法。两边现在均输出 7 个；ASC-RS
  会补回纯 Rust 后端默认隐藏的 R8 合成桥接方法。
- 原版 DAD 输出的控制流和调用表达式整体更清晰。当前 Rust `simple` 输出
  更接近线性 IR，仍存在 `local0`、省略参数和部分错误类型推断。两边输出
  都不能直接作为可编译 Java 使用。

## WPS Office 大型 multidex 三方测试

为验证前述结论在大型多 DEX APK 上是否仍成立，使用用户提供的 WPS Office
样本补充测试 ASC-RS、原版 ASC 和独立 JADX CLI。测试时间为 2026-09-11。

### 样本与环境

- APK：`moffice_26.9.0_0x0804_cn00563_multidex_64_0c8b155ab49.apk`
- SHA-256：`485B1E850C0F4AC85424717570A687082F232E3D30C967319B89277F718FFEF8`
- APK 大小：189,203,175 字节（180.44 MiB）
- 根 DEX：27 个，解压后合计 221.33 MiB
- 类定义：217,837 个
- 包名：`cn.wps.moffice_eng`
- 已启用的 launcher alias 指向
  `cn.wps.moffice.documentmanager.PreStartActivity`；目标类位于
  `classes25.dex`
- ASC-RS：基于提交 `7ce2dbd` 的本次优化版，rustc 1.97.1，内置 Rust
  反编译器
- 原版 ASC：提交 `47663fd`，Python 3.12.13，Androguard 4.1.4
- JADX：1.5.5，OpenJDK 11.0.30
- 机器：Windows 11 Pro 10.0.26200，Intel Core i9-13980HX，32 逻辑处理器，
  63.6 GiB 内存

每个用例先预热一次，再启动全新进程交替执行 5 次。三者都设置为 8 个工作
线程，系统文件缓存保持预热，输出被丢弃。表中是墙钟时间中位数与 5 次范围。
JADX 使用 `--single-class --no-res`，只输出同一个目标类，不把资源解码或全 APK
源码导出时间混入三方对比。

### 原版策略移植与单类按需反编译

初测暴露出两个瓶颈：ASC-RS 通过 `ZipArchive` 扫描 189 MB APK 的全部 ZIP
元数据，而且按 DEX 序号顺序完整解压、建立所有类描述符后才继续查找。优化版
按原版 ASC 的路径改为：

1. APK 只读 `mmap`，直接解析 EOCD、中央目录和本地文件头；
2. 根 DEX 按压缩后大小排序并行探测，命中后用共享取消标志终止其余解压；
3. Deflate 直接读取 mmap 中的压缩片段，并以 512 KiB 输出块检查取消；
4. 每个 DEX 只对有序 type 表二分查找目标描述符，再探测 class_defs，不为
   单类查询建立完整类名索引。

同一机器上重新交替执行优化版和原版各 5 次，结果如下。JADX 一列沿用同一轮
测试中未发生代码变化的 1.5.5 数据：

| 目标 | 优化前 ASC-RS | 优化后 ASC-RS | 原版 ASC | JADX single-class |
|---|---:|---:|---:|---:|
| `classes.dex` 中的 `cn.wps.sdk.fcsync.Fcsync` | 2,139.114 ms | 229.526 ms（206.997–244.393） | 634.405 ms（620.659–718.599） | 未重复测量 |
| `classes25.dex` 中的 launcher `PreStartActivity` | 25,928.727 ms | 101.944 ms（87.516–180.617） | 280.343 ms（258.216–281.882） | 38,129.376 ms（37,004.277–40,451.506） |

优化后两个位置的类查询分别比原版快 2.76 倍和 2.75 倍；launcher 查询相对
优化前缩短约 254 倍。launcher 的一次内部计时为 APK 定位/探测 21.895 ms、
单类抽取与重建 16.302 ms、内置反编译 0.889 ms、合计 39.085 ms。剩余墙钟
时间主要是新进程启动和清理，而不再是 ZIP 扫描或无关 DEX 的类索引。

### 全局引用搜索

统一执行以下语义相同的查询：

```text
findrefs APK type PreStartActivity
```

| 实现 | 中位数 | 5 次范围 |
|---|---:|---:|
| 优化前 ASC-RS | 11,240.794 ms | 10,719.291–12,000.966 ms |
| 优化后 ASC-RS | 392.576 ms | 378.017–439.852 ms |
| 原版 ASC | 1,244.885 ms | 1,231.865–1,322.096 ms |

优化版比自身初测缩短约 28.6 倍，比原版快 3.17 倍。一次内部计时为 27 个 DEX
加载/解析 199.347 ms、引用扫描 25.826 ms、总计 225.173 ms。两边仍都返回
61 个唯一调用方法；把 ASC-RS 的完整签名归一成原版格式后，集合差异为 0。

另外用 WPS 样本覆盖了其余三类定位器：string `PreStartActivity` 为 29/29、
method `startActivity` in `android.app.Activity` 为 293/293、目标 launcher 类的
全部 field 引用为 3/3，三组调用者集合的双向差异均为 0。JADX CLI 没有与
`findrefs` 等价的无索引命令，因此没有把“全量反编译后文本搜索”冒充成同一
用例。

物理 DEX 041 容器也按原版策略拆分为独立逻辑 DEX；解析时保留共享物理缓冲区
和绝对偏移，避免为每个逻辑头复制整个容器。

完整的可复跑命令位于 `scripts/compare-moffice.ps1`。例如：

```powershell
.\scripts\compare-moffice.ps1 -Runs 5
```

### 大型 multidex 测试结论

WPS 初测发现的两个数量级瓶颈已经消除。移植原版的 mmap ZIP/Deflate 与并行
按需探测策略后，ASC-RS 在两个单类位置及全局引用搜索三项均快于当前原版，
同时保留精确相同的归一化调用者集合。相比为整包建立数据库式全局索引，这条
路径继续保持按查询付费和会话内缓存的设计。

## 结论

- 在前述单 DEX Demo 上，ASC-RS 的引用搜索调用方法集合一致，速度约快
  4.7–5.5 倍，并且
  Unicode 匹配文本更准确。
- 在该单 DEX Demo 上，ASC-RS 单类反编译按原版流程先重建最小 DEX，新进程
  测试快约 2.47 倍；原版 DAD 的源码可读性仍更好，Rust 后端则能保留完整
  中文。
- ASC-RS 默认引擎全程为 Rust，无 Python、JVM 或 JADX 运行时；大型
  multidex 中原先落后的类定位和全局引用搜索现已分别快于原版约 2.75 倍和
  3.17 倍。需要更高层 Java 重建质量时，仍可显式切换到外部 JADX 引擎。
