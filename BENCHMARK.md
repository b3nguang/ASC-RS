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
| `getclass MainActivity` | 198.040 ms | 142.990 ms | Rust 1.38× | 194.685–203.533 / 138.141–155.939 ms |
| `findrefs string FIRST_START` | 373.220 ms | 138.790 ms | Rust 2.69× | 363.321–392.755 / 135.167–140.627 ms |
| `findrefs type SPUtils` | 407.240 ms | 138.490 ms | Rust 2.94× | 397.365–428.722 / 134.239–151.884 ms |
| `findrefs method saveString` | 436.960 ms | 140.130 ms | Rust 3.12× | 431.506–450.356 / 139.003–149.376 ms |
| `findrefs field INSTANCE` | 427.310 ms | 140.310 ms | Rust 3.05× | 423.749–447.579 / 137.728–140.716 ms |

ASC-RS 现已移植原版 `DexManager -> DvmInterpreter/IndexHandler ->
DexHollower -> DexIndexMapper -> DexBuilder` 链路。带内部计时的单次
`getclass` 为：APK 定位与按需类索引约 57.2 ms、抽取与重建约 15.6 ms、
纯 Rust 反编译约 7.4 ms、总计约 80.2 ms；新进程墙钟中位数为 143.0 ms。

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

## 结论

- 引用搜索：ASC-RS 在本样本上调用方法集合一致，速度约快 2.7–3.1 倍，并且
  Unicode 匹配文本更准确。
- 单类反编译：ASC-RS 已按原版流程先重建单类最小 DEX，新进程测试快约
  1.38 倍；原版 DAD 的源码可读性仍更好，Rust 后端则能保留完整中文。
- ASC-RS 全程为 Rust，无 Python、JVM 或 JADX 运行时；本样本的命令行核心
  在速度和引用搜索结果上均已达到或超过原版。
