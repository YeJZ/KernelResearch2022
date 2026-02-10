# OpenHarmony 全版本安全审计：扫描策略与漏洞分析报告

**OpenHarmony（含6.0）面临的最大安全风险集中在五个核心领域：ArkCompiler运行时引擎、分布式软总线（DSoftBus）、多媒体解析框架、HDF驱动框架以及内核子系统。** 基于对2022-2025年Android安全公告（累计500-700+ CVE）、Google Project Zero野外0-day追踪（2024年75个0-day）、OpenHarmony已披露的90余个CVE以及完整架构分析的四维交叉研究，本报告识别出TOP 20优先扫描目标，并为每个目标提供精确的漏洞模式与AI扫描技能描述。核心发现：**use-after-free占野外利用漏洞的首位，内存安全类漏洞占所有0-day的68%**，而OpenHarmony特有的分布式架构显著扩大了传统移动OS不具备的跨设备攻击面。

---

## 一、TOP 20 优先扫描目标清单

以下排序综合四维数据：Android CVE热度、OpenHarmony已知漏洞密度、Project Zero野外利用趋势、以及架构风险评估。

| 排名 | 模块名称 | 仓库路径 | 风险等级 | 主要语言 | 核心理由 |
|------|---------|---------|---------|---------|---------|
| **1** | ArkCompiler ETS Runtime | `arkcompiler/ets_runtime` | **🔴 Critical** | C++ | OpenHarmony CVE最多的模块（15+ CVE），多个CVSS 8.2+ RCE，OOB write/UAF导致预装应用任意代码执行 |
| **2** | DSoftBus 分布式软总线 | `foundation/communication/dsoftbus` | **🔴 Critical** | C | 网络面向、多协议栈（CoAP/BLE/BR/TCP）、已有认证绕过CVE-2022-38064（Critical）、整数溢出CVE-2024-21845 |
| **3** | Multimedia Player Framework | `foundation/multimedia/player_framework` | **🔴 Critical** | C++ | 媒体解析是零点击攻击的首要入口（Samsung Quram/BLASTPASS），依赖FFmpeg，解析MP4/MKV/MP3等复杂格式 |
| **4** | HDF驱动框架 | `drivers/hdf_core` | **🔴 Critical** | C | 内核态代码，CVE-2022-42464（CVSS 9.8）内核内存池覆写，CVE-2022-44470 OOB读写，IOCTL接口暴露 |
| **5** | Kernel LiteOS-A | `kernel/liteos_a` | **🔴 Critical** | C | 10+ CVE，UAF→root提权（CVE-2024-41157），double free（CVE-2024-47404），futex内存写绕过（CVE-2025-31172/31173） |
| **6** | Linux Kernel 5.10 | `kernel/linux_5.10` | **🔴 Critical** | C | Android野外利用重灾区：USB驱动（CVE-2024-53104 Cellebrite利用）、网络子系统、ALSA兼容层竞态条件 |
| **7** | IPC/RPC通信机制 | `foundation/communication/ipc` | **🟠 High** | C++ | 核心信任边界，类Binder协议，序列化/反序列化漏洞，所有系统服务依赖IPC，Android Binder持续产出EoP CVE |
| **8** | Multimedia Image Framework | `foundation/multimedia/image_framework` | **🟠 High** | C++ | 图片解析（PNG/JPEG/WebP/HEIF/RAW），依赖libpng/libjpeg-turbo/libwebp，零点击图片利用是2024-2025最活跃攻击模式 |
| **9** | Communication Bluetooth | `foundation/communication/bluetooth` | **🟠 High** | C/C++ | Android蓝牙栈是Critical RCE第一大来源（80-120+ CVE），SDP协议UAF持续出现，零点击远程攻击向量 |
| **10** | ArkUI ACE Engine | `foundation/arkui/ace_engine` | **🟠 High** | C++ | 类型混淆CVE-2023-0083，SVG解析缓冲区溢出CVE-2024-58115/58116，处理不受信UI声明与图片渲染 |
| **11** | third_party_ffmpeg | `third_party/ffmpeg` | **🟠 High** | C | 历史CVE数百个，音视频编解码/解封装核心，缓冲区溢出/整数溢出/堆溢出高发模块 |
| **12** | Graphic 2D渲染引擎 | `foundation/graphic/graphic_2d` | **🟠 High** | C++ | GPU命令处理、共享内存缓冲区管理、Surface合成，GPU驱动是Project Zero追踪的#1第三方内核攻击面 |
| **13** | Peripheral Drivers | `drivers/peripheral` | **🟠 High** | C/C++ | Display/Audio/Camera/Codec/USB外设驱动，HDI接口跨用户态-内核态，OpenMAX IL编解码缓冲区管理 |
| **14** | Security Access Token | `base/security/access_token` | **🟠 High** | C++ | 权限验证核心，绕过=提权，CVE-2022-38081权限绕过，分布式token同步机制 |
| **15** | Communication Wi-Fi | `foundation/communication/wifi` | **🟠 High** | C/C++ | WiFi管理帧处理（CVE-2024-45569 CVSS 9.8），wpa_supplicant集成，P2P/热点连接处理 |
| **16** | Startup AppSpawn | `startup/appspawn` | **🟠 High** | C/C++ | 缓冲区溢出CVE-2022-38701→任意应用代码执行，路径穿越CVE-2022-43662→沙箱逃逸，所有应用进程启动器 |
| **17** | Distributed Data Manager | `foundation/distributeddatamgr/datamgr_service` | **🟡 Medium-High** | C++ | 跨设备数据同步、分布式KV存储、UDMF统一数据框架，跨设备信任边界 |
| **18** | DFS分布式文件系统 | `filemanagement/dfs_service` | **🟡 Medium-High** | C++ | 路径穿越CVE-2025-31174，HMDFS内核级跨设备文件访问，文件权限跨设备一致性 |
| **19** | Multimedia AV Codec | `multimedia/av_codec` | **🟡 Medium-High** | C++ | 硬件/软件编解码接口（H.264/H.265/AV1），OpenMAX IL HDI，畸形码流处理 |
| **20** | third_party_openssl + mbedtls | `third_party/openssl`, `third_party/mbedtls` | **🟡 Medium-High** | C | TLS/密码学基础设施，CVE-2024-28836/28960，密钥派生/证书解析/握手协议 |

---

## 二、各模块热点漏洞模式详细分析

### 2.1 ArkCompiler ETS Runtime（排名#1）

**已知漏洞模式分布：** OOB Write（~35%）、UAF（~25%）、OOB Read（~20%）、Stack Overflow（~10%）、Type Confusion（~10%）

这是OpenHarmony当前CVE密度最高的模块。ArkTS运行时作为新语言的新引擎，尚未经历V8/JavaScriptCore数十年的安全加固。多个CVE允许在预装应用中远程执行任意代码（CVSS 8.2-8.4），攻击者可通过构造恶意ArkTS字节码或触发JIT编译器缺陷实现利用。

**热点漏洞模式：**

- **Out-of-bounds Write/Read** — CVE-2024-36243、CVE-2024-36260、CVE-2024-38386、CVE-2025-27132均为此类，发生在数组操作、TypedArray处理、字节码解释器中
- **Use-after-free** — CVE-2024-37030，垃圾回收器（GC）与运行时对象引用之间的生命周期管理缺陷
- **Type Confusion** — CVE-2024-31071，ArkTS的类型系统与底层C++对象表示不一致
- **Stack Overflow** — CVE-2024-29086，递归深度未限制导致栈溢出
- **Integer Overflow** — CVE-2025-20024，整数溢出导致预装应用任意代码执行

### 2.2 DSoftBus 分布式软总线（排名#2）

**已知漏洞模式分布：** Authentication Bypass（~25%）、Integer Overflow→Heap Overflow（~20%）、Deserialization（~15%）、Incomplete Validation（~20%）、Memory Leak（~10%）、Logic Bug（~10%）

DSoftBus是OpenHarmony独有的最大攻击面。它同时暴露蓝牙、WiFi、NFC和以太网的网络接口，实现零配置设备发现与连接。其`core/`目录下的authentication、bus_center、connection、discovery、transmission五个子模块均处理来自不受信对端的网络数据。

**热点漏洞模式：**

- **Authentication Bypass** — CVE-2022-38064通过蓝牙rfcomm包绕过认证，在分布式网络中执行任意命令
- **Integer Overflow → Heap Overflow** — CVE-2024-21845，NFC协议中整数溢出导致堆溢出
- **Deserialization Mismatch** — CVE-2025-31175，序列化/反序列化不一致
- **Incomplete Data Verification** — CVE-2024-21863，软总线数据验证不完整导致DoS
- **Memory Leak** — CVE-2025-20011，内存未释放

### 2.3 Multimedia Player Framework（排名#3）

**预测漏洞模式分布：** Buffer Overflow（~30%）、Integer Overflow（~25%）、OOB Read/Write（~20%）、UAF（~15%）、Null Pointer Dereference（~10%）

基于Android Media Framework的CVE历史（Stagefright时代产生了移动安全史上最严重的漏洞），以及Samsung Quram库零点击利用（CVE-2025-21042 DNG解析OOB Write通过WhatsApp投递LANDFALL间谍软件），多媒体解析是零点击攻击的首要入口。OpenHarmony的player_framework依赖FFmpeg进行解封装和编解码，解析MP4、MKV、MP3、AAC、FLAC、WAV、OGG、MPEG-TS等容器格式。

**热点漏洞模式：**

- **Heap Buffer Overflow** — 媒体容器解析中的chunk size/sample size字段未正确校验
- **Integer Overflow** — 计算buffer大小时整数溢出导致小buffer分配→后续写入溢出
- **OOB Read/Write** — 解封装器处理malformed atom/box时的越界访问
- **UAF** — MediaCodec buffer管理中的异步回调导致生命周期错误
- **Format String** — 日志输出中直接使用用户可控的metadata字符串

### 2.4 HDF驱动框架（排名#4）

**已知漏洞模式分布：** Kernel Memory Pool Override（~30%）、OOB Read/Write（~30%）、IOCTL Input Validation（~25%）、Privilege Escalation Logic（~15%）

HDF作为统一驱动接口框架，其Bind()→Init()→Release()驱动入口模式和HdfIoService用户-内核通信接口是关键攻击面。CVE-2022-42464（CVSS 9.8）证明`/dev/mmz_userdev`设备驱动中存在内核内存池覆写可导致代码执行和root权限获取。

**热点漏洞模式：**

- **IOCTL Handler缺陷** — 用户态传入的IOCTL参数未充分校验，直接用于内核内存操作
- **OOB Read/Write** — CVE-2022-44470，设备驱动中越界读写导致信息泄露和内存破坏
- **Race Condition** — 驱动加载/卸载过程中的并发访问
- **Missing Bounds Check** — HDI接口传递的buffer size未校验
- **Null Pointer Dereference** — 驱动Release()时对象已释放但仍被访问

### 2.5 Kernel LiteOS-A（排名#5）

**已知漏洞模式分布：** UAF（~25%）、Double Free（~15%）、Integer Overflow（~15%）、Stack Overflow（~10%）、Memory Write Permission Bypass（~20%）、File Permission Bypass（~15%）

LiteOS-A是OpenHarmony小型系统的定制RTOS内核，其POSIX兼容实现和自定义系统调用是漏洞高发区。与Linux内核相比，LiteOS-A缺乏同等程度的安全加固（ASLR/栈canary在IoT设备上可能不完整）。

**热点漏洞模式：**

- **UAF** — CVE-2024-41157，内核级UAF→local root提权
- **Double Free** — CVE-2024-47404，double free→提权+信息泄露
- **Futex Memory Write Bypass** — CVE-2025-31172/31173，futex模块中内存写权限绕过
- **File System Permission Bypass** — CVE-2025-31171，文件读权限绕过
- **Stack Overflow** — CVE-2022-45126，SysClockGettime中栈溢出导致4字节内核数据泄露
- **Integer Overflow** — CVE-2024-28044

### 2.6 Linux Kernel 5.10（排名#6）

**野外利用热点：** USB驱动（CVE-2024-53104 Cellebrite利用）、网络子系统（CVE-2024-36971）、ALSA兼容层（CVE-2023-0266竞态条件）、POSIX CPU定时器（CVE-2025-38352竞态条件）、Netfilter（CVE-2024-1086 UAF）

**热点漏洞模式：**

- **UAF** — netfilter/nftables、ALSA、驱动子系统中最常见
- **Race Condition** — 32位兼容层代码、POSIX定时器、文件系统操作中的TOCTOU
- **OOB Write** — USB Video Class驱动中帧大小校验不足（CVE-2024-53104）
- **Integer Overflow** — VBO IOMMU（CVE-2024-23372，Adreno GPU）
- **Null Pointer Dereference** — 异常路径下的空指针解引用

### 2.7 IPC/RPC通信机制（排名#7）

**预测漏洞模式分布：** Deserialization（~30%）、Logic Bug/Permission Bypass（~30%）、Type Confusion（~15%）、Buffer Overflow in Parcel（~15%）、Race Condition（~10%）

**热点漏洞模式：**

- **Deserialization漏洞** — Parcel反序列化时类型校验不严格，可构造恶意Parcel数据
- **Permission Bypass** — Binder调用方UID/PID校验逻辑缺陷，confused deputy攻击
- **Type Confusion** — IPC传递对象时类型检查不一致
- **Buffer Overflow** — Parcel数据包大小计算错误

### 2.8 Image Framework（排名#8）

**预测漏洞模式分布：** Buffer Overflow（~35%）、Integer Overflow（~25%）、OOB Read（~20%）、Heap Overflow（~15%）、Null Deref（~5%）

**热点漏洞模式：**

- **Heap Buffer Overflow** — PNG chunk处理、JPEG marker解析、WebP VP8解码中的缓冲区溢出
- **Integer Overflow** — 图片宽高计算溢出导致小buffer分配（经典CVE-2023-4863 libwebp模式）
- **OOB Read** — EXIF/ICC profile解析中的越界读取
- **UAF** — 图片解码回调异步操作中的生命周期错误

### 2.9 Bluetooth（排名#9）

**Android CVE热度：** 80-120+ CVE（2022-2025），是Critical RCE第一大来源

**热点漏洞模式：**

- **UAF in SDP** — Android sdp_discovery.cc/sdp_server.cc中反复出现UAF，OpenHarmony蓝牙栈若共享类似代码逻辑则面临同样风险
- **OOB Write** — L2CAP/AVDTP协议包解析中的越界写
- **Integer Overflow** — 协议字段长度计算溢出
- **Type Confusion** — 蓝牙配置文件（A2DP/HFP/AVRCP）中的类型混淆
- **Zero-Click RCE** — CVE-2023-45866蓝牙键盘注入，无需配对

### 2.10-2.20 其余模块概要

| 模块 | 核心漏洞模式 |
|------|------------|
| **ArkUI ACE Engine** | Type confusion、SVG/XML解析buffer overflow、XComponent渲染UAF |
| **FFmpeg** | Integer overflow→heap overflow（codec解析）、OOB write（demuxer）、格式字符串 |
| **Graphic 2D** | GPU命令UAF、共享内存竞态条件、Surface composition OOB |
| **Peripheral Drivers** | IOCTL handler OOB、codec buffer管理UAF、USB热插拔竞态 |
| **Access Token** | Permission bypass逻辑漏洞、distributed token同步不一致 |
| **Wi-Fi** | Management frame内存破坏、wpa_supplicant认证绕过、P2P协商OOB |
| **AppSpawn** | Buffer overflow（CVE-2022-38701）、path traversal（CVE-2022-43662）、进程创建竞态 |
| **Distributed Data Mgr** | 跨设备数据同步反序列化、distributed transaction竞态条件 |
| **DFS** | Path traversal（CVE-2025-31174）、HMDFS权限模型跨设备不一致 |
| **AV Codec** | Malformed bitstream OOB write、OpenMAX IL buffer管理UAF、codec状态机逻辑错误 |
| **OpenSSL/mbedTLS** | 证书解析OOB read、握手协议状态机逻辑错误、侧信道 |

---

## 三、SKILL描述：每种漏洞模式的AI扫描技能

以下为每种热点漏洞模式提供详细的SOTA AI模型代码扫描技能描述（Skill Description），指导扫描引擎精确定位高风险代码路径。

### SKILL 1: Use-After-Free (UAF) 检测

**适用模块：** ArkCompiler、Kernel LiteOS-A、Linux Kernel、HDF、Bluetooth、Multimedia、IPC

```
扫描策略：
1. 追踪所有 malloc/calloc/new 分配与 free/delete 释放的配对关系。重点关注：
   - 释放后指针未置NULL的情况（dangling pointer）
   - 回调函数/异步操作中持有的对象引用在回调执行时对象已被释放
   - C++ shared_ptr/unique_ptr的不当使用：raw pointer从smart pointer提取后，smart pointer被销毁
   
2. 特别关注以下模式：
   - 事件循环/消息队列中：对象注册回调后被销毁，回调触发时访问已释放内存
   - 引用计数错误：RefBase/RefCounted类的引用计数减少到0后仍有引用持有
   - 多线程场景：线程A释放对象，线程B仍在使用（无同步保护）
   - GC相关（ArkCompiler）：GC标记阶段与mutator线程的竞态，native pointer wrap的弱引用失效
   - 容器元素删除后迭代器失效（见SKILL 8）
   
3. 高风险函数签名模式：
   - void Callback(void* userData) 中 userData 指向的对象可能已被释放
   - destructor/Release() 中释放资源后，其他成员函数仍可能被调用
   - Close()/Disconnect()/Stop() 异步完成，但调用方立即释放对象

4. OpenHarmony特有：
   - HDF驱动中 HdfDeviceObject 的生命周期管理
   - IPC Stub/Proxy中 RemoteObject 的引用计数
   - DSoftBus Session关闭时的异步回调处理
```

### SKILL 2: Buffer Overflow / Heap Overflow 检测

**适用模块：** Multimedia、FFmpeg、Image Framework、AppSpawn、HDF、Bluetooth、ArkUI SVG解析

```
扫描策略：
1. 识别所有内存拷贝操作并验证边界检查：
   - memcpy(dst, src, len) / memmove / strcpy / strncpy / sprintf / snprintf
   - 检查 len 是否来自外部输入（文件头字段、网络包字段、IPC parcel字段）
   - 检查 dst buffer的分配大小是否≥len
   
2. 文件解析场景（多媒体重点）：
   - 解析容器格式（MP4 atom/box、MKV EBML、PNG chunk）时：
     * box/atom 的 size 字段是否被信任用于分配buffer？是否有上限检查？
     * 嵌套结构中内部元素的长度是否超过外部容器的剩余长度？
   - 图片解析：width × height × bpp 计算像素buffer大小时是否溢出？（见SKILL 3）
   
3. 协议解析场景（Bluetooth/WiFi/NFC/DSoftBus）：
   - 协议包长度字段是否信任？是否有最大值校验？
   - 变长字段（TLV格式）的 length 字段是否用于直接分配？
   - SDP/L2CAP/AVDTP协议响应解析中的多级嵌套长度校验
   
4. 栈缓冲区溢出：
   - 固定大小的栈数组（char buf[256]）接收可变长度输入
   - 递归深度无限制导致栈耗尽
   - alloca() 使用不安全的用户输入作为参数

5. OpenHarmony特有：
   - HDF IOCTL handler中用户态传入的buffer size用于内核内存操作
   - AppSpawn中sandbox路径构造的buffer大小
   - ArkUI SVG解析器中path data/viewBox属性的长度
```

### SKILL 3: Integer Overflow / Underflow 检测

**适用模块：** Multimedia、Image Framework、DSoftBus NFC协议、Kernel LiteOS-A、ArkCompiler、FFmpeg

```
扫描策略：
1. 关注所有用于内存分配大小计算的算术运算：
   - size = width * height * channels * bytesPerChannel — 经典图片解码溢出模式
   - size = count * sizeof(element) — 数组分配大小计算
   - offset + length > total — 检查是否在offset和length都很大时发生回绕
   
2. 具体检查点：
   - 乘法溢出：两个32位值相乘结果超过32位/64位范围
   - 加法溢出：size + padding / size + header_size 回绕为小值
   - 减法下溢：unsigned subtraction 结果变为极大值
   - 类型截断：64位值赋给32位变量、size_t赋给int
   
3. 安全检查模式识别：
   - 有无使用 __builtin_mul_overflow / __builtin_add_overflow？
   - 有无使用 SafeInt / CheckedNumeric 类？
   - 分配前是否有 if (a > SIZE_MAX / b) 类型的溢出检查？
   
4. 高风险场景：
   - CVE-2024-21845模式：DSoftBus NFC协议中整数溢出→堆溢出
   - CVE-2024-28044模式：LiteOS-A内核中整数溢出→崩溃
   - CVE-2025-20024模式：整数溢出→预装应用任意代码执行
   - FFmpeg解封装器中sample_count/chunk_offset的计算
   - 图片EXIF数据中的IFD entry count × entry size

5. OpenHarmony特有：
   - ArkCompiler中TypedArray的byteOffset和byteLength计算
   - IPC Parcel中数据长度字段的算术运算
   - DSoftBus传输层的segment size计算
```

### SKILL 4: Type Confusion 检测

**适用模块：** ArkCompiler、ArkUI、IPC/RPC、Bluetooth、Chromium/ArkWeb

```
扫描策略：
1. C++多态/继承场景：
   - static_cast 用于向下转型且无动态类型检查（应用dynamic_cast或typeid）
   - reinterpret_cast 将不相关类型互相转换
   - void* 转换为具体类型时无验证
   - union类型中不同成员的混用（C风格多态）
   
2. JIT编译器/运行时（ArkCompiler重点）：
   - JIT编译器生成的代码假设了错误的对象类型/布局
   - Speculative optimization中类型守卫（type guard）被绕过
   - Inline cache miss导致错误的方法分派
   - ArkTS中 as 强制类型转换的底层实现是否真正校验类型
   
3. IPC/序列化场景：
   - Parcel中读取的类型标记与实际数据不匹配
   - readInt32() 读取的类型ID用于构造不同类型的对象
   - 服务端信任客户端声称的对象类型
   
4. 蓝牙协议：
   - SDP attribute解析中不同attribute类型的混用
   - Profile-specific数据结构的类型转换
   
5. CVE参考模式：
   - CVE-2024-31071（ArkUI type confusion → crash）
   - CVE-2023-0083（ArkUI type confusion → local crash）
   - CVE-2022-4262（Chrome V8 type confusion → RCE，Project Zero跟踪的利用链）
```

### SKILL 5: Race Condition / Data Race 检测

**适用模块：** Linux Kernel、LiteOS-A、HDF、DSoftBus、Graphic 2D、Peripheral Drivers、IPC

```
扫描策略：
1. 共享可变状态识别：
   - 全局变量/静态变量被多线程访问但无mutex/lock保护
   - 成员变量在多线程回调中被修改
   - 原子操作与非原子操作混合使用于同一数据
   
2. TOCTOU（Time-of-Check-Time-of-Use）：
   - if (file_exists(path)) { open(path) } — 检查和使用之间文件可能被替换
   - if (permission_check()) { do_operation() } — 权限检查后对象状态可能改变
   - stat() + open() 组合，或 access() + open() 组合
   
3. 内核特有竞态：
   - CVE-2025-38352模式：POSIX CPU定时器中的竞态条件
   - CVE-2023-0266模式：ALSA 32位兼容层中的竞态
   - ioctl与驱动卸载之间的竞态（use-after-unregister）
   - 中断处理程序与进程上下文之间的竞态
   
4. 锁相关问题：
   - 死锁：多把锁的获取顺序不一致
   - 锁范围不足：critical section太小，不能保护完整的原子操作
   - 读写锁降级/升级中的窗口期
   - spin_lock在可能睡眠的路径上使用
   
5. OpenHarmony特有：
   - DSoftBus连接管理中的并发连接/断开
   - HDF驱动热插拔与IOCTL处理的竞态
   - IPC线程池中的请求处理竞态
   - Graphic RenderService中Surface buffer的生产者-消费者竞态
```

### SKILL 6: C++ Iterator Invalidation 检测

**适用模块：** ArkUI、IPC、DSoftBus、Ability Framework、Distributed Data Mgr

```
扫描策略：
1. 识别STL容器在迭代期间被修改的模式：
   - for (auto it = vec.begin(); it != vec.end(); ++it) 循环体内调用 vec.erase() / vec.push_back() / vec.insert()
   - range-based for循环中修改被迭代的容器
   - std::map/set 的 erase 返回值未用于更新迭代器
   
2. 间接修改：
   - 迭代期间调用的函数（尤其是回调函数/虚函数）内部修改了被迭代的容器
   - 事件处理循环中，handler回调注册/注销新的handler到同一个容器
   - Observer模式：通知observer时，observer的回调中添加/删除observer
   
3. 并发迭代：
   - 一个线程迭代容器，另一个线程修改容器（无锁）
   - 使用 std::vector 作为线程安全队列但不保护迭代操作
   
4. OpenHarmony特有：
   - DSoftBus中设备列表（deviceList）在discovery/connection回调中被修改
   - Ability Framework中extension列表在生命周期回调中被修改
   - IPC注册的callback列表在通知过程中被添加/删除
```

### SKILL 7: Logic Bug / Permission Bypass / Authentication Bypass 检测

**适用模块：** Security Access Token、DSoftBus Authentication、Ability Framework、IPC、AppSpawn、DFS

```
扫描策略：
1. 权限检查逻辑：
   - 权限检查是否在所有代码路径上执行？（是否存在绕过分支？）
   - 权限检查的结果是否被正确使用？（检查后是否仍然执行了操作？）
   - 是否存在 "先操作后检查" 而非 "先检查后操作" 的模式？
   - 分布式场景：本地权限检查是否适用于远程请求？
   
2. 路径穿越：
   - 文件路径中是否过滤了 "../" ？是否处理了URL编码的 "%2e%2e%2f"？
   - CVE-2022-43662（AppSpawn路径穿越→沙箱逃逸）模式
   - CVE-2025-31174（DFS路径穿越）模式
   - 符号链接跟随：是否在沙箱边界内解析符号链接？
   
3. 认证绕过：
   - CVE-2022-38064模式：DSoftBus蓝牙rfcomm认证绕过
   - 设备配对/认证协议中是否可跳过某些步骤？
   - PIN/密码是否明文传输？（CVE显示OpenHarmony曾有此问题）
   - 分布式设备信任建立是否可被中间人攻击？
   
4. Confused Deputy：
   - 高权限服务是否在处理低权限客户端请求时使用了自己的权限？
   - IPC Binder调用中是否正确验证了调用方的UID/PID？
   - Intent/Ability跳转中是否可以绕过权限检查？
   
5. OpenHarmony特有：
   - Access Token的分布式同步是否可被伪造？
   - Ability Framework中跨设备ability调用的权限传播
   - param service（CVE-2022-42488）缺少权限校验→禁用安全特性
```

### SKILL 8: Format String Vulnerability 检测

**适用模块：** Multimedia、DSoftBus日志、HDF驱动日志、Legacy C代码

```
扫描策略：
1. 直接搜索危险函数调用模式：
   - printf(user_input) / sprintf(buf, user_input) / fprintf(fd, user_input)
   - HILOG_INFO(LOG_CORE, user_controlled_string) — OpenHarmony日志宏
   - syslog(priority, user_input)
   
2. 间接模式：
   - 日志函数封装中，格式字符串参数来自外部：
     void LogMsg(const char* msg) { HILOG_INFO(LOG_CORE, msg); }
   - 错误消息模板从配置文件/网络读取
   
3. 元数据场景：
   - 媒体文件中的title/artist/album等metadata字段用于日志输出
   - Bluetooth设备名称用于日志/UI显示
   - 网络设备发现消息中的设备名用于格式化输出
```

### SKILL 9: Null Pointer Dereference 检测

**适用模块：** 所有C/C++模块

```
扫描策略：
1. malloc/new 返回值未检查：
   - void* p = malloc(size); p->field = value; // 未检查p==NULL
   - 特别关注分配失败路径上的所有解引用
   
2. 函数返回值未检查：
   - GetService() / FindDevice() / LookupSession() 返回NULL但调用方未检查
   - IPC GetRemoteProxy() 返回nullptr时的处理
   
3. 错误路径上的空指针：
   - try-catch/goto-cleanup路径上使用了可能未初始化的指针
   - 析构函数中访问可能未成功初始化的成员
   
4. 竞态导致的空指针：
   - 成员变量被另一个线程置NULL，当前线程仍在使用
```

### SKILL 10: Deserialization Vulnerability 检测

**适用模块：** IPC/RPC、DSoftBus、Distributed Data Mgr、Ability Framework

```
扫描策略：
1. Parcel/序列化接口：
   - ReadParcelable / WriteParcelable 对的一致性
   - 读取顺序与写入顺序是否严格匹配？（CVE-2025-31175 deserialization mismatch）
   - ReadString 后是否校验字符串内容（长度、字符集、注入字符）？
   
2. 自定义序列化：
   - Marshalling/Unmarshalling 实现中的buffer长度校验
   - 嵌套对象的递归反序列化深度限制
   - 循环引用/自引用对象导致的无限递归或资源耗尽
   
3. 跨设备反序列化（OpenHarmony特有）：
   - 不同版本设备之间的序列化格式兼容性
   - 大端/小端不一致
   - 32位/64位设备之间的指针大小差异
   
4. 类型实例化：
   - 反序列化时根据类型ID实例化对象——类型ID是否可伪造？
   - 工厂模式中是否有白名单限制可实例化的类型？
```

### SKILL 11: Command Injection 检测

**适用模块：** AppSpawn、Startup、HDF（脚本调用）、DSoftBus

```
扫描策略：
1. 系统命令执行接口：
   - system() / popen() / exec*() 族函数中拼接用户输入
   - shell脚本调用中的参数注入
   
2. 间接注入：
   - 文件名/路径拼接后传递给shell命令
   - 环境变量注入
   - LD_PRELOAD / PATH修改

3. OpenHarmony特有：
   - CVE-2022-38064：DSoftBus蓝牙rfcomm→任意命令执行
   - AppSpawn中应用包名/进程名用于构造文件路径或命令
   - init脚本中的参数注入
```

### SKILL 12: Double Free 检测

**适用模块：** Kernel LiteOS-A、HDF、Multimedia

```
扫描策略：
1. 显式double free：
   - 同一指针在不同代码路径上被free两次
   - 错误处理/清理路径中重复调用free/delete
   - CVE-2024-47404模式：LiteOS-A内核中double free→提权
   
2. 隐式double free：
   - 对象被加入多个容器，每个容器销毁时都释放对象
   - 父子对象的所有权不清晰，双方都释放子对象
   - 异常安全问题：构造函数部分完成后异常，析构函数释放未完全初始化的资源
```

---

## 四、各TOP模块的代码级漏洞分析提示

### 4.1 ArkCompiler ETS Runtime — 高风险代码路径

**关键审计文件/目录：**
- `ecmascript/compiler/` — JIT编译器，关注type speculation和deoptimization
- `ecmascript/interpreter/` — 字节码解释器，关注opcode handler中的类型检查
- `ecmascript/mem/` — 垃圾回收器，关注GC标记与mutator的同步
- `ecmascript/builtins/` — 内置对象实现（Array、TypedArray、String），关注边界检查
- `ecmascript/js_typed_array.cpp` — TypedArray操作，整数溢出高发区
- `ecmascript/object_factory.cpp` — 对象创建，关注内存分配失败处理

**高风险API/函数：**
- `JSArray::SetLength()` — 数组长度修改时的内存重分配
- `EcmaString::Concat()` — 字符串拼接的buffer计算
- `TypedArray::SetTypedArrayFromTypedArray()` — 跨类型复制的offset计算
- `JSSerializer::Serialize()`/`Deserialize()` — 序列化边界
- 所有使用`TaggedArray`的操作 — 数组索引越界

### 4.2 DSoftBus — 高风险代码路径

**关键审计文件/目录：**
- `core/authentication/` — 设备认证逻辑，检查是否可绕过
- `core/connection/tcp/` — TCP连接处理，检查buffer管理
- `core/connection/ble/` — BLE连接，检查配对/认证
- `core/connection/br/` — BR连接，rfcomm数据处理
- `core/discovery/coap/` — CoAP发现协议，检查报文解析
- `core/transmission/` — 数据传输，检查分包/组包逻辑
- `core/bus_center/lnn/` — LNN网络管理，检查节点信息处理

**高风险API/函数：**
- `AuthSessionProcessDevIdData()` — 设备ID认证处理
- `TransProxyUnpackHandshakeMsg()` — 握手消息解包
- `ConnBlePackCtlMessage()` — BLE控制消息打包
- `LnnProcessNodeInfo()` — 节点信息处理
- 所有`Unpack*()`/`Parse*()`函数 — 网络数据反序列化

### 4.3 Multimedia Player Framework — 高风险代码路径

**关键审计文件/目录：**
- `services/services/avcodec/` — 编解码服务，IPC stub处理
- `services/services/player/` — 播放器服务
- `frameworks/native/avcodec/` — native层编解码接口
- FFmpeg集成代码 — demuxer/decoder调用链

**高风险API/函数：**
- 媒体容器解析中的所有`Read*()`函数 — 从文件读取并解析结构
- codec buffer管理中的`QueueInputBuffer()`/`DequeueOutputBuffer()` — buffer生命周期
- metadata提取中的字符串处理 — 格式字符串和buffer溢出
- IPC stub中的`OnRemoteRequest()` — 处理来自不受信进程的请求

### 4.4 HDF驱动框架 — 高风险代码路径

**关键审计文件/目录：**
- `framework/core/host/` — 驱动宿主管理
- `framework/core/manager/` — 驱动管理器
- `framework/support/platform/` — 平台驱动（I2C、SPI、GPIO、UART、USB）
- 所有`/dev/`设备节点的ioctl handler

**高风险API/函数：**
- `HdfDeviceObject::Dispatch()` — IOCTL分发，用户态数据进入内核态的入口
- `HdfSBuf`读写操作 — 序列化buffer，类似Parcel的序列化/反序列化
- `DriverBind()`/`DriverInit()`/`DriverRelease()` — 驱动生命周期管理
- 平台驱动中的DMA buffer管理 — 物理内存映射

### 4.5 Kernel LiteOS-A — 高风险代码路径

**关键审计文件/目录：**
- `kernel/base/ipc/` — IPC实现（futex、信号量、消息队列）
- `kernel/base/mem/` — 内存管理（堆、页表、VMM）
- `kernel/base/vm/` — 虚拟内存管理
- `fs/` — 文件系统实现
- `syscall/` — 系统调用入口（全部需审计）

**高风险API/函数：**
- `SysFutex()` — CVE-2025-31172/31173的漏洞点
- `SysClockGettime()`/`SysClockGetres()` — CVE-2022-45126的漏洞点
- `LOS_MemAlloc()`/`LOS_MemFree()` — 自定义内存分配器的UAF/double free
- `OsVmSpaceMap()` — 虚拟内存映射权限检查
- 所有`copy_from_user()`/`copy_to_user()` — 用户态-内核态数据拷贝的边界检查

---

## 五、扫描优先级与执行策略建议

### 第一优先级（立即扫描）— Critical风险模块

**ArkCompiler + DSoftBus + Multimedia + HDF + Kernel** 这五个模块应作为第一批扫描目标。扫描重点为：**UAF、OOB Write、Integer Overflow**三大漏洞类。建议采用以下策略：

对于每个模块，AI扫描应分三轮执行。**第一轮**聚焦外部输入入口点（网络数据接收、文件解析、IPC请求处理、IOCTL handler），追踪外部数据的传播路径（taint analysis），识别所有未经验证就用于内存操作的外部数据。**第二轮**聚焦内存管理模式（分配/释放配对、引用计数、生命周期管理），识别UAF和double free。**第三轮**聚焦并发安全（锁使用、共享状态、竞态条件），识别TOCTOU和data race。

### 第二优先级 — High风险模块

**IPC/RPC、Bluetooth、WiFi、ArkUI、Graphic 2D、Access Token、AppSpawn** 应在第一批完成后立即扫描。这些模块中**逻辑漏洞（权限绕过、认证绕过）与内存安全漏洞并重**，扫描策略需要同时覆盖两类。

### 第三优先级 — Medium-High风险模块

**Distributed Data、DFS、AV Codec、OpenSSL/mbedTLS、Peripheral Drivers** 可作为第三批，重点关注跨设备信任边界和第三方库版本更新状态。

### 关键的跨模块扫描点

以下跨模块交互路径是攻击链的关键连接点，需要特别关注：

**DSoftBus → IPC → Ability Framework** 这条路径实现了从网络入口到应用执行的完整攻击链。攻击者可通过物理邻近的蓝牙/WiFi接口进入DSoftBus，利用IPC机制的漏洞进行提权，最终通过Ability Framework在目标设备上启动恶意能力。

**Multimedia → Codec → HDF** 这条路径实现了从文件解析到内核代码执行。通过crafted媒体文件触发多媒体解析漏洞，利用编解码器的HDI接口到达HDF驱动层，最终获得内核权限。

**ArkWeb/Chromium → ArkCompiler → Kernel** 这条路径类似Android上的浏览器利用链（Chrome V8 → sandbox escape → kernel）。Project Zero追踪显示这类利用链在2022-2025年持续活跃，是商业监控软件（NSO Group、Intellexa）的主要攻击路径。

---

## 结论：OpenHarmony安全态势的独特挑战

OpenHarmony面临的安全挑战既包含传统移动OS的共性问题，也包含其分布式架构带来的独有风险。**共性方面**，Android生态中Bluetooth SDP的UAF、Media Framework的解析漏洞、GPU驱动的内存破坏等模式在OpenHarmony中同样存在或具有对应物。**独有方面**，DSoftBus作为一个同时暴露BLE/BR/WiFi/NFC/TCP五种协议接口的统一通信框架，其攻击面远大于任何单一协议栈——这在Android和iOS中都不存在对等物。

从Project Zero的野外利用数据看，**2024年最重要的趋势是零点击图片/音频解析利用（Samsung Quram DNG、APE codec）和取证公司的USB物理攻击链（Cellebrite）**。前者要求OpenHarmony对multimedia_image_framework和所有第三方图片解码库（libpng、libjpeg-turbo、libwebp、giflib）进行最高优先级的安全审计和沙箱隔离。后者要求USB子系统和HDF驱动框架具备对物理攻击的防御能力。

最值得关注的单一技术风险是ArkCompiler ETS Runtime——作为一个相对年轻的语言运行时引擎，它在2024年单年即产出6个高危RCE漏洞（CVSS 8.2-8.4），这与V8引擎早期的漏洞密度模式高度相似。Google对V8的持续投入（MiraclePtr、V8 Sandbox）花了十余年才显著降低利用成功率。OpenHarmony需要在ArkCompiler上采取类似的系统性安全加固策略，包括但不限于：JIT编译器的类型安全加固、GC与mutator的并发安全保障、以及TypedArray/ArrayBuffer操作的全面边界检查。