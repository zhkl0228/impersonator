# ECH over QUIC —— 给 impersonator 加一个 QUIC 模块（第 1 步）

> **本计划已执行完毕**，`quic` 模块可用。计划正文原样保留（它是当初的设计记录），
> 实际做出来跟计划有出入的地方、验证证据、以及第 2 步接手时需要知道的事，
> 都在文末的[「执行结果」](#执行结果)。

写给接手这项工作的会话。目标只有一个：**让 kwik 上的 QUIC/HTTP-3 握手能发真正的 Encrypted Client Hello**，
并且复用 impersonator 现有的 `EchConfigProvider`，这样上层（proxy-transport 的 `EchConfigs`）一行都不用改。

指纹（让 QUIC 长得像 Chrome）是第 2、3 步，**本计划明确不做**。

---

## 已经定下的事

| 决定 | 内容 |
|---|---|
| 许可 | impersonator 整体改成 **LGPL-3**（kwik/agent15 是 LGPL-3；BC 是 MIT 系，可并入 LGPL 作品） |
| 范围 | 仅客户端 ECH。不做 HRR、不做 PSK/0-RTT 组合、不做服务端 ECH、不做指纹 |
| 形态 | 新增模块 `quic`（artifactId `impersonator-quic`），照 `bctls` 的 vendored 模式 |
| 验证 | Cloudflare：h3 打 `crypto.cloudflare.com/cdn-cgi/trace`，body 里 `sni=encrypted` 即成功 |

---

## 两个让工作量大幅缩小的发现

### 1. 只需 vendor agent15（83 个文件），kwik 保持上游依赖

kwik 对 agent15 **只用公开 API**——全仓库检索，`tech.kwik.core` 引用的是
`agent15.extension` / `agent15.engine` / `agent15.handshake` / `TlsConstants`，
**没有任何一处碰 `agent15.engine.impl`**；依赖方式是普通 artifact（`core/build.gradle`:
`implementation "tech.kwik:agent15:$agent15_version"`）。

所以：vendor agent15（保持包名 `tech.kwik.agent15.*`），在依赖里 exclude 上游 agent15，
让 kwik 链到我们这份。**kwik 一行都不用改**，也就仍然可以随上游升级。

ECH 配置怎么进到引擎？kwik 的 `QuicClientConnectionImpl` 在 `startHandshake` 里先
`tlsEngine.setServerName(host)` 再 `tlsEngine.startHandshake(...)`——引擎自己就知道 server name，
而 `EchConfigProvider` 恰好就是「按 server name 给 ECHConfigList」。于是：

- `TlsClientEngine` 上加一个 per-engine 的 setter（主 API）；
- `TlsClientEngineFactory` 上加一个**进程级默认 provider**（注入点），因为 kwik 在内部 new 引擎，外面拿不到。
  进程级是合理的：ECHConfigList 属于主机而不属于连接，上层 `EchConfigs.shared()` 本来就是单例。

被拒绝的路径不需要 kwik 配合：抛一个带 `retry_configs` 的异常，kwik 会当作连接失败往上抛，
上层照 TCP 那条路已有的做法处理（`EchConfigs.recordRejection()` → 重试）。

### 2. 这个仓库里已经有一份跑通的 Java ECH 实现

`bctls/src/main/java/org/bouncycastle/tls/` 下面：

```
EchClient.java              471 行   inner/outer 构造、ech_outer_extensions 压缩、padding、HPKE seal、accept confirmation
EchClientHello.java         114 行   扩展的 inner/outer 两种形态
EchConfig.java              259 行   单条 ECHConfig：版本/kem/kdf/aead 判定、cipher suite 选择
EchConfigList.java           99 行   0xfe0d 列表解析与挑选，挑不出就抛（带 hex）
TlsEchRejectedException.java 48 行   retry_configs 的承载
```

**HPKE 也不用自己写**：`EchClient` 直接用 `org.bouncycastle.crypto.hpke.HPKE`，本仓库已依赖 BC。

所以这项工作的本质是**把这 991 行的逻辑搬到 agent15 的消息构造 API 上**，而不是从零实现 RFC 9849。
先把 `EchClient.create(...)` 通读一遍再动手，它把所有坑都踩过了
（`INFO_PREFIX = "tls ech"`、outer 的 supported_versions 要去掉 legacy 版本、可压缩扩展的分组……）。

**强烈建议**：`EchConfig` / `EchConfigList` 的可见性放开成 public，让 `quic` 模块**直接依赖 bctls 复用它们**，
不要复制第二份。这样「拿到一串 ECHConfigList，挑哪一条、挑不出怎么办」在 TCP 和 QUIC 两条路上永远一致。
代价是这部分不可能再上游给 agent15——第 1 步本来就不打算 PR，可以接受。

---

## 模块骨架

```
impersonator/
├── bctls/          （已有；把 EchConfig/EchConfigList 放开为 public）
├── okhttp/         （已有）
└── quic/           （新增，artifactId impersonator-quic）
    ├── UPSTREAM.md                     记录 vendored 自哪个 commit + 改过哪些文件
    └── src/main/java/
        ├── tech/kwik/agent15/**        vendored + 修改（83 个文件）
        └── com/github/zhkl0228/impersonator/quic/**   胶水层
```

依赖：`impersonator-bctls`（复用 ECHConfig 解析 + BC 的 HPKE）、`tech.kwik:kwik-core`（**exclude 掉传递来的
`tech.kwik:agent15`**）。

vendored 的基线 commit（写进 UPSTREAM.md）：agent15 `977b893`。

---

## 干活顺序

按这个顺序提交，每一步都能独立编译、独立验证。

### 0. 换许可 + 原样 vendor
父 pom 的 `<licenses>` 改 LGPL-3、补 LICENSE 文件、README 说明。
然后**先提交一次一字未改的 agent15 拷贝**——后面所有的 `git diff` 才有意义，将来同步上游也才能机械地做。
每个文件保留上游的 LGPL 头，并按 LGPL 要求标注「本文件已被修改」。

> 下游提醒：proxy-transport 是 Apache-2.0，仅仅依赖 LGPL 库是允许的；
> 但如果它以后要 shade 成 uberjar，LGPL 的 relink 义务就会生效，到时候要处理。

### 1. 扩展与配置（最容易，先拿分）
- `tech.kwik.agent15.ech.EncryptedClientHelloExtension`：outer 形态
  `{config_id, cipher_suite, enc, payload}`、inner 形态（空）、以及 EncryptedExtensions 里承载
  `retry_configs` 的形态。照 `EchClientHello.java` 抄。
- `TlsConstants` 加扩展类型 `encrypted_client_hello(0xfe0d)` 和 alert `ech_required(121)`。
- 解析侧：`ExtensionParser` 认得它（EncryptedExtensions 里要能取出 retry_configs）。

### 2. ClientHello 造两份
这是全部工作里唯一需要真正设计的地方，因为 agent15 的 `ClientHello` 是「构造器里一趟写完 buffer」。

- **inner**：真实 SNI、自己的 random、`legacy_session_id` 为空
  （QUIC 从不用 compatibility mode——`compatibilityMode` 默认 false 且 kwik 从不调
  `setCompatibilityMode`，所以 inner/outer 的 session_id 复制规则自动满足），加 inner 标记扩展。
- **outer**：`public_name` 当 SNI、自己的 random、ECH 扩展的 payload 先填等长的零。
- **AAD 回填**：序列化出的 outer（payload 全零）就是 `ClientHelloOuterAAD` → HPKE seal → 把密文补回原位。
  **这个「先序列化再打补丁」的手法 agent15 里已有先例**：`ClientHello` 构造器末尾算 PSK binder 时就是
  `buffer.position(pskExtensionStartPosition)` 然后重写。照着写。
- padding 按 RFC 9849 §6.1.3。
- `ech_outer_extensions` 压缩第一版**可以不做**（规范里是 MAY）。代价只是 CH 变大；
  kwik 的 `CryptoStream.sendFrame(maxSize)` 已经按包分片并自动续注册，CH 跨多个 Initial 包没有问题。
  （`EchClient` 里有现成的压缩实现，想做也可以直接搬。）

### 3. 引擎接线
`TlsClientEngineImpl` 新增状态：provider / innerClientHello / outerClientHello / echAccepted。

- `startHandshake`：provider 对 serverName 给得出 ECHConfigList 就造两份、发 outer、留住 inner。
- `received(ServerHello)`：算
  `accept_confirmation = HKDF-Expand-Label(HKDF-Extract(0, inner.random), "ech accept confirmation", H(inner ‖ 后 8 字节 random 清零的 SH), 8)`，
  和 `ServerHello.random[24..32]` 比对，**决定 transcript 记 inner 还是 outer**。
  `TlsState.hkdfExpandLabel` 是 public，直接可用。
  - 有利的时序：非 PSK 路径里 CH 是收到 SH、选定 cipher 之后才 `transcriptHash.record(clientHello)`
    （`TlsClientEngineImpl` 约 314–316 行），正好留出选择的余地。
  - PSK 路径在 `startHandshake` 里就 record 了——**所以第一版明确不支持 ECH + 会话恢复/0-RTT，
    两者同时设置就抛**。inner/outer 各自算 binder 是 ECH 里最容易出错的部分，不值得在第一版趟。
- **拒绝路径**：继续握手，但证书必须按 **`public_name`** 而不是真实 SNI 验证（会碰
  `HostnameVerifier` 的调用点，这是唯一一处改动既有安全逻辑的地方），
  然后从 EncryptedExtensions 取出 `retry_configs`，抛 `TlsEchRejectedException` 带上它。
  语义对齐 bctls 里已经做过的 RFC 9849 §6.1.7（见 commit `48090c1`）。

### 4. 胶水层
`com.github.zhkl0228.impersonator.quic` 下提供把 `EchConfigProvider` 装进
`TlsClientEngineFactory` 默认值的入口，命名和现有 `api.setEchConfigProvider(...)` 保持一致的观感。

> 尽量**别让 vendored 的 agent15 反过来 import impersonator 的类型**：
> agent15 里用一个自己的小接口（或 `Function<String, byte[]>`），在胶水层做适配。
> 这样第 2、3 步真要上游时，agent15 的 patch 是干净的。

---

## 验证

### 单元
- ECHConfig 解析：直接复用 bctls 那份（如果按建议放开可见性），只补 agent15 侧的扩展编解码测试。
- HPKE：用 BC 的实现，不需要自己验向量。

### 集成（真正的证据）
Cloudflare 的 `/cdn-cgi/trace` 会直接告诉你 ECH 有没有生效——`sni=encrypted` 还是 `sni=plaintext`。
HTTPS RR 里 `ech=` 和 `alpn=h3` 是同一条记录、同一份 ECHConfig，所以对 QUIC 同样适用。

1. **基线（先做，最便宜）**：用现有的 TCP + bctls 路径打 `https://crypto.cloudflare.com/cdn-cgi/trace`，
   确认拿到 `sni=encrypted`。这一步就能确定 Cloudflare 侧行为和 DoH 取到的配置都对。
2. **目标**：flupke-on-kwik 走 h3 打同一个 URL，同样拿到 `sni=encrypted`。
3. **反向对照**：同一请求不开 ECH → `sni=plaintext`。这条必须做，否则无法证明 1、2 不是巧合。
4. **拒绝路径**：故意喂一份改坏的 ECHConfig（翻一个 public key 字节或用错 config_id），
   期望抛 `TlsEchRejectedException` 且带回 `retry_configs`；用返回的配置重试应当 `sni=encrypted`。
5. **真实节点**：proxy-transport 那份订阅里的 XHTTP-over-h3 节点（`dedione.gzmtx.cn`）已确认支持 h3 ECH，
   作为最终验收。

---

## 明确不做

HelloRetryRequest（agent15 本来就不实现，`ServerHello` 直接抛，ECH 的 HRR 分支同样跳过）、
ECH + PSK/0-RTT、服务端 ECH、GREASE ECH、`ech_outer_extensions` 压缩（可选）、
QUIC/h3 指纹（第 2、3 步）、以及 proxy-transport 侧的任何改动——
那边等这个模块可用后，只需去掉 `ClashProxies.noteEchNotHonored` 那条 info。

---

## 交接给上层时的收益

QUIC 侧的 ECH 一旦走 `EchConfigProvider`，proxy-transport 的
`EchConfigs` / `EchTarget` **原样生效**：每节点的 DoH resolver（clash 订阅 `dns:` 下发的那个）、
预热、`retry_configs` 被拒自愈，全部自动覆盖到 hysteria2 和 XHTTP-over-h3。
这也是「放进 impersonator 而不是散在一个 kwik fork 里」的主要理由。

---

## 执行结果

`quic` 模块（artifactId `impersonator-quic`）已实现并验证：**ECH 做完了，第 2 步的 TLS 那一层
也做完了**（JA4 与 curl 完全一致，见下面「第 2 步」）。vendored 的 agent15 之外：
新增 `tech.kwik.agent15.ech` 包 6 个类 + `RawExtension` + `ClientHelloSpec` 共 1009 行，
胶水层 3 个类 261 行，往 8 个 vendored 文件里加了 510 行，测试 5 个类共 27 条 811 行。

### 计划里说错的地方

| 计划里写的 | 实际 |
|---|---|
| 依赖 `tech.kwik:kwik-core` | 发布出来的 artifact 叫 **`tech.kwik:kwik`**（`kwik-core` 是 gradle 子项目名）。当前版本 0.11，依赖 agent15 3.3 |
| 「把 `EchConfig`/`EchConfigList` 放开为 public」 | **本来就是 public**，bctls 一行都不用改 |
| 用 `crypto.cloudflare.com` 验证 h3 | 那台机器的 HTTPS RR 只有 `alpn=h2`，QUIC 握手直接回 `handshake_failure`（拿上游原版 kwik+agent15 直连真实 IP 复现过，不是本模块的问题）。**改用 `cloudflare-ech.com`**，它一条记录里同时有 `alpn=h3` 和 `ech=`，而且它自己就是自己 ECHConfig 的 public_name，被拒时证书照样能验 |
| 「抛一个带 `retry_configs` 的异常，kwik 会当作连接失败往上抛」 | kwik 把 `TlsProtocolException` 压成 `handshakeError = e.toString()`，再抛一个新的 `ConnectException`，**异常对象本身到不了调用方**，`retry_configs` 的字节拿不出来。所以 `EchConfigProvider` 加了第二个方法 `echRejected(EchRejectedException)`：谁给的 config，就回调谁 |
| （未提及） | kwik 的 `QuicClientConnectionImpl.startHandshake` 把它声明的 `IOException` 吞掉了（注释写「不会发生」）。所以 ECH 构造失败必须抛 **unchecked** 的 `EchException`，否则会被吞掉、连接一路挂到超时、日志里一个字都没有 |
| （未提及） | agent15 和 kwik 是 Java 11 字节码，`quic` 模块只能是 Java 11；bctls/okhttp 仍是 Java 8 |
| （未提及） | 父 pom 里给 okhttp 用的 javadoc `<extdirs>` 在 target 11 上会被 javadoc 直接拒绝（`option -extdirs not allowed with target 11`），已经挪进 okhttp 自己的 pom |

### 最后长成什么样

```
quic/
├── UPSTREAM.md                  vendored 基线 commit + 改过哪些文件 + 怎么跟上游同步
└── src/main/java/
    ├── tech/kwik/agent15/       vendored 82 个文件（module-info.java 没抄，理由在 UPSTREAM.md）
    │   └── ech/                 新增：EncryptedClientHelloExtension / EchClient /
    │                            EchConfigProvider / EchRejectedException / EchException /
    │                            EchPayloadCalculator
    └── com/github/zhkl0228/impersonator/quic/
        ├── ImpersonatorQuic.java      装 impersonator 的 EchConfigProvider
        └── EchRejectionHandler.java   被拒时把 retry_configs 交出来
```

改动的 7 个 vendored 文件，每个都按 LGPL 第 2 条加了「Modified for impersonator」的头注释：

- `TlsConstants` — `encrypted_client_hello(0xfe0d)`、`ech_required(121)`。
  注意 `ExtensionType.value` 是 `short`，`0xfe0d` 会变成负数，比较时必须 `& 0xffff`。
- `handshake/ClientHello` — 多一个收 `EchPayloadCalculator` 的构造器。**没有**照计划说的「先序列化再打补丁」
  手写偏移量，而是照 `BinderCalculator` 的样子做成回调：构造器写完扩展、算出 `data`、
  把去掉 4 字节头的 `data` 当 AAD 交给回调、拿密文回填。跟旁边的 PSK binder 是同一个套路，
  将来往上游 PR 也干净。
- `handshake/HandshakeMessage` — `parseExtensions` 认得 ECH（ClientHello 和 EncryptedExtensions 两种上下文）。
- `engine/TlsClientEngine` + `TlsClientEngineFactory` — per-engine setter + 进程级默认值。
- `engine/impl/TlsClientEngineImpl` — 造两份 CH、按 accept confirmation 选 transcript、
  被拒时按 public_name 验证书、发空的 client Certificate、最后抛 `EchRejectedException`。
- `engine/impl/TlsState` — 加 `hkdfExtract`，`hkdfExpandLabel(byte[], String, byte[], short)` 放开为 public。

`ech_outer_extensions` 压缩按计划没做。HRR、ECH+PSK/0-RTT、compatibility mode 全部抛异常，不猜。

### 验证证据

单元 8 条（`EchClientTest`）：测试自己扮演 client-facing server —— ECHConfig 的私钥在测试手上，
所以能真的用 §5.2 的 AAD 打开 ClientHelloOuter 的 payload，比对里面就是 ClientHelloInner。
覆盖 §6.1.3 padding、AAD 绑定（翻一个 bit 必须解不开）、§7.2 accept confirmation、
以及「ECHConfigList 一条都用不了必须抛而不是退回明文 SNI」。
另外 12 条（`EncryptedClientHelloExtensionTest`）测 §5 的三种线格式收发。

集成 4 条（`EchOverQuicTest`，真打 h3）：

| | 结果 |
|---|---|
| 走 DoH 查 ECHConfigList | `sni=encrypted` |
| 不装 provider（反向对照） | `sni=plaintext` |
| 把 public key 翻一个字节 | 连接失败，handler 收到 `retry_configs`，拿它重试 → `sni=encrypted` |
| 喂一份用不了的 ECHConfigList | 一个包都没发就抛 `EchException` |

TCP 基线（okhttp `EchTest` 8 条）照旧通过。JDK 8（3 个模块）和 JDK 11（4 个模块，含 javadoc）都构建通过。

计划里的第 5 条「真实节点 `dedione.gzmtx.cn`」没做：那份订阅在 proxy-transport，不在本仓库。

### 第 2 步（QUIC/h3 指纹）接手时要知道的

QUIC 上**完全没有做指纹伪装**，而且暴露面比 TCP 那条路多两层。下面是实测出来的，不是推测。

#### 靶场：`https://quic.tools.scrapfly.io/api/fp/quic`

先找靶子。现有测试里的五个指纹站，只有 `tls.peet.ws` 在 alt-svc 里广播 `h3=":443"`，
但它的 h3 从本机连不上——我们的客户端和 curl 8.21（ngtcp2）都超时，走 fake-IP 和 `--resolve`
直连真实 IP 一样，而同一台机器上 `quic.nginx.org`、`cloudflare-ech.com` 的 h3 两个客户端都能通。
是它的 h3 挂了还是这条链路挡 UDP，分不出来，换个网络值得再试一次。
`tls.browserleaks.com` 不支持 h3，但它发布了 ECHConfig（public_name `tls-outer.browserleaks.com`），
可以当 **TCP 路径**的 ECH 对照靶子，现在的测试没用上。

scrapfly 另开了一个子域，`tools.scrapfly.io` 上没有 alt-svc，但 **`quic.tools.scrapfly.io` 有**，
而且它一次量五层，是目前找到的唯一能用的 QUIC 指纹靶场：

| 它测什么 | 归谁管 |
|---|---|
| `ja4` / `ja4_r`（TLS ClientHello） | agent15 的 `ClientHello` |
| `dcid_length` / `scid_length` | kwik 的 `ConnectionIdManager` |
| Initial 包的 `frames` / `padding_length` | kwik 的包组装 |
| `transport_parameters` 的取值 | kwik 的 `initTransportParameters` |
| `h3_hash` / `h3_text`（HTTP/3 SETTINGS） | flupke |

后四样都在 TLS ClientHello 之外，`Chrome.java` 那套东西**一个都够不着**。

#### 现在的实测值

同一个 endpoint、同一台机器，我们的模块 vs curl 8.21/ngtcp2：

| | 本模块 | curl / ngtcp2 |
|---|---|---|
| `ja4` | `q13d0108h3_0f2cb44170f4_276fd97ef477` | `q13d0312h3_55b375c5d22e_f5ac3e2d82fc` |
| `h3_hash` | `e05363953b1f`（`1:0;7:0`） | `c71fbd791d8b`（`1:0;6:…;7:0`） |
| DCID 长度 | 8 | 20 |
| Initial padding | 889 字节 | 12 字节 |
| transport params | idle 60000ms、max_udp 1500、bidi 0 / uni 3 | idle 0、max_udp 2^62-1、bidi/uni 262144 |

`ja4_r` 把明细摊开，缺什么一目了然：

```
ours: q13d0108h3_1301_000a,000d,002b,002d,0033,0039_0403,0503,0603,0804,0805,0806
curl: q13d0312h3_1301,1302,1303_000a,000b,000d,0016,0017,002b,002d,0031,0033,0039_（19 个签名算法）
```

`q13d` 后的四位是「cipher 数 + 扩展数」，我们是 `01 08`。把 kwik 交给 agent15 的那份
ClientHello 原样重建出来是：

```
ClientHello size     255 bytes
cipher_suites        [TLS_AES_128_GCM_SHA256]
extensions (order)   0 43 10 13 51 45 57 16
  10  supported_groups     = [secp256r1]
  51  key_share            = secp256r1
  13  signature_algorithms = 6 个
```

对比 `Chrome.java` 在 TCP 上已经在发的：16 个 cipher（含 GREASE）、约 17 个扩展
（GREASE×2、ALPS、compress_certificate、trust_anchors、session_ticket、SCT、padding）、
supported_groups `GREASE, X25519MLKEM768, x25519, secp256r1, secp384r1`、
key_share `GREASE + X25519MLKEM768`、12 个签名算法（含 ML-DSA）。

注意 `padding_length: 889`——kwik 把 Initial 填到 1200 字节，我们的 CH 才 255，
所以 **padding 的大小反过来泄露了 ClientHello 的大小**。这一项会随着 CH 做像了自动对上，
但也说明只改 TLS 层不够。

#### 四个硬拦路虎，前三个已经拆掉

1. ~~`SupportedGroupsExtension` 只收一个组，`KeyShareExtension` 只发一份 key share~~ —— 解决了。
   `ClientHelloSpec` 口述整个扩展列表，key_share 由它自己拼，agent15 只负责写出去。
2. ~~X25519MLKEM768 生成不出来~~ —— 解决了，而且**没有在 agent15 里实现 ML-KEM**：
   bctls 加了一个 `TlsKeyShare` 门面，把 BouncyCastle 本来就有、但 package-private 的
   `TlsUtils.createKeyShare` 开出来。混合组哪一半在前、peer value 在哪切、两个 secret 怎么拼，
   全是 BC 在 TCP 路径上跑了很久的代码。agent15 只多了 `TlsState.setSharedSecret`，
   `KeyShareExtension` 多保留一份服务端 key share 的原始字节（私钥这次不在 agent15 手里）。
3. ~~`ClientHello` 的 `defaultExtensions` 顺序写死~~ —— 解决了。新增一个构造器，给什么写什么。
4. **kwik 和 flupke 那几层还没动**，见下面「下一步」。

#### 结果：JA4 与 curl 完全一致

同一个 endpoint 实测：

| | 本模块 | curl 8.21/ngtcp2 |
|---|---|---|
| `ja4` | `q13d0312h3_55b375c5d22e_f5ac3e2d82fc` | **一致** |
| `ja4_hash` | `16fc307196e6` | **一致** |
| `ja4_r` 全串 | | **一致** |
| cipher 列表 / 扩展顺序 / supported_groups | | **一致** |
| key_share `X25519MLKEM768 + X25519` | | **一致** |
| `h3_hash` | `e05363953b1f` | `c71fbd791d8b` |
| `dcid_length` / transport params | 8 / max_udp 1500 | 20 / 2^62-1 |

改造前是 `q13d0108h3_`。副作用一则：CH 变大后 Initial 包的 `padding_length` 字段直接消失，
包被真实内容填满了，跟 curl 一样。

curl 的那份 profile 在 **test 源码**里（`Curl8QuicClientHello`），不是 main——没人要伪装成 curl，
它的价值只是证明机制。`Impersonator.getQuicClientHello()` 默认抛异常，**不从 TCP 那份推导**。

#### 下一步：vendor kwik，模块拆成四个

剩下的差异全在 agent15 够不着的地方，而这几层归谁、能不能不 vendor 就改，查清楚了：

| 层 | 归谁 | 现在能不能配 |
|---|---|---|
| **TLS 引擎的创建** | kwik | **不能**——`QuicClientConnectionImpl` 构造器里静态调 `TlsClientEngineFactory.createClientEngine`，没有参数能把 profile 传进去 |
| transport parameters | kwik | 不能 |
| DCID 长度 | kwik | **不能**——`ConnectionIdManager` 里写死 `new byte[8]`；builder 的 `connectionIdLength()` 只管 source CID |
| Initial 包 padding / frames | kwik | 不能 |
| h3 SETTINGS | flupke | 快能了——`settingsParameters` 是 protected `Map` 且有 add 方法，但它是 `HashMap`，参数顺序未定义（后来做了：清空后按 `LinkedHashMap` 顺序 putAll，见下面「QPACK 动态表」） |

第一行是最要紧的：**`ImpersonatorQuic` 现在那两个进程级静态入口（ECH provider 和 profile）
不是设计偏好，是这一个事实逼出来的。** 构造器跑在调用方线程上，所以 ThreadLocal 对
`Http3Client.send()` 能用，但 `sendAsync` 走 executor 线程就失效——「大部分时候对」的东西不要。

所以顺序是：

1. **vendor kwik**（照 agent15 的规矩：先提一次一字未改的拷贝）。
   flupke 引用 kwik 只用了 `tech.kwik.core` / `.generic` / `.server` / `.log` / `.concurrent`，
   **一处都没碰 `tech.kwik.core.impl`**——所以 agent15 那个招数原样再用一次：vendor kwik，
   `tech.kwik:flupke` 继续当上游依赖并 exclude 掉它传递来的 `tech.kwik:kwik`，flupke 仍可跟上游升级。
   代价：kwik 有 200 个 java 文件（agent15 才 82）。
2. `QuicClientConnection.Builder` 上加 profile 参数传给引擎 →
   干掉 `TlsClientEngineFactory` 的两个静态默认值，**ECH 和指纹一起变成 per-instance**。
3. 新建 `http3` 模块和 `Http3ClientFactory`，形状照 `OkHttpClientFactory`。
   **不需要 vendor flupke**：`Http3ClientConnectionImpl` 有一个 public 构造器直接收 `QuicConnection`，
   我们自己建好 QUIC 连接交给它就行。
4. 用同一个 endpoint 把 transport parameters、DCID 长度、Initial padding 逐项对上，
   h3_hash 最后再说；真要动 SETTINGS 的顺序时再评估要不要 vendor flupke。
   （结论：SETTINGS 的顺序和取值都不用 vendor flupke，vendor 的是 **qpack**，见下面「QPACK 动态表」。）

模块结构跟着变成四个（`quic` 是聚合 pom，两份 vendored 各自一个 artifact，
这样每个模块 1:1 顶替一个上游 artifact，各有各的 UPSTREAM.md 和基线 commit，
而且「kwik 依赖 agent15、反过来不行」这条由编译器守着）：

```
impersonator/
├── bctls/          impersonator-bctls     TLS + Impersonator/ImpersonatorApi
├── okhttp/         impersonator-okhttp    OkHttpClientFactory
├── quic/           聚合 pom
│   ├── agent15/    impersonator-agent15   vendored agent15 + ECH + ClientHelloSpec
│   ├── qpack/      impersonator-qpack     vendored qpack + QPACK 动态表
│   └── kwik/       impersonator-kwik      vendored kwik + per-connection profile 接线
└── http3/          impersonator-http3     flupke（上游依赖）+ Http3ClientFactory
```

#### 浏览器的抓包还是没有

Chrome 在这个 endpoint 上的值还没拿到：浏览器自动化开了标签页刷三次，Chrome 始终走 HTTP/2
（站点回 `http3_supported: false`），而同机的 curl 和本模块都能 h3 连上。浏览器当然能 h3，
只是要单独的启动参数（`--enable-quic --origin-to-force-quic-on=quic.tools.scrapfly.io:443`
这一路，具体的自己试）。

**对上 curl 不等于反检测有效**，没人会把 curl 的指纹当正常流量；它证明的是机制。
在拿到 Chrome 的真实抓包之前，**不要照记忆写 Chrome 的扩展列表**，这个仓库的做法一直是照抓包改。

#### ECH 本身还欠的

- ~~**没有 GREASE ECH。**~~ —— 做了。profile 的 ClientHello 里带 GREASE ECH，服务端回
  retry_configs 时按 RFC 9849 6.2.1 忽略（"It otherwise ignores the extension. It MUST NOT save
  the retry_configs value"）。这条当初连着两个 bug：引擎按 Java 类而不是扩展类型去匹配「发过没发过」，
  以及匹配上之后当成错误而不是忽略。
- **ECH 扩展目前放在扩展列表最后。** Chrome 放在哪要照抓包改，改的地方是
  `EchClient.create` 里往 `innerExtensions` / `outerExtensions` 里 add 的位置。
- ~~**一旦要压缩 `ech_outer_extensions`**~~ —— 做了，而且**当初判断错了**。计划正文里写的是
  「第一版可以不做，代价只是 CH 变大」。实际代价是：浏览器的 ClientHello 里光后量子 key share
  就一千多字节，不压缩的话 outer 里每个扩展再来一份，**3422 字节、三个 Initial 包**，
  Cloudflare 把三个包全 ACK 了然后**一个字节都不回**。压缩后 1854 字节、两个包，握手正常。
  这不是优化，是能不能用的问题。

#### 上层

proxy-transport 现在可以去掉 `ClashProxies.noteEchNotHonored` 那条 info，
改成 `ImpersonatorQuic.setEchConfigProvider(EchConfigs.shared(), EchConfigs.shared()::recordRejection)`。

### QPACK 动态表（h3_hash 对上 Chrome）

Chrome 的 SETTINGS 是 `1:65536; 6:262144; 7:100; 51:1; GREASE`。前面一直只对上三个，
`QPACK_MAX_TABLE_CAPACITY` 和 `QPACK_BLOCKED_STREAMS` 故意写 0——因为这两个数字不是描述自己，
**是给对端 encoder 的邀请**：允许它建动态表、允许它引用还没送达的条目。乱写不是指纹不准，是连接直接废。
而且 `h3_hash` 是整组算的，**五个对四个和对一个一样**，所以这两个不补，前面三个白对。

补的时候发现缺口比预想的深：

- 上游 qpack 的 `DecoderImpl` 四条 encoder stream 指令只实现两条，服务端开场第一条
  Set Dynamic Table Capacity 就 `NotYetImplementedException`；field section 前缀的
  Required Insert Count / Base 读出来直接丢掉；引用动态表的四种表示全部不支持。
  那个「动态表」还是**从旧端开始索引**的（RFC 9204 的相对索引从最新一条往回数），
  而且查不到时返回 null，`decodeStream` 里 `if (entry != null)` **把这个 header 悄悄丢了**。
- 而且从外面够不着：`Decoder` 接口只有一个 `decodeStream(InputStream)`，builder 没有任何选项，
  flupke 在构造器里把它赋给 `protected final` 字段。**所以只能 vendor qpack**（第 4 份 vendored 树）。
- flupke 这边还缺两块，但**都不用 vendor flupke**：它收下对端的 encoder stream 却从来不读
  （`setPeerEncoderStream` 存进一个没人看的字段），也从不开自己的 decoder stream。
  两处都能在 `Http3Connection` 这个子类里补上。
- 唯一真正的 API 缺口是 Section Acknowledgment 要**按流 id** 确认（RFC 9204 4.4.1），
  而 `decodeStream` 只拿到一段字节。flupke 的 `readHeadersFrame` 是 private，
  但它调用的 `readFrame(InputStream, long, long)` 是 protected 且拿到的就是 kwik 自己的流——
  所以 kwik 的 `StreamInputStream` 加了个 `getStreamId()`。

顺手挖出来的两个 bug：

- **`PrefixedInteger`**：续字节边界写成 `> 128`（该是 `>= 128`），余数正好 128 时写成单字节 0x80，
  读回来变成「续字节，值 0」；解析时 `(next & 0x7f) << factor` 是 int 移位，factor 到 32 就绕回，
  而 RFC 9204 4.1.1 要求支持 62 位整数。
- **`Http3Client` 的连接顺序**：先 `quicConnection.connect()` 再 new `Http3Connection`，
  但注册 peer-initiated stream 回调的正是 flupke 的构造器，而 kwik 在没有回调时默认
  `NO_OP_CONSUMER`——**握手一完成服务端就开的 control / QPACK encoder 两条流，谁先到谁被静默丢弃**。
  一直没人发现，是因为在动态表用上之前，丢了也看不出来。改成先构造再 connect。

**证据**：`QpackDynamicTableTest` 打真服务器。这里有个意外发现——**能用上动态表的服务器很少**：
Cloudflare 和 Scrapfly 的 QPACK encoder 都把 capacity 设成 0，每个 field line 都只查静态表，
这条路一点都碰不到。nghttp2.org 会设 capacity 4096、插入、然后**引用自己插入的条目**
（实测 4 个请求 references=20），引用这件事伪造不了：服务端只会引用它已经被告知收到了的条目，
也就是说 decoder stream 上的 Section Acknowledgment / Insert Count Increment 也一并验证了。

所以测试是打真服务器而不是手写字节向量：照着 RFC 手写的字节只能证明「解码器和我读 RFC 的方式一致」，
能反驳这一点的是一个自己选编码方式的服务端。

### Chrome profile 连不上 Google：两个互相独立的问题

`www.google.com` / `www.youtube.com` 用 Chrome profile 走 h3 连不上，不带 profile 正常（302），
同机 curl `--http3-only` 也正常。查下来是**两件不相干的事**，第一件已经修了，第二件没有。

#### 一、trust_anchors 换来一条被裁短的证书链（已修）

profile 里发的 `trust_anchors`（51764，draft-ietf-tls-trust-anchor-ids）**不是装饰**：
它告诉服务端「这些根我有」，服务端就可以把它认为你已经有的证书**省掉不发**。Google 照做了：

| | Google 发回来的链 | PKIX |
|---|---|---|
| 带 Chrome profile | **1 张**——只有叶子 `*.google.com` | 失败：`unable to find valid certification path` |
| 不带 profile | 3 张——叶子 → `WE2` → `GTS Root R4` | 通过 |

被省掉的 `WE2` 中间证书是 Chrome 自带、而 JDK 信任库里没有的。**发了这个扩展就得兑现**：
Chrome 靠内置根库兑现，我们按 RFC 5280 4.2.2.1 走叶子证书里的 AIA `caIssuers` 指针把缺的补回来
（`http://i.pki.goog/we2.crt`，657 字节，补上后 PKIX 立刻通过）——浏览器和系统验证器对付
「服务端漏发中间证书」用的也是这一套。

实现在 `bctls` 的 `CertificateChains`，只在**正常校验失败之后**才走，补不上就把原来的失败原样抛出。
停止条件是「链已经够到信任库」——这里 JDK 8 和 21 的 cacerts 不一样正好把 bug 抓出来了：
只判断「签发者是不是锚点」不够，还得判断「这张证书自己是不是锚点」，
因为 Google 的根是交叉签名的，`GTS Root R4` 自己是锚点、但它的签发者 `GlobalSign Root CA`
在 JDK 21 的库里没有。走明文 HTTP 取证书不是弱点：取回来的证书不因为「取回来了」就被信任，
它只是补上一条链路，签名照样要被路径校验一路验到本来就在的锚点。

#### 二、ALPS 只发不认（**没修**）

修完第一件，Google 的报错变成握手末尾被关连接。打开 kwik 日志拿到 BoringSSL 的原话：

```
CRYPTO_ERROR (unexpected_message)
UNEXPECTED_MESSAGE (got type 20, wanted type 8)
```

类型 20 是 `Finished`，类型 8 是 `EncryptedExtensions`。**客户端**会发类型 8 只有一种情况：
ALPS（`application_settings`，17613）。profile 发了这个扩展，Google 支持并接受了它，
于是等我们在 Finished 之前发一条客户端的 `EncryptedExtensions`——而 agent15 没实现，直接发了 Finished。

把 `addApplicationSettingsExtension(clientExtensions, "h3")` 去掉再试：google 302、youtube 200、
nghttp2 200，全通。**所以这一条就是它。**

**TCP 那条路一样中招**：Chrome profile 走 okhttp 请求 `www.google.com` 报
`TlsFatalAlertReceived: unexpected_message(10)`，不带 profile 正常——同一个原因，
只是 BouncyCastle 那边也没实现 ALPS。也就是说**这个 profile 现在连不上 Google，TCP 和 QUIC 都连不上**。

两条路可选，都不便宜：

- **实现 ALPS**：在服务端 EncryptedExtensions 里认出 `application_settings`，然后在 Finished 之前
  发一条客户端 `EncryptedExtensions`（要进握手 transcript）。指纹一个字节不用改。
  代价是 agent15 和 BouncyCastle 两套都要动，而且**载荷没有抓包支撑**——
  抓包只记录了扩展存在，载荷是加密的。只能照 draft 写，再拿 Google 的接受与否当验证。
- **不发 `application_settings`**：五分钟的事，但 Chrome 的扩展列表里少一个，JA4 跟着变——
  正是这个项目一直避免的「指纹说是 Chrome、字节不是」。
