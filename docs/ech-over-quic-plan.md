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

`quic` 模块（artifactId `impersonator-quic`）已实现并验证。vendored 的 agent15 之外：
新增 `tech.kwik.agent15.ech` 包 6 个类 + 胶水层 2 个类共 937 行，
往 7 个 vendored 文件里加了 246 行，测试 3 个类共 24 条 582 行。

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

- **现在的 ClientHello 是 agent15 的，不是浏览器的。** 密码套件只有一个、只offer secp256r1
  （`QuicClientConnectionImpl.startHandshake` 里写死的）、扩展的顺序和内容都跟 Chrome 不一样。
- **没有 GREASE ECH。** TCP 那条路对没有 ECHConfig 的主机会发 GREASE ECH（因为浏览器会），
  QUIC 这条路目前是发一个普通的 ClientHello。要对齐指纹的话这是必须补的。
- **ECH 扩展目前放在扩展列表最后。** Chrome 放在哪要照抓包改，改的地方是
  `EchClient.create` 里往 `innerExtensions` / `outerExtensions` 里 add 的位置。
- **一旦要压缩 `ech_outer_extensions`**，inner 和 outer 的扩展顺序就开始互相约束（§5.1），
  bctls 的 `EchClient.groupCompressibleExtensions` 有现成的实现可以搬。
- 上层 proxy-transport 现在可以去掉 `ClashProxies.noteEchNotHonored` 那条 info，
  改成 `ImpersonatorQuic.setEchConfigProvider(EchConfigs.shared(), EchConfigs.shared()::recordRejection)`。
