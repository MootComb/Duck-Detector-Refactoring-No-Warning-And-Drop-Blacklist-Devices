# Duck Detector 编码规范

## 1. 文档目的

本规范用于统一 Duck Detector 项目的编码、模块划分、测试、文档与提交要求。

适用范围：

- Kotlin / Compose 代码
- Native / JNI 代码
- Gradle / CI / 脚本
- 文档与 commit

默认原则：

- 先保证结论正确，再追求代码简短
- 先保证模块边界清晰，再考虑复用
- 先补足验证，再扩大改动范围

## 2. 总体原则

### 2.1 单一职责

- 一个类只负责一件清晰的事。
- 一个 probe 只负责一种探测语义，不要把多个独立异常揉进一个大类里。
- 一个 reducer 负责汇总与判定，不负责底层采集。
- 一个源文件只放语义上紧密相关的声明。任何源文件（Kotlin、Java、C/C++、汇编、Gradle 脚本、Python、Shell）都不得达到 400 行，这对应 Kotlin 编码规范“文件不超过几百行”的建议，由 `check-source-file-length.py` 强制。接近上限时按语义归属拆分，不要压缩格式，也没有基线豁免。
- 拆分计时敏感的 native 代码时，计时读取与被测调用这条测量路径留在同一个翻译单元，只移走测量之前或之后运行的代码。

### 2.2 小步提交

- 一个 commit 应只表达一个主目标。
- 不要把功能新增、重构、格式清理、版本修改、无关文档改动混在一起。
- 如果必须一起提交，正文里要明确说明它们为何耦合。

### 2.3 可追溯

- 代码必须能解释“为什么这样做”。
- 探测类改动要能追溯到具体证据语义，而不是只留下启发式代码。
- 重要判断应在命名、注释、测试或文档中体现出处和意图。

## 3. 模块化要求

### 3.1 按功能分层

每个 feature 是 `feature/<name>/` 下的一组 Gradle 模块，层次由构建强制：

- `domain`：结果与报告模型、状态定义、判定规则（纯 JVM）
- `data`：采集、解析、桥接、底层探测
- `presentation`：卡片模型、报告投影与卡片映射（纯 JVM）
- `detector`（仅检测器）：唯一的 headless `<Name>Detector` 对象，把 data、domain 与 presentation 绑定给 SDK 与 UI
- `ui`：Compose 卡片与对话框（`internal`），以及用 `CardDetectorFeature` 构造、以 `detectorFeature` 导出的 `DetectorFeature`；检测器声明了 consent 时，提示与设置项也写在这里（`consentCards`）

依赖方向为 `:app` → `:sdk` → `:feature` → `:capability` → `:core`，feature 之间、capability 之间互不依赖。新增检测器只改动 `feature/<name>/` 与 `DetectorCatalog` 中的一行；带 native unit 时，再加 `DUCKDETECTOR_NATIVE_UNITS` 与 `native-boundaries.json` 各一条，这些脚手架都会写好。仪表盘卡片列表由构建根据各 ui 模块生成；探针需要的 service、intent filter 等 manifest 条目，写在所属 data 模块的 manifest 里。模块职责、禁止知识与扩展规则见 [`docs/architecture/README.md`](./docs/architecture/README.md)；`.github/policies/` 中的边界策略在构建与 CI 中校验。

不要出现这些情况：

- `presentation` 直接调用 native / JNI
- `domain` 持有 Android Framework 细节
- 判定逻辑（domain 规则、TEE 的 `TeeReportReducer`）直接做文件系统、Binder、KeyStore 访问
- `:app`、dashboard、导出或通知代码按具体检测项分支
- 一层根据另一层写出的文字做判断（见 4.1）

### 3.2 Probe 拆分规则

新增检测时，按脚手架生成的结构拆分：

- `Probe`（data）：执行一次独立探测，输出结构化结果
- `<Name>Repository`（data）：协调多个 probe，汇总成 `<Name>Report`
- `<Name>ReportStatus`（domain）：根据报告给出判定
- `<Name>CardModelMapper` 与 `<Name>DetectorReport`（presentation）：投影出卡片模型与导出内容
- `<Name>DetectorCard`（ui）：只负责展示

TEE 的证据较多，在 data 层另有 `TeeReportReducer` 负责汇总。

不要把“采集 + 判定 + UI 文案”写在同一个类里。

### 3.3 共享逻辑收敛

- 只有在两个以上模块确实共享同一语义时，才抽公共 helper。
- 多个 feature 共享的证据采集放入 `:capability`；capability 只采集，不判定。
- 公共 helper 必须表达稳定语义，不要为了省几行代码强行抽象。
- 涉及安全级别、判定等级、字段兼容映射的 helper，要优先测试覆盖。

### 3.4 允许耦合的情况

以下场景可以接受耦合，但要在 commit 或注释里说明原因：

- virtualization / preload / native runtime 一起变动
- TEE deep checks 与 reducer / presentation 联动修改
- JNI bridge 改动导致 Kotlin parser 同步修改

## 4. Kotlin / Compose 规范

### 4.1 Kotlin

- 命名优先表达语义，不优先缩写。
- 返回结构化结果，不要靠字符串做判断。presentation、ui、core、SDK、app 与 native 代码不得比较、搜索或截取其他层写的文字（label、title、summary、detail 等）；需要区分时，在产生证据的地方带上枚举、类型化 id 或标志，由枚举自带 label（`check-text-protocols.py` 校验）。data 层可以解读平台给出的文字，例如错误信息，但要在那里转成类型。
- SDK 契约模块（`:sdk:runtime`、`:core:detector`、`:core:report`、`:core:evidence`）不声明 `data class`：给 data class 加属性会改变构造函数与 `copy` 的签名，调整属性顺序会改变 `componentN` 的含义，都会破坏已编译的宿主（见 Kotlin 的库作者兼容性指南）。值类型写成 `@ContractValue` 普通类，模块应用 `duckdetector.contract-values`，由 Poko 生成与 data class 相同的 `equals`、`hashCode` 与 `toString`。给契约值类型加属性时，把原来的构造函数保留为次构造函数。
- SDK 契约中的声明不能一步删除或不兼容地修改：先标 `@Deprecated`，message 写明替代项，能给出时附 `ReplaceWith`；之后的版本依次把级别调到 `WARNING`、`ERROR`、`HIDDEN`，最后才删除。检测器自己的类型化对象标注 `@DetectorSpecificApi`，不在契约内，不受这个周期约束。兼容性策略见 [SDK 指南](./docs/guides/sdk-integration.md#compatibility)。
- 文案不经反射获得：不要用类名拼出文案或报告内容，异常用 `FailureName`（`:core:evidence`）或 `PlatformFailureName`（`:core:platform`）命名；探针确需反射访问隐藏 API 时，写进 `reflection-allowlist.json` 并说明原因（`check-reflection-boundaries.py` 校验）。
- `Result` 数据类要让“成功 / 失败 / 跳过”状态清晰可区分。
- 对异常路径，优先保留可审计的 `detail`，不要只返回布尔值。

### 4.2 Compose

- UI 层只消费报告与展示模型，不重新发明判定逻辑。
- 不要在 Compose 组件里重新拼安全结论。
- 展示文案在 presentation 层根据类型化的值生成，证据等级与 domain 判定保持一致。

### 4.3 注释

- 只给非显然逻辑写注释。
- 注释应解释“为什么”，不是重复“代码在做什么”。
- 对兼容 API、厂商差异、行为学阈值，必要时写明背景。

## 5. Native / JNI / 兼容性规范

### 5.1 Native 改动

- Native 结果要输出稳定、可解析的结构，而不是临时字符串拼接：payload 中的每个值用 `escape_payload_value` 转义，Kotlin 侧用 `NativePayloadCodec` 解析。
- 修改 native payload 时，要同步更新 Kotlin 侧 parser，并保持向后兼容或明确中断。
- native unit 之间不读对方的文字（finding 的 label、group 等），用枚举传递类别。
- ABI 敏感改动必须完成构建验证。

### 5.2 Android 兼容性

- 涉及 API level 差异时，要明确区分新旧路径。
- 对 deprecated API 的兼容访问，要集中封装，避免散落在多个调用点。
- 对 `KeyInfo`、Binder、系统属性、`/proc` 等平台行为，不要假设所有厂商完全一致。

## 6. 测试与验证要求

### 6.1 基本要求

- 新增 probe 必须至少有一个结果层测试。
- 修改 reducer / mapper 时，必须补展示或判定回归测试。
- 修复 bug 时，优先先补回归测试，再改实现。

### 6.2 必跑验证

每次改动至少执行以下验证：

- `./gradlew unitTest :app:assembleDebug :app:lintDebug`：运行所有模块的单测，构建四个 ABI 的 native 库，并执行覆盖全部依赖模块的 lint
- `for s in .github/scripts/check-*.py; do python3 "$s"; done`：全部仓库守卫，几秒内完成，包括源文件不得达到 400 行、检测器触点、证据记录、JNI 契约、native 边界、反射与文本协议

按改动类型追加以下验证。CI 会运行其中全部的 Gradle 任务、SDK 构建与自测，并额外生成一个 native 检测器来检查脚手架：

- TEE probe / reducer 改动：相关 unit tests
- 模块边界或 build-logic 改动：`./gradlew :build-logic:test`
- 依赖或模块改动（任何 `build.gradle.kts`、`libs.versions.toml`、新增模块）：`./gradlew buildHealth`，按报告增删依赖或调整 `api` / `implementation`
- 新增检测器：用 `python3 scripts/new_detector.py <name> --description "..."` 生成，按 [docs/guides/adding-a-detector.md](./docs/guides/adding-a-detector.md) 填写各层
- SDK 或 headless 模块改动：`./gradlew :sdk:aar:publish :sdk:aar:verifySdkAar`，再运行 `./gradlew -p samples/sdk-consumer assembleDebug`
- SDK 契约模块（`:sdk:runtime`、`:core:detector`、`:core:report`、`:core:evidence`）的公开 API 改动：`./gradlew checkPublicApi`；确属有意的改动运行 `./gradlew updatePublicApi`，并在提交中审阅 `api/*.api` 的 diff
- 脚手架或模板改动：`python3 scripts/test_new_detector.py`
- 检查脚本改动：运行对应的 `.github/scripts/test-*.py` 自测
- 文案或卡片映射改动：对应 mapper / reducer tests；检测器在 golden 导出中且卡片或导出有变化时，运行 `DD_UPDATE_GOLDEN=1 ./gradlew :app:testDebugUnitTest --tests '*DashboardExportGoldenTest*'` 重新生成，并审阅 diff

### 6.3 真机验证

以下类型不能只依赖 JVM 单测：

- AndroidKeyStore 硬件路径
- StrongBox 行为
- Binder hook / native anti-hook
- `/proc` / SELinux / mount / cgroup 运行态探测
- manifest 声明与进程入口：app zygote preload、隔离服务、NativeActivity 启动

如果没有真机验证，要在最终说明里明确指出。

## 7. 文档同步要求

以下改动原则上应同步文档：

- 新增或删除检测项
- 新增或修改信号：同一提交里更新该检测器或 capability 的 `EVIDENCE.md`（`check-evidence-records.py` 校验）
- 修改 verdict 影响规则
- 修改证据层级定义
- 修改 release / CI / Telegram 推送行为
- 修改模块边界、capability 或 native unit：同步更新 `docs/architecture/README.md`；有意保留的边界例外和尚未解决的问题记入 `docs/architecture/follow-ups.md`，并写明原因
- 修改 SDK 的公开 API、宿主步骤或 manifest：同步更新 `docs/guides/sdk-integration.md`

涉及 TEE、native root、virtualization 这类检测口径变化时，先更新对应的 `EVIDENCE.md`；用户能感知的变化再同步到 `README.MD` 与 `README_ZH.MD`。

## 8. Commit 规范

### 8.1 基本格式

commit 标题使用英文，推荐格式：

`type(scope): imperative summary`

示例：

- `feat(tee): add AES-GCM keystore round-trip deep check`
- `fix(nativeroot): preserve SELinux process contexts in cgroup parsing`
- `refactor(virtualization): split preload parsing from reducer logic`

### 8.2 type 建议

- `feat`：新增功能或检测能力
- `fix`：修复错误、误判、兼容性问题
- `refactor`：重构但不改变外部语义
- `test`：测试补充或重构
- `docs`：文档修改
- `build`：构建、依赖、lint、签名、发布流程
- `ci`：CI 工作流与仓库守卫脚本
- `chore`：杂项维护

### 8.3 scope 要求

- scope 应尽量对应真实模块。
- 优先使用 feature、capability 名或工程域名，例如：
    - `tee`
    - `nativeroot`
    - `selinuxpolicy`
    - `sdk`
    - `core`
    - `build-logic`

不要使用无信息量 scope：

- `misc`
- `update`
- `stuff`

### 8.4 标题要求

- 标题使用祈使句。
- 标题应说明“做了什么”，不是“这个提交很重要”。
- 不要把多个主语义塞进同一个标题。
- 标题建议控制在 72 个字符左右。

### 8.5 正文要求

commit 正文使用英文，推荐包含三部分：

- 背景：为什么要改
- 变更：具体改了什么
- 验证：跑了哪些测试或构建

推荐风格：

- 先写 1 到 2 段背景说明
- 再用 flat bullets 列出关键变更
- 结尾以 `Verification:` 开头，写明跑过的测试与构建

### 8.6 不合格 commit 示例

以下提交信息不应出现：

- `update`
- `fix bug`
- `try fix`
- `misc changes`
- `wip`

这些标题无法表达模块、目标与风险边界。

## 9. 变更边界要求

- 不要在同一提交里混入无关格式化。
- 不要顺手修改无关 feature 的命名和文案。
- 不要因为方便而重写大段无关代码。

如果工作区里已有他人改动：

- 先理解再兼容
- 不要直接覆盖
- 不要回退不属于本任务的变更

## 10. 最终交付要求

完成编码后，输出说明至少应交代：

- 改了什么
- 是否完成测试 / 构建
- 是否还有真机验证缺口
- 是否同步了相关文档

如果没有完成某项验证，不要省略，要明确说明。
