# 成员一章节：数据底座、系统架构与质量保障

> 适用数据：`CISA_KEV_2026-07-29.json`。本文为最终报告的成员一章节草稿，所有结果数字应以项目运行生成的 `outputs/` 正式产物为准。

## 1. 实验背景与任务目标

CISA Known Exploited Vulnerabilities（KEV）目录收录了具有可靠在野利用证据、明确修复措施和 CVE 标识的漏洞。本文使用课程提供的本地 KEV 快照，完成数据读取、结构验证、日期和字段逻辑检查、数据清洗、统计分析、CWE 多标签分析、组合查询以及可选的 GUI 和机器学习扩展。

本项目的目标不是建立漏洞严重程度评分，也不是预测某个厂商或漏洞未来被攻击的概率，而是基于给定快照，建立一套可复现、可验证、可扩展的分析流水线。分析结论只适用于该本地快照，不能外推为全部互联网漏洞或真实攻击频率。

## 2. 数据集结构与字段语义

### 2.1 顶层结构

JSON 顶层包含以下字段：

| 字段 | 含义 |
|---|---|
| `title` | KEV 目录标题 |
| `catalogVersion` | 目录版本 |
| `dateReleased` | 快照发布时间 |
| `count` | 顶层声明的漏洞记录数 |
| `vulnerabilities` | 漏洞记录数组 |

本次快照的目录版本为 `2026.07.29`，发布时间为 `2026-07-29T18:45:59.5809Z`，顶层声明数量为 1,656，实际数组长度也为 1,656。

### 2.2 漏洞记录字段

每条记录包含 11 个原始字段：

```text
cveID, vendorProject, product, vulnerabilityName, dateAdded,
shortDescription, requiredAction, dueDate,
knownRansomwareCampaignUse, notes, cwes
```

其中 `cwes` 在内存中始终保持为 CWE 字符串列表。一条 CVE 可以对应多个 CWE，也可以没有 CWE。`dateAdded` 表示漏洞加入 KEV 目录的日期，不表示漏洞披露日期、攻击发生日期或 CVE 分配日期。`dueDate` 表示目录中要求采取措施的期限，不表示实际修复完成日期。`Unknown` 仅表示 CISA 尚未确认该漏洞被勒索软件利用，不能解释为“没有被利用”。

## 3. 系统总体架构

项目采用“数据底座、分析服务、统一导出、交互展示”分层架构：

```text
原始 JSON
    |
    v
Loader 读取
    |
    v
Validator 结构与逻辑验证 ---- 失败: 输出校验结果并终止
    |
    v
Cleaner 生成 Prepared DataFrame
    |
    +--> 时间、期限、勒索状态分析
    +--> 厂商、产品与集中度分析
    +--> CWE 多标签分析
    +--> 组合查询服务
    +--> TF-IDF + KMeans 机器学习扩展
    |
    v
统一 Exporter
    |
    +--> CSV / PNG / HTML / Manifest
    +--> Streamlit GUI
```

成员一负责公共数据流和接口边界。后续分析模块接收清洗后的 DataFrame，不自行复制 JSON 读取或清洗逻辑；GUI 则直接读取用户上传的原始 JSON，并复用 Loader、Validator、Cleaner 和查询服务。

完整流水线由 `main.py` 编排，业务公式位于各自分析模块。默认命令执行包括数据底座、四类必做分析、三组查询和机器学习扩展；`--skip-ml` 可在环境缺少机器学习依赖或只检查必做模块时跳过 ML。

## 4. 开发环境与依赖

项目建议使用 Python 3.11 至 3.13。主要依赖如下：

- `pandas`：DataFrame 转换、清洗和统计；
- `numpy`：数值处理；
- `matplotlib`、`plotly`：静态和交互式图表；
- `streamlit`：GUI；
- `scikit-learn`：TF-IDF、KMeans、SVD 和轮廓系数；
- `pytest`：测试；
- `ruff`、`mypy`：代码质量和类型检查。

安装和运行方式：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py --input data/CISA_KEV_2026-07-29.json --output outputs
streamlit run app.py
```

原始 JSON 只作为输入读取，不被程序覆盖。正式产物按 `validation`、`prepared`、`tables`、`queries`、`figures`、`html`、`ml` 和 `manifests` 分类写入 `outputs/`。

## 5. JSON 读取方法

Loader 使用 Python 标准库 `json` 读取文件，并分别提取顶层元数据和 `vulnerabilities` 数组。随后使用等价于 `pd.json_normalize` 的结构化转换方式得到原始 DataFrame。转换过程保留原始字段名称和顺序，不把 `cwes` 提前转换为分号连接的字符串。

读取阶段只负责解析和基本结构获取，不负责修改字段值。这样可以保证 Validator 检查的是原始输入，Cleaner 产生的是独立副本，便于定位数据问题并保证后续模块共享同一数据语义。

## 6. 数据验证

Validator 对字段结构和业务逻辑执行分级检查。冻结快照的实际结果如下：

| 检查项目 | 实际结果 | 状态 |
|---|---:|---|
| 顶层 `count` | 1,656 | 通过 |
| DataFrame 行数 | 1,656 | 通过 |
| 原始字段数量 | 11 | 通过 |
| CVE 非空且唯一 | 1,656 条唯一 | 通过 |
| CVE 格式错误 | 0 | 通过 |
| 日期格式错误 | 0 | 通过 |
| `dueDate < dateAdded` | 0 | 通过 |
| 非法勒索软件状态 | 0 | 通过 |
| 非列表 CWE | 0 | 通过 |
| 非法 CWE 成员 | 0 | 通过 |
| 关键文本空值或空字符串 | 0 | 通过 |

数据中的冻结黄金计数也与题目附件一致：共有 1,485 条记录至少包含一个 CWE，171 条记录的 CWE 列表为空；其中含 CWE 的 Known 记录为 294 条，Unknown 记录为 1,191 条。另有 6 条 `vendorProject` 和 10 条 `product` 含有首尾空格。

验证结果写入：

- `outputs/validation/metadata.json`：元数据、记录数和原始字段；
- `outputs/validation/validation_summary.csv`：各项检查的通过状态和实际值；
- `outputs/validation/validation_details.csv`：详细问题记录；
- `outputs/validation/field_profile.csv`：字段类型、非空数、空值数、空字符串数和唯一值数。

如果存在 `FATAL` 或 `ERROR` 级别的失败项，流水线不会继续导出 Prepared 数据，避免错误输入进入后续统计。

## 7. 数据清洗与公共模型

清洗过程遵循最小修改原则：

1. 保留全部 11 个原始字段，不覆盖原始值；
2. 对 `vendorProject` 和 `product` 仅执行 `.str.strip()`，生成 `vendor_clean` 和 `product_clean`；
3. 将 `dateAdded` 和 `dueDate` 转换为可计算的日期类型；
4. 生成 `added_year`、`added_month`、`deadline_days`、`has_cwe` 和 `cwe_count`；
5. 不对空 CWE 填充 `CWE-0`、`Unknown` 或其他推测值；
6. 不进行模糊匹配、拼写纠正或主观厂商合并；
7. 不原地修改输入 DataFrame。

清洗后的公共表 `outputs/prepared/kev_prepared.csv` 共 1,656 行、18 列。内存中的 `cwes` 仍为列表；只有在 CSV 导出时才按统一规则序列化，避免后续 CWE 精确查询失效。

## 8. 程序目录与模块接口

核心模块职责如下：

| 模块 | 职责 |
|---|---|
| `src/kev_analysis/loader.py` | 读取 JSON、提取元数据和原始记录 |
| `src/kev_analysis/validator.py` | 字段、格式、日期、枚举和黄金计数校验 |
| `src/kev_analysis/cleaner.py` | 生成清洗后的公共 DataFrame |
| `src/kev_analysis/models.py` | 公共数据类、过滤条件和分析结果模型 |
| `src/kev_analysis/query.py` | 组合查询及查询摘要 |
| `src/kev_analysis/pipeline.py` | 编排完整运行流程 |
| `src/kev_analysis/export_utils.py` | 按输出注册表导出表格、图表和 Manifest |
| `main.py` | 命令行入口和参数编排 |
| `app.py` | Streamlit GUI 编排 |

公共接口的设计原则是：验证器不改变数据，清洗器返回独立 Prepared 数据，分析函数不修改输入，Exporter 不参与指标计算，GUI 复用公共业务函数。

## 9. 测试、质量检查与可复现性

项目测试覆盖以下层次：

- Loader、Validator、Cleaner、Query 的正常、边界和异常输入；
- 冻结字段、函数签名和输出注册表契约；
- `load -> validate -> prepare -> analyze -> export` 集成流程；
- 1,656 条记录、1,485/171 条 CWE 黄金计数；
- GUI 上传、筛选、重置、详情和导出冒烟流程；
- KMeans 固定随机种子、多组 `k` 比较和聚类输出。

当前整合分支的验证结果为：`62 passed`，Ruff 检查通过，严格 Mypy 检查通过，冻结文件校验、接口签名检查和 Python 编译检查通过。完整运行后生成 39 个正式分析产物，并由 `run_manifest.json` 记录输入 SHA-256、运行状态、软件版本以及输出文件哈希、行数和列名。

推荐的最终验收命令：

```powershell
python -m pytest tests -q
python -m ruff check src tests main.py app.py scripts
python -m mypy src
python scripts/verify_freeze.py
python main.py --check-contracts
python main.py
```

报告和 PPT 中的数字应直接读取 `outputs/`，不应手工重新计算。交付前还应在全新环境中按照 README 完成一次复现，并排除虚拟环境、缓存和 IDE 文件。

## 10. 项目总结与成员分工

成员一完成了从原始 JSON 到公共 Prepared 数据的完整数据底座，并负责统一接口、流水线、测试和质量门槛。该底座使成员二能够直接开展时间、期限、勒索状态、厂商和机器学习分析，使成员三能够在 GUI 中上传原始 JSON 后复用同一套读取、验证、清洗和查询逻辑。

三人分工如下：

- **成员一**：数据读取、验证、清洗、公共模型、流水线、测试、集成和报告总编；
- **成员二**：时间、期限、勒索状态、厂商产品、集中度和机器学习分析；
- **成员三**：CWE 多标签分析、组合查询、GUI、动态图表和结果展示。

本模块的主要限制是：校验和分析针对课程给定的本地快照，清洗只处理首尾空格，不进行主观实体归并；目录记录数量不等同于攻击次数，`Unknown` 不等同于“未被利用”，期限也不等同于实际修复耗时。后续报告必须沿用这些语义边界。

## 11. 成员一答辩要点

答辩时成员一重点说明：

1. 为什么先验证再清洗：避免错误数据进入分析，并保留问题定位依据；
2. 为什么保留原字段：保证可追溯性，清洗字段只用于分组、排序和查询；
3. 为什么 `cwes` 不直接转字符串：后续需要进行多标签展开和精确成员匹配；
4. 如何保证复现：固定输入快照、固定随机种子、统一输出注册表和运行 Manifest；
5. 如何保证三人协作：所有分析模块共享同一个 Prepared 数据契约，不各自读取或改写原始数据。
