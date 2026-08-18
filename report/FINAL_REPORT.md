# CISA KEV目录分析与查询系统

## 摘要

本文基于课程提供的 `CISA_KEV_2026-07-29.json` 快照，构建了一套从原始 JSON 读取、结构验证、数据清洗到统计分析、组合查询、GUI 展示和机器学习扩展的可复现分析系统。快照包含1,656条漏洞记录和11个原始字段。项目首先验证顶层数量、字段结构、CVE唯一性、日期逻辑、Known/Unknown枚举和CWE列表，再生成公共 Prepared DataFrame，供时间、期限、勒索软件确认状态、厂商产品、CWE和查询模块共同使用。

结果表明，1,485条记录至少包含一个CWE，171条记录的CWE列表为空；厂商记录按文本标签集中，Microsoft为382条，占23.07%，CR5为43.60%，CR10为54.11%，HHI为0.06841758。目录行动窗口中位数为21天，平均为43.69天。文本机器学习扩展使用TF-IDF和KMeans，在候选 `k=4..8` 中选择 `k=8`，最高余弦轮廓系数为0.07116479。该聚类用于探索文本相似性，不作为风险预测或官方漏洞分类。

**关键词：** CISA KEV；JSON校验；数据清洗；CWE多标签；组合查询；Streamlit；TF-IDF；KMeans

## 1. 实验背景与任务目标

CISA Known Exploited Vulnerabilities（KEV）目录收录具有可靠在野利用证据、明确修复措施和CVE标识的漏洞。仅根据CVE编号或描述文本，无法判断数据结构是否完整，也不能直接把目录记录数解释为攻击次数。因此，本项目将数据质量控制作为分析前置步骤，再完成题目要求的统计和查询任务。

项目目标包括：

1. 使用 Python 解析嵌套 JSON，并验证顶层元数据和漏洞数组；
2. 校验记录数、字段、CVE、日期、枚举值和CWE列表；
3. 只进行题目允许的数据清洗，生成可复用的公共数据模型；
4. 分析加入目录时间、行动窗口、勒索软件确认状态、厂商产品与集中度；
5. 正确处理CWE多标签字段并实现可组合查询；
6. 提供直接读取原始JSON的 GUI、结果导出和机器学习扩展；
7. 通过测试、契约校验和运行 Manifest 保证可复现性。

本文所有结论只适用于课程给定的本地快照。KEV记录数不等于漏洞披露数量、攻击次数或厂商安全质量。

## 2. 数据集与字段语义

### 2.1 顶层数据

| 字段 | 含义 |
|---|---|
| `title` | KEV目录标题 |
| `catalogVersion` | 目录版本 |
| `dateReleased` | 快照发布时间 |
| `count` | 顶层声明的记录数 |
| `vulnerabilities` | 漏洞记录数组 |

本次快照目录版本为 `2026.07.29`，发布时间为 `2026-07-29T18:45:59.5809Z`，顶层 `count=1656`，实际漏洞数组长度也是1,656。

### 2.2 原始漏洞字段

每条记录包含以下11个字段：

```text
cveID, vendorProject, product, vulnerabilityName, dateAdded,
shortDescription, requiredAction, dueDate,
knownRansomwareCampaignUse, notes, cwes
```

`cwes` 是列表字段，一条CVE可以有多个CWE或为空。`dateAdded` 表示加入KEV目录的日期，不是漏洞披露日期、攻击发生日期或CVE分配日期。`dueDate` 是目录中要求采取措施的期限，不是实际修复完成日期。`Known` 表示已确认，`Unknown` 表示尚未确认，不能把Unknown解释为“未被勒索软件利用”。

## 3. 需求与系统架构

### 3.1 评分覆盖

| 模块 | 分值 | 实现状态 |
|---|---:|---|
| JSON读取、结构处理、验证和导出 | 20 | 已完成 |
| 时间、期限、勒索软件确认状态 | 20 | 已完成 |
| 厂商、产品和集中度 | 20 | 已完成 |
| CWE多标签和组合查询 | 20 | 已完成 |
| GUI扩展 | 14 | 已完成 |
| 机器学习扩展 | 6 | 已完成 |

### 3.2 分层架构

```text
原始JSON
  -> Loader读取
  -> Validator校验
  -> Cleaner生成Prepared DataFrame
  -> 时间/期限/勒索状态分析
  -> 厂商/产品/集中度分析
  -> CWE/组合查询
  -> TF-IDF + KMeans
  -> Exporter统一导出
  -> CSV / PNG / HTML / Manifest / GUI
```

公共 Prepared DataFrame 是三名成员之间的数据契约。分析模块不互相读取对方导出的CSV，不复制JSON读取或清洗逻辑；GUI直接上传原始JSON后复用公共Loader、Validator、Cleaner和查询服务。`main.py` 只负责流程编排，不承载各模块的统计公式。

## 4. 开发环境、目录与运行方式

项目建议使用 Python 3.11 至 3.13。主要依赖包括 pandas、numpy、matplotlib、plotly、streamlit、scikit-learn、pytest、ruff 和 mypy。

安装并运行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py --input data/CISA_KEV_2026-07-29.json --output outputs
streamlit run app.py
```

核心目录如下：

```text
src/kev_analysis/
  loader.py              JSON读取
  validator.py           结构与逻辑校验
  cleaner.py             Prepared DataFrame
  time_analysis.py       时间分析
  deadline_analysis.py  期限分析
  ransomware_analysis.py 状态分析
  vendor_analysis.py     厂商产品与集中度
  cwe_analysis.py        CWE多标签
  query.py               组合查询
  ml_analysis.py         TF-IDF + KMeans
  pipeline.py            全流程编排
main.py                  CLI入口
app.py                   Streamlit GUI
outputs/                 正式运行产物
report/                  报告文稿
ppt/                     PPT文稿
screenshots/             GUI演示截图
```

## 5. JSON读取、结构处理与数据验证

### 5.1 读取方法

Loader 使用 Python 标准库 `json` 读取文件，分离顶层元数据和 `vulnerabilities` 数组，再转换为原始 DataFrame。读取阶段保留原字段顺序，并保证 `cwes` 在内存中是列表，不提前转成分号字符串。Validator 检查原始输入，Cleaner 在独立副本上生成派生字段。

### 5.2 验证结果

| 检查项目 | 实际结果 | 状态 |
|---|---:|---|
| 顶层 `count` | 1,656 | 通过 |
| DataFrame行数 | 1,656 | 通过 |
| 原始字段数 | 11 | 通过 |
| CVE非空且唯一 | 1,656个唯一值 | 通过 |
| CVE格式错误 | 0 | 通过 |
| 日期格式错误 | 0 | 通过 |
| `dueDate < dateAdded` | 0 | 通过 |
| 非法勒索软件状态 | 0 | 通过 |
| 非列表CWE | 0 | 通过 |
| 非法CWE成员 | 0 | 通过 |
| 关键文本空值/空字符串 | 0 | 通过 |

课程快照黄金计数也全部匹配：1,485条含CWE、171条空CWE、294条Known且含CWE、1,191条Unknown且含CWE。另有6条 `vendorProject` 和10条 `product` 含首尾空格。

正式验证结果来自：

- `outputs/validation/metadata.json`
- `outputs/validation/validation_summary.csv`
- `outputs/validation/validation_details.csv`
- `outputs/validation/field_profile.csv`

## 6. 数据清洗与公共模型

清洗遵循最小修改原则：

1. 保留全部11个原始字段，不覆盖原始值；
2. 对厂商和产品只执行 `.str.strip()`，生成 `vendor_clean` 和 `product_clean`；
3. 转换日期并生成 `added_year`、`added_month`；
4. 计算 `deadline_days`、`has_cwe` 和 `cwe_count`；
5. 空CWE保持为空列表，不填充虚构类别；
6. 不进行模糊匹配、拼写纠正或主观厂商合并；
7. 不原地修改输入DataFrame。

`outputs/prepared/kev_prepared.csv` 共有1,656行、18列。内存中的 `cwes` 仍然是 `list[str]`，只有导出CSV时才进行统一序列化。

## 7. 时间分布分析

### 7.1 方法

程序依据 `dateAdded` 建立2021年11月至2026年7月的连续57个月序列，无记录月份保留为0。年度表同时记录覆盖首月、末月、月份数和完整性。2021年只覆盖11月至12月，2026年只覆盖1月至7月29日，因此完整年度比较使用2022至2025年，并补充1月至7月同期比较。

### 7.2 结果

| 年份 | 记录数 | 覆盖月份 | 完整年度 | 1-7月同期数 |
|---:|---:|---:|:---:|---:|
| 2021 | 311 | 11-12，共2个月 | 否 | 不适用 |
| 2022 | 555 | 1-12，共12个月 | 是 | 477 |
| 2023 | 187 | 1-12，共12个月 | 是 | 113 |
| 2024 | 186 | 1-12，共12个月 | 是 | 87 |
| 2025 | 245 | 1-12，共12个月 | 是 | 152 |
| 2026 | 172 | 1-7，共7个月 | 否 | 172 |

2021年11月有291条、2022年3月有226条，是月序列中的明显高值。该数量只表示加入KEV目录的记录数，不能当作漏洞披露数、攻击次数或网络攻击趋势。

数据来源：`outputs/tables/monthly_added_counts.csv`、`annual_added_summary.csv`、`same_period_comparison.csv`。

![月度新增记录](../outputs/figures/monthly_added_trend.png)

## 8. 处置期限分析

对每条记录定义：

\[
D_i=\text{dueDate}_i-\text{dateAdded}_i
\]

`deadline_days` 是两个日期之间的日历天数，不把开始日期额外计为一天。总体统计如下：

| 指标 | 天数 |
|---|---:|
| 最小值 | 1 |
| 第一四分位数 | 21 |
| 中位数 | 21 |
| 平均值 | 43.69 |
| 第三四分位数 | 21 |
| 最大值 | 184 |

多数记录集中在21天，但存在181至184天的较长行动窗口，因此均值高于中位数。该指标表示目录规定的行动期限，不表示组织实际修复速度，也不能单独衡量漏洞严重程度。

![行动窗口分布](../outputs/figures/deadline_distribution.png)

## 9. 勒索软件确认状态

`knownRansomwareCampaignUse` 只取 `Known` 和 `Unknown`。总体有332条Known，占20.05%；1,324条Unknown，占79.95%。年度Known比例计算为：

\[
K_y=\frac{N_{y,Known}}{N_{y,Known}+N_{y,Unknown}}
\]

| 年份 | Known | Unknown | 总数 | Known比例 |
|---:|---:|---:|---:|---:|
| 2021 | 77 | 234 | 311 | 24.76% |
| 2022 | 125 | 430 | 555 | 22.52% |
| 2023 | 43 | 144 | 187 | 22.99% |
| 2024 | 42 | 144 | 186 | 22.58% |
| 2025 | 26 | 219 | 245 | 10.61% |
| 2026 | 19 | 153 | 172 | 11.05% |

2025和2026的比例较低，但2026是未完整年度，且状态可能随目录后续确认而变化。因此这些结果只作快照内描述，不解释为勒索软件真实发生率趋势。

![年度Known和Unknown](../outputs/figures/ransomware_by_year.png)

## 10. 厂商、产品与集中度

### 10.1 厂商统计

分组只使用 `vendor_clean` 和 `product_clean`。厂商按记录数降序、厂商文本升序稳定排序；厂商-产品组合先按记录数降序、厂商升序、产品升序排序，再截取Top30。

| 排名 | 厂商 | 记录数 | 占比 | 产品数 |
|---:|---|---:|---:|---:|
| 1 | Microsoft | 382 | 23.07% | 69 |
| 2 | Cisco | 95 | 5.74% | 40 |
| 3 | Apple | 93 | 5.62% | 9 |
| 4 | Adobe | 80 | 4.83% | 12 |
| 5 | Google | 72 | 4.35% | 25 |
| 6 | Oracle | 45 | 2.72% | 16 |
| 7 | Apache | 39 | 2.36% | 21 |
| 8 | Ivanti | 35 | 2.11% | 14 |

前三个厂商-产品组合为 Microsoft-Windows（172条，10.39%）、Apple-Multiple Products（53条，3.20%）和Google-Chromium V8（39条，2.36%）。`Multiple Products` 是原始产品文本，未被拆分。

### 10.2 CR5、CR10和HHI

设厂商文本标签份额为 (p_j)：

\[
CR_k=\sum_{j=1}^{k}p_j,\qquad HHI=\sum_jp_j^2
\]

| 指标 | 小数值 | 百分数展示 |
|---|---:|---:|
| CR5 | 0.43599034 | 43.60% |
| CR10 | 0.54106280 | 54.11% |
| HHI | 0.06841758 | 保持0-1口径 |

HHI使用小数份额平方求和，不乘10,000。上述集中度只描述KEV目录记录在厂商文本标签间的分布，不代表市场份额、产品安全质量或实际攻击概率。

![厂商Top15](../outputs/figures/vendor_top15.png)

![厂商累计占比](../outputs/figures/vendor_cumulative_share.png)

## 11. CWE多标签分析

程序使用 `explode()` 将 `cwes` 列表展开成CVE-CWE长表，并对同一关系去重。总体比例的分母为1,485；Known和Unknown子集分母分别为294和1,191。由于一条CVE可对应多个CWE，比例之和可以超过100%。

总体Top CWE如下：

| CWE | 不同CVE数 | 分母 | 占比 |
|---|---:|---:|---:|
| CWE-20 | 118 | 1,485 | 7.95% |
| CWE-78 | 107 | 1,485 | 7.21% |
| CWE-787 | 100 | 1,485 | 6.73% |
| CWE-416 | 92 | 1,485 | 6.20% |
| CWE-119 | 84 | 1,485 | 5.66% |

Known子集中CWE-20和CWE-22均为25条，占8.50%；Unknown子集中CWE-78为95条，占7.98%。这些是标签结构差异，不构成漏洞类型与勒索软件利用之间的因果结论。

![总体CWE Top20](../outputs/figures/cwe_top20.png)

![Known和Unknown CWE比较](../outputs/figures/cwe_known_unknown.png)

## 12. 组合查询函数

题目指定接口为：

```python
filter_kev(
    df,
    start_date=None,
    end_date=None,
    vendor=None,
    ransomware=None,
    cwe=None,
)
```

实现规则：日期作用于 `dateAdded` 闭区间；厂商使用 `vendor_clean` 的不区分大小写字面子串匹配；状态只接受Known、Unknown或None；CWE先转大写并校验 `^CWE-[0-9]+$`，再进行列表成员精确匹配；多个条件按AND组合；结果按 `dateAdded DESC, cveID ASC` 稳定排序；输入DataFrame保持不变；空结果保留完整列结构。

GUI额外使用 `filter_kev_extended()` 增加产品关键词筛选，不改变题目指定核心接口。

三组已导出的查询案例：

| 案例 | 条件 | 记录数 | 厂商数 | Known数 | 最大日期 |
|---:|---|---:|---:|---:|---|
| 1 | 2022年、Microsoft、Known | 51 | 1 | 51 | 2022-12-13 |
| 2 | Microsoft、CWE-119 | 34 | 1 | 4 | 2022-06-08 |
| 3 | 2022年、Unknown、CWE-119 | 60 | 13 | 0 | 2022-09-15 |

数据来源：`outputs/queries/query_cases_summary.csv` 及三个 `query_case_*.csv` 文件。

## 13. GUI设计与实现

GUI使用Streamlit直接上传原始JSON，上传后调用公共Loader、Validator和Cleaner。主要功能包括：

- 展示目录版本、发布日期、原始记录数、含CWE数和校验状态；
- 日期、厂商、产品、Known/Unknown和CWE组合筛选；
- 动态月度新增、厂商Top10和CWE Top20图；
- 查询结果表、CVE详情和数据校验页；
- 当前筛选结果CSV和当前图表PNG导出；
- 机器学习结果页，展示聚类指标、关键词、代表CVE和二维图。

![GUI完整数据概览](../screenshots/01-data-overview.png)

![GUI组合筛选结果](../screenshots/02-combined-query-cwe.png)

截图中的三条件查询为 `Microsoft`、`Known`、`CWE-119`，返回4条记录，证明GUI使用AND逻辑。GUI不读取 `kev_prepared.csv` 作为上传文件，以避免把CSV中的日期字符串和序列化列表误当成已经解析的类型。

## 14. TF-IDF与KMeans机器学习扩展

### 14.1 方法

将 `vulnerabilityName` 和 `shortDescription` 拼接为文本，使用英文停用词、1-2元词组、`min_df=2`、`max_df=0.95` 和最多5,000个特征构建TF-IDF矩阵。随后测试 `k=4,5,6,7,8`，使用随机种子 `20260806`、`n_init=20` 的KMeans，以余弦轮廓系数选择最佳聚类数。TruncatedSVD仅用于二维可视化。

### 14.2 聚类数选择

| k | 轮廓系数 | 惯性 | 是否选择 |
|---:|---:|---:|:---:|
| 4 | 0.04475750 | 1533.4376 | 否 |
| 5 | 0.05239631 | 1512.8712 | 否 |
| 6 | 0.05828975 | 1497.3918 | 否 |
| 7 | 0.06589860 | 1481.5306 | 否 |
| 8 | 0.07116479 | 1469.6543 | 是 |

### 14.3 聚类摘要

| 聚类 | 记录数 | 占比 | Known数 | Known比例 | 代表CVE |
|---:|---:|---:|---:|---:|---|
| 0 | 178 | 10.75% | 36 | 20.22% | CVE-2022-46169 |
| 1 | 669 | 40.40% | 143 | 21.38% | CVE-2024-27348 |
| 2 | 329 | 19.87% | 79 | 24.01% | CVE-2021-27059 |
| 3 | 159 | 9.60% | 51 | 32.08% | CVE-2021-28310 |
| 4 | 62 | 3.74% | 0 | 0.00% | CVE-2020-16009 |
| 5 | 96 | 5.80% | 12 | 12.50% | CVE-2015-0313 |
| 6 | 75 | 4.53% | 11 | 14.67% | CVE-2021-27137 |
| 7 | 88 | 5.31% | 0 | 0.00% | CVE-2021-30665 |

第1类占40.40%，说明大量漏洞文本具有相似的通用描述结构；但轮廓系数较低，聚类间不能视为清晰、互斥的漏洞类型。某个聚类Known数为0只表示当前快照中没有标为Known的记录，不能解释为没有被利用。

![漏洞文本聚类](../outputs/ml/ml_clusters.png)

## 15. 系统测试与可复现性

测试覆盖契约、单元、集成、黄金数据、GUI冒烟和输出一致性。重点检查：

- Loader/Validator对缺失字段、非法JSON、CVE、日期、枚举和CWE的异常处理；
- Cleaner只去首尾空格、保留原始字段、不修改输入；
- 时间序列连续、年度完整性标记和计数守恒；
- 比例和累计比例、CR5、CR10、HHI及稳定Top30排序；
- CWE唯一关系和正确分母；
- 查询闭区间、大小写、精确CWE、AND逻辑、空结果和排序；
- GUI上传、筛选、详情和导出；
- ML固定随机种子、候选k比较和正式产物。

当前整合分支已验证 `62 passed`，Ruff、严格Mypy、冻结校验、接口签名和编译检查通过。完整流水线生成正式CSV、PNG、HTML、ML文件及 `run_manifest.json`。Manifest记录输入SHA-256、运行状态、Python和依赖版本，以及每个产物的哈希、行数和列名。

## 16. 结果讨论、限制与伦理边界

1. `dateAdded` 只反映加入目录的时间，不能替代漏洞披露时间或攻击发生时间；
2. `deadline_days` 是目录行动窗口，不是实际修复时长；
3. `Unknown` 是尚未确认，不能作为未被勒索软件利用的负面证据；
4. 厂商记录数和HHI只反映目录文本标签集中度，不能判断厂商更不安全；
5. CWE是多标签字段，各类比例不要求互斥；
6. TF-IDF+KMeans是探索性无监督分析，不能当作官方分类、风险评分或攻击预测；
7. 数据只来自一个本地快照，不能外推到全部漏洞、所有厂商或未来时间。

## 17. 总结与成员分工

本项目建立了从原始JSON到验证报告、Prepared数据、统计表、图表、查询案例、GUI和机器学习结果的完整流程。数据底座统一了三位成员的字段、清洗和查询口径，统计模块覆盖题目要求的时间、期限、状态、厂商和集中度分析，CWE模块正确处理多标签分母，GUI提供了可操作的上传、筛选、详情和导出体验，机器学习模块提供了可复现的探索性文本聚类。

成员分工如下：

- **成员一**：数据读取、验证、清洗、公共模型、Exporter、Pipeline、契约、测试、最终集成和报告总编；
- **成员二**：时间、期限、勒索软件状态、厂商产品、CR5/CR10/HHI、TF-IDF+KMeans及对应结果分析；
- **成员三**：CWE多标签、组合查询、Streamlit GUI、动态展示、详情、结果导出和现场演示。

## 参考资料

1. CISA Known Exploited Vulnerabilities Catalog：<https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
2. CISA KEV JSON Schema：<https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json>
3. Pandas `json_normalize`：<https://pandas.pydata.org/docs/reference/api/pandas.json_normalize.html>
4. Pandas `explode`：<https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.explode.html>
5. Plotly Treemap：<https://plotly.com/python/treemaps/>
6. 项目内部契约、输出注册表、测试和语义边界文档：`docs/`、`contracts/`。
