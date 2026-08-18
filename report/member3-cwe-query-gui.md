# 成员3：CWE、组合查询与GUI章节草稿

> 适用快照：`CISA_KEV_2026-07-29.json`，目录版本 `2026.07.29`，共1,656条记录。
> 本文数字来自完整流水线生成的 `outputs/` 正式产物；比例在CSV中保存为0到1的小数，
> 正文中显示为百分数。CWE描述的是软件弱点类别，不等同于CVE漏洞实例，也不表示风险等级。

## 1. CWE概念与多标签结构

CWE（Common Weakness Enumeration）用于描述软件或硬件中的弱点类别，例如输入验证不当、
命令注入和越界写入。CVE标识具体漏洞实例，而CWE用于说明漏洞可能涉及的弱点类型，二者是
“实例—类别”关系。一个CVE可能对应零个、一个或多个CWE，因此原始字段`cwes`必须保持为
`list[str]`，不能把它当作普通字符串分组，也不能只取列表中的第一个值。

冻结快照共1,656条记录，其中1,485条至少包含一个CWE，171条没有CWE。含CWE的记录中，
`Known`子集为294条，`Unknown`子集为1,191条。`Unknown`仅表示CISA尚未确认该漏洞被用于
勒索软件活动，不能解释为“未被利用”。

数据来源：`outputs/validation/metadata.json`、`outputs/validation/field_profile.csv`；
冻结核对数来自程序校验契约。

## 2. CWE展开与计数方法

### 2.1 长表转换

程序通过`build_cwe_long_table(df)`把多标签字段转换为长表：

1. 检查`cveID`、`cwes`、勒索软件状态、日期、厂商和产品等依赖列；
2. 验证每个`cwes`值均为列表，列表成员满足`^CWE-[0-9]+$`；
3. 排除空列表记录，再用`explode("cwes")`把每个CVE-CWE关系展开为一行；
4. 按`cveID,cwe`去重，避免同一CVE内重复标签造成重复计数；
5. 按`cveID ASC, cwe ASC`稳定排序，并返回新的DataFrame。

展开后的核心结构为：

| 字段 | 含义 |
|---|---|
| `cveID` | 具体漏洞标识 |
| `cwe` | 当前展开行对应的弱点类别 |
| `knownRansomwareCampaignUse` | `Known`或`Unknown`确认状态 |
| `dateAdded` | 加入KEV目录的日期 |
| `vendor_clean`、`product_clean` | 仅去除首尾空格后的分组字段 |

输出文件：`outputs/tables/cve_cwe_long.csv`。

### 2.2 不同CVE计数与分母

每个CWE的计数采用`nunique(cveID)`，而不是长表行数。总体及两个状态子集的比例为：

\[
S_c=\frac{N_c}{1485},\qquad
S_{c,K}=\frac{N_{c,K}}{294},\qquad
S_{c,U}=\frac{N_{c,U}}{1191}
\]

其中，`N_c`为含CWE记录中属于类别`c`的不同CVE数；`N_{c,K}`和`N_{c,U}`分别是
`Known`和`Unknown`子集内的不同CVE数。因为一个CVE可以有多个CWE，各类别占比之和可以
超过100%，不能把这些比例解释为互斥构成比。

## 3. 总体CWE统计

| 排名 | CWE | 不同CVE数 | 占1,485条含CWE记录的比例 |
|---:|---|---:|---:|
| 1 | CWE-20 | 118 | 7.95% |
| 2 | CWE-78 | 107 | 7.21% |
| 3 | CWE-787 | 100 | 6.73% |
| 4 | CWE-416 | 92 | 6.20% |
| 5 | CWE-119 | 84 | 5.66% |
| 6 | CWE-22 | 76 | 5.12% |
| 7 | CWE-502 | 69 | 4.65% |
| 8 | CWE-94 | 66 | 4.44% |
| 9 | CWE-287 | 41 | 2.76% |
| 10 | CWE-306 | 38 | 2.56% |

总体频数最高的是CWE-20，共118个不同CVE，占含CWE记录的7.95%；其后是CWE-78和
CWE-787。该结果只描述课程快照中已进入KEV目录且有CWE标注的记录分布，不能代表所有已
披露漏洞的CWE分布，也不能据此比较弱点的危害程度。

数据来源：`outputs/tables/cwe_overall_summary.csv`；图：
`outputs/figures/cwe_top20.png`。

## 4. Known与Unknown子集比较

| 子集排名 | Known：CWE | 不同CVE数 | 子集占比 | Unknown：CWE | 不同CVE数 | 子集占比 |
|---:|---|---:|---:|---|---:|---:|
| 1 | CWE-20 | 25 | 8.50% | CWE-78 | 95 | 7.98% |
| 2 | CWE-22 | 25 | 8.50% | CWE-20 | 93 | 7.81% |
| 3 | CWE-502 | 24 | 8.16% | CWE-787 | 90 | 7.56% |
| 4 | CWE-287 | 16 | 5.44% | CWE-416 | 82 | 6.88% |
| 5 | CWE-306 | 12 | 4.08% | CWE-119 | 76 | 6.38% |
| 6 | CWE-78 | 12 | 4.08% | CWE-94 | 57 | 4.79% |
| 7 | CWE-416 | 10 | 3.40% | CWE-22 | 51 | 4.28% |
| 8 | CWE-59 | 10 | 3.40% | CWE-502 | 45 | 3.78% |
| 9 | CWE-787 | 10 | 3.40% | CWE-843 | 36 | 3.02% |
| 10 | CWE-89 | 10 | 3.40% | CWE-284 | 31 | 2.60% |

两个子集必须各自使用自己的分母。Known子集中CWE-20和CWE-22并列为8.50%，CWE-502为
8.16%；Unknown子集中CWE-78为7.98%，CWE-20为7.81%，CWE-787为7.56%。这些差异是
快照内的描述性比较，不等于某类弱点导致勒索软件利用，也不能进行因果推断。尤其要避免用
总体1,485条作为两个子集的共同分母，否则会低估子集内部占比。

数据来源：`outputs/tables/cwe_known_summary.csv`、
`outputs/tables/cwe_unknown_summary.csv`；图：
`outputs/figures/cwe_known_unknown.png`。

## 5. 组合查询函数设计

题目指定接口为：

```python
filter_kev(
    df,
    start_date=None,
    end_date=None,
    vendor=None,
    ransomware=None,
    cwe=None,
) -> tuple[pd.DataFrame, QuerySummary]
```

所有有效条件按AND组合。日期作用于`dateAdded`闭区间；只提供一侧日期时分别执行
`>=start_date`或`<=end_date`。厂商条件在`vendor_clean`上执行不区分大小写、非正则的
字面子串匹配。CWE先去除首尾空白并转大写，再执行格式校验，最后在`cwes`列表内精确匹配。
勒索软件状态只接受`Known`、`Unknown`或`None`。

返回结果按`dateAdded DESC, cveID ASC`稳定排序，不修改输入DataFrame。`QuerySummary`
统一返回记录数、不同厂商数、最新加入日期和Known数量，使CLI、固定案例和GUI使用同一业务
口径。GUI需要的产品条件放在`filter_kev_extended`包装器中，并复用核心函数，避免出现两套
筛选逻辑。

## 6. 参数校验与异常处理

| 错误码 | 触发条件 | 处理方式 |
|---|---|---|
| `KEV-QRY-001` | 日期无法解析，或开始日期晚于结束日期 | 抛出`InvalidDateRangeError` |
| `KEV-QRY-002` | 状态不是`Known`、`Unknown`或`None` | 抛出`InvalidRansomwareStatusError` |
| `KEV-QRY-003` | CWE不满足`CWE-数字`格式 | 抛出`InvalidCweError` |
| `KEV-QRY-004` | 缺少prepared字段，或使用CWE筛选时`cwes`不是列表 | 抛出`MissingPreparedColumnError` |

空白厂商、产品或CWE条件视为未提供。合法查询返回0行不是异常：结果仍保留完整列结构，摘要
计数为0，`max_date=None`，GUI显示空结果提示。错误对象统一包含`code`、`message`和
`context`，界面捕获`KevError`后向用户显示可读消息并停止当前计算。

## 7. 三组可复现查询案例

默认案例不是手工挑选，而是从冻结快照按稳定排序规则选择高频且非空的条件组合。

| 案例 | 条件（AND） | 记录数 | 厂商数 | 最新加入日期 | Known数 | 输出文件 |
|---:|---|---:|---:|---|---:|---|
| 1 | 2022全年；Microsoft；Known | 51 | 1 | 2022-12-13 | 51 | `query_case_1.csv` |
| 2 | Microsoft；CWE-119 | 34 | 1 | 2022-06-08 | 4 | `query_case_2.csv` |
| 3 | 2022全年；Unknown；CWE-119 | 60 | 13 | 2022-09-15 | 0 | `query_case_3.csv` |

案例1覆盖日期、厂商和状态组合；案例2覆盖厂商和CWE组合；案例3覆盖日期、状态和CWE组合。
程序同时导出摘要表与每组实际记录，便于复核查询条件、排序和计数，而不是只展示一个手工
填写的结果数字。

数据来源：`outputs/queries/query_cases_summary.csv`及三个`query_case_*.csv`。

## 8. GUI需求分析

GUI面向不直接编写Python代码的使用者，需要完成以下任务：

1. 上传课程原始JSON，显示目录版本、发布日期、记录数和含CWE记录数；
2. 在侧栏组合日期、厂商、产品、Known/Unknown和CWE条件，并支持一键重置；
3. 实时显示筛选记录数、厂商数、Known数量和最新加入日期；
4. 提供月度、厂商Top 10和CWE Top 20三种随筛选结果变化的图表；
5. 展示查询表格和单条CVE详情，包括描述、要求采取的行动及备注；
6. 展示输入校验摘要与字段画像；
7. 导出当前筛选结果CSV和当前图表PNG；
8. 展示完整流水线预生成的机器学习结果。

非功能需求包括：复用公共加载、校验、清洗和查询函数；校验失败时禁止继续正式分析；空结果
可解释；本地离线运行；预先准备截图以应对答辩现场环境异常。

## 9. GUI界面设计

界面采用宽屏单页布局。左侧栏负责输入和组合筛选，主区域顶部先呈现数据加载状态和四个
元数据指标，再显示四个查询摘要指标。主体通过五个标签页分离不同任务：

| 标签页 | 主要内容 |
|---|---|
| 动态可视化 | 月度新增、厂商Top 10、CWE Top 20单选切换及PNG下载 |
| 查询结果 | 冻结核心字段表格及CSV导出 |
| CVE详情 | 单条CVE选择、基础字段、漏洞简述、行动要求和备注 |
| 数据校验 | 校验摘要和可展开的字段画像 |
| 机器学习 | 候选k、选定k、轮廓系数、二维图、聚类摘要、关键词和代表记录 |

侧栏只负责筛选条件，不把结果和解释塞入侧栏；主区域按“状态—摘要—分析/明细”的顺序组织，
使现场演示可以沿同一视觉路径完成。

## 10. GUI核心流程

```text
上传原始JSON
  -> load_kev_json读取元数据与11字段
  -> validate_raw_kev执行完整校验
  -> 校验失败：展示错误并停止
  -> 校验通过：prepare_kev_dataframe生成衍生字段
  -> ExtendedKevFilter收集界面条件
  -> filter_kev_extended执行AND组合筛选
  -> 生成摘要、动态图、表格与CVE详情
  -> 用户导出当前CSV或PNG
  -> 机器学习页读取outputs/ml中的预生成产物
```

动态图只统计当前筛选子集，不套用全量快照的冻结分母；正式报告中的CWE总体比例仍以
1,485、294和1,191为分母。这样区分了“报告级固定统计”和“界面当前子集概览”。

## 11. GUI运行截图与演示说明

正式截图统一放在`screenshots/`，拍摄顺序、文件名、图注和验收要求见
`screenshots/README.md`。报告建议至少插入以下四张：

- `01-upload-and-metadata.png`：加载成功、元数据和筛选区；
- `02-combined-query-cwe.png`：组合筛选、摘要指标与CWE动态图；
- `04-cve-detail.png`：单条CVE详情；
- `06-ml-results.png`：机器学习结果页。

答辩时按“上传—组合查询—动态图—详情—导出—机器学习”的顺序演示；若现场无法运行，按
截图编号顺序讲解。截图只作为界面与流程证据，报告中的统计数字仍引用正式CSV输出。

## 12. 机器学习界面展示

机器学习页不在浏览器中重新训练，而是读取`outputs/ml/`下的正式产物，保证GUI、报告和PPT
数字一致。当前快照比较`k=4`至`k=8`，选择`k=8`，轮廓系数为0.07116。页面顶部显示候选
聚类数、选定k和轮廓系数；中部显示二维聚类图与聚类摘要；底部允许按聚类查看关键词和按
中心距离排序的代表CVE。

轮廓系数较低，且最大聚类包含669条记录、占40.40%，说明文本类别存在明显重叠。因此该页
定位为探索性浏览工具，不能把聚类当作CISA官方弱点分类、风险评分或勒索软件利用预测。

数据来源：`outputs/ml/ml_cluster_selection.csv`、`ml_cluster_summary.csv`、
`ml_cluster_keywords.csv`、`ml_cluster_results.csv`和`ml_clusters.png`。

## 13. 正确性验证与局限

成员三模块的测试覆盖：CWE列表展开与去重、不同CVE计数、三种固定分母、排序稳定性、空输入、
非法CWE和非法状态；查询的闭区间边界、单侧日期、AND组合、字面子串、空条件、空结果、参数
异常和输入不变性；三组案例非空及导出列契约；GUI启动、子集统计和空图支持。

结果仅适用于课程冻结快照。CWE标签可能缺失，一个CVE可以有多个标签；Known/Unknown是
CISA确认状态；GUI筛选与机器学习只帮助浏览目录，不能替代漏洞严重度评估、组织资产暴露
分析或实际修复决策。
