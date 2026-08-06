# 数据契约

## 1. 顶层JSON契约

必需字段：

| 字段 | 类型 | 必需 | 说明 |
|---|---|---:|---|
| `title` | string | 是 | 目录标题 |
| `catalogVersion` | string | 是 | 目录版本 |
| `dateReleased` | string | 是 | 本地快照发布日期 |
| `count` | integer | 是 | 顶层声明记录数 |
| `vulnerabilities` | array<object> | 是 | 漏洞记录数组 |

`count` 必须等于 `len(vulnerabilities)`，且本快照预期为1656。

## 2. 原始记录字段

原始字段必须完整保留，禁止覆盖、重命名、删除或改变语义。

| 顺序 | 字段 | 内存类型 | 约束 | 空值策略 |
|---:|---|---|---|---|
| 1 | `cveID` | string | 唯一；`^CVE-[0-9]{4}-[0-9]{4,19}$` | 禁止为空 |
| 2 | `vendorProject` | string | 保留原文 | 禁止为空 |
| 3 | `product` | string | 保留原文；`Multiple Products`不得拆分 | 禁止为空 |
| 4 | `vulnerabilityName` | string | 保留原文 | 禁止为空 |
| 5 | `dateAdded` | raw阶段string；prepared阶段Timestamp | 严格`YYYY-MM-DD` | 禁止为空 |
| 6 | `shortDescription` | string | 保留原文 | 禁止为空 |
| 7 | `requiredAction` | string | 保留原文 | 禁止为空 |
| 8 | `dueDate` | raw阶段string；prepared阶段Timestamp | 严格`YYYY-MM-DD`；不得早于`dateAdded` | 禁止为空 |
| 9 | `knownRansomwareCampaignUse` | string | 仅`Known`或`Unknown` | 禁止为空 |
| 10 | `notes` | string | 保留原文；允许空字符串 | 不填充 |
| 11 | `cwes` | `list[str]` | 可为空列表；成员匹配`^CWE-[0-9]+$` | 空列表合法，不得填充 |

## 3. 公共衍生字段

| 字段 | 内存类型 | 生成规则 | 约束 |
|---|---|---|---|
| `vendor_clean` | string | `vendorProject.str.strip()` | 只去除首尾空白，不做其他规范化 |
| `product_clean` | string | `product.str.strip()` | 只去除首尾空白，不做其他规范化 |
| `added_year` | nullable integer | `dateAdded.dt.year` | 四位年份 |
| `added_month` | string | `dateAdded`格式化为`YYYY-MM` | 固定7字符 |
| `deadline_days` | nullable integer | `(dueDate-dateAdded).days` | 必须`>=0` |
| `has_cwe` | bool | `len(cwes)>0` | 不允许空值 |
| `cwe_count` | nullable integer | `len(cwes)` | 必须`>=0` |

机器学习专用字段（如`analysis_text`、`cluster_id`）不属于公共prepared契约，必须留在ML模块输出中，禁止写回核心DataFrame作为其他模块依赖。

## 4. 快照核对常量

这些值用于验证老师给定快照，不应被程序“修正”出来：

- 总记录数：1656；
- 原始字段数：11；
- 空CWE列表：171；
- 含至少一个CWE：1485；
- Known且含CWE：294；
- Unknown且含CWE：1191；
- `vendorProject`首尾有空格：6；
- `product`首尾有空格：10。

若实际输入与上述快照不一致：

- 命令行批处理默认作为`FATAL`并终止评分版运行；
- GUI可提示“输入不是课程指定快照”，但不得伪造通过；
- 若老师后续发布新版数据，必须通过变更流程更新契约版本。

## 5. 缺失值规则

- `None`、`NaN`、空字符串、空列表必须区分；
- `cwes=[]` 是合法业务值；
- 不得将空CWE填为`CWE-0`、`Unknown`或常见CWE；
- 不得将文本空值统一填0；
- 不得删除整行以制造“完整数据”；
- 校验失败的原始数据不得静默修复。

## 6. 语义限制

- `dateAdded`：加入KEV目录日期，不是披露、攻击或CVE分配日期；
- `dueDate`：目录指定处置截止日期，不是实际修复完成日期；
- `Unknown`：尚未确认，不等于否定证据；
- 厂商记录数和集中度：仅描述本地目录文本标签分布，不评价产品质量或真实受攻击概率。
