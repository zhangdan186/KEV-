# 错误与告警契约

## 1. 严重级别

| 级别 | 含义 | 流水线行为 |
|---|---|---|
| `INFO` | 正常信息 | 继续 |
| `WARNING` | 可解释偏差，不破坏核心分析 | 继续并记录 |
| `ERROR` | 单项数据或调用不符合契约 | 该模块失败；整体按配置处理 |
| `FATAL` | 输入结构或快照不可信 | 立即终止正式分析 |

## 2. 错误码

| 错误码 | 异常/问题 | 级别 | 说明 |
|---|---|---|---|
| `KEV-IO-001` | `KevFileNotFoundError` | FATAL | 输入文件不存在 |
| `KEV-IO-002` | `KevJsonDecodeError` | FATAL | JSON无法解析 |
| `KEV-IO-003` | `KevEncodingError` | FATAL | 非UTF-8或解码失败 |
| `KEV-SCHEMA-001` | `KevTopLevelSchemaError` | FATAL | 缺少顶层字段或类型错误 |
| `KEV-SCHEMA-002` | `KevRecordSchemaError` | FATAL | 缺少原始11字段 |
| `KEV-VAL-001` | count不一致 | FATAL | 顶层count、数组长度、DataFrame行数不一致 |
| `KEV-VAL-002` | 快照数量不为1656 | FATAL | 评分版输入不是冻结快照 |
| `KEV-VAL-003` | CVE为空或重复 | ERROR | 唯一键失效 |
| `KEV-VAL-004` | CVE格式非法 | ERROR | 不满足冻结正则 |
| `KEV-VAL-005` | 日期解析失败 | ERROR | dateAdded或dueDate非法 |
| `KEV-VAL-006` | dueDate早于dateAdded | ERROR | 逻辑不成立 |
| `KEV-VAL-007` | 勒索状态非法 | ERROR | 非Known/Unknown |
| `KEV-VAL-008` | cwes不是列表 | ERROR | 类型错误 |
| `KEV-VAL-009` | CWE成员格式非法 | ERROR | 不满足冻结正则 |
| `KEV-VAL-010` | 关键文本为空 | ERROR | 厂商、产品、名称、描述、行动缺失 |
| `KEV-VAL-011` | 快照核对数不一致 | FATAL | 171/1485/294/1191/6/10不匹配 |
| `KEV-QRY-001` | `InvalidDateRangeError` | ERROR | 起始日期晚于结束日期 |
| `KEV-QRY-002` | `InvalidRansomwareStatusError` | ERROR | 查询状态非法 |
| `KEV-QRY-003` | `InvalidCweError` | ERROR | 查询CWE格式非法 |
| `KEV-QRY-004` | `MissingPreparedColumnError` | ERROR | 查询依赖列缺失 |
| `KEV-OUT-001` | `OutputContractError` | ERROR | 输出列、路径或格式不符合注册表 |
| `KEV-OUT-002` | `ArtifactWriteError` | ERROR | 文件写入失败 |
| `KEV-ML-001` | `MlConfigurationError` | ERROR | K、特征等参数非法 |
| `KEV-ML-002` | `MlInsufficientDataError` | WARNING/ERROR | 筛选后样本不足 |

## 3. 错误消息结构

日志和GUI统一展示：

```text
[KEV-QRY-003] CWE格式错误：期望CWE-数字，例如CWE-79；收到“79”。
```

异常对象必须包含：

- `code`；
- `message`；
- `context`（不得包含敏感路径以外的不必要信息）；
- 原始异常链`raise ... from exc`。

## 4. 空结果不是异常

合法条件组合返回0行时：

- 不抛异常；
- 结果保留完整列；
- 摘要计数为0；
- `max_date=None`；
- GUI显示“未找到符合条件的记录”。
