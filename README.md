# CISA KEV 第3题开发冻结包

- 冻结版本：`1.0.0`
- 冻结日期：`2026-08-06`
- 适用数据：`CISA_KEV_2026-07-29.json`
- 目标：在三人并行开发前冻结字段、函数接口、输出文件、排序规则、错误语义、测试门槛和协作流程。

本包只冻结契约和工程骨架，不包含统计模块的最终业务实现。各成员必须在冻结契约内开发，不得自行修改公共字段名、函数签名、输出列、排序规则或比例口径。

## 快速检查

```bash
python scripts/verify_freeze.py
python -m pytest tests -q
python main.py --check-contracts
```

Windows PowerShell：

```powershell
.\scripts\bootstrap.ps1
.\scripts\check.ps1
```

## 成员一数据底座

将课程JSON放入`data/CISA_KEV_2026-07-29.json`后运行：

```powershell
python main.py --data-core
```

该命令读取原始JSON、执行完整校验、生成公共prepared DataFrame，并写入：

- `outputs/validation/metadata.json`
- `outputs/validation/validation_summary.csv`
- `outputs/validation/validation_details.csv`
- `outputs/validation/field_profile.csv`
- `outputs/prepared/kev_prepared.csv`

若存在`ERROR`或`FATAL`校验项，命令返回非零状态且不会导出prepared数据。后续成员在内存中应复用`load_kev_json`、`validate_raw_kev`和`prepare_kev_dataframe`，不要从CSV反推`cwes`列表。

## 文档阅读顺序

1. `FREEZE_MANIFEST.md`
2. `docs/requirements-traceability.md`
3. `docs/data-contract.md`
4. `docs/interface-contract.md`
5. `docs/output-contract.md`
6. `docs/error-contract.md`
7. `docs/testing-and-quality-gates.md`
8. `docs/collaboration-and-change-control.md`

## 核心原则

- 原始11个字段永不覆盖、永不重命名。
- `cwes` 在内存中始终为 `list[str]`；导出CSV时序列化为JSON数组字符串。
- `dateAdded` 是加入KEV目录的日期，不是漏洞披露或攻击发生日期。
- `Unknown` 表示“未确认”，不得解释为“未被勒索软件利用”。
- 比例字段在CSV中保存为 `[0,1]` 小数；报告和图表显示时再格式化为百分数。
- 所有公开分析函数不得原地修改输入DataFrame。
- 所有Top-N输出必须先执行冻结的稳定排序，再截取。
- GUI必须读取原始JSON，并复用公共业务函数，不得复制一套独立分析逻辑。
