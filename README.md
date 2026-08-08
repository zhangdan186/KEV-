# CISA KEV 第3题开发冻结包

- 冻结版本：`1.0.0`
- 冻结日期：`2026-08-06`
- 适用数据：`CISA_KEV_2026-07-29.json`
- 目标：完成课程第3题的可复现分析流水线、组合查询、GUI和机器学习扩展。

项目已集成三名成员的业务实现。公共字段名、函数签名、输出列、排序规则和比例口径仍以冻结契约为准。

## 安装与数据

建议使用Python 3.11至3.13：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

将课程JSON放在`data/CISA_KEV_2026-07-29.json`。程序只读原文件，不会覆盖或修改它。

## 完整运行

默认执行全部必做分析、三组查询和机器学习扩展：

```powershell
python main.py
```

不运行机器学习时：

```powershell
python main.py --skip-ml
```

自定义输入和输出目录：

```powershell
python main.py --input data/CISA_KEV_2026-07-29.json --output outputs
```

成功运行后，正式产物写入`outputs/validation`、`prepared`、`tables`、`queries`、`figures`、`html`、`ml`和`manifests`。`run_manifest.json`记录输入SHA-256、运行状态、环境版本和每个产物的哈希、行数与列名。

## GUI

先运行`python main.py`生成机器学习产物，再启动：

```powershell
streamlit run app.py
```

GUI直接读取上传的原始JSON，支持日期、厂商、产品、Known/Unknown和CWE组合筛选，以及动态图表、详情、CSV/PNG导出和机器学习结果查看。

## 快速检查

```bash
python scripts/verify_freeze.py
python -m pytest tests -q
python -m ruff check src tests main.py app.py scripts
python -m mypy src
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
