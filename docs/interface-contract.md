# 接口契约

## 1. 通用约束

- Python版本：3.11；
- 路径参数使用`str | pathlib.Path`；
- 公开分析函数不得原地修改输入DataFrame；
- 公开函数返回列顺序、排序规则和数据类型必须稳定；
- 业务校验问题尽量汇总到`ValidationReport`，不可读文件或非法调用参数使用异常；
- 不允许模块自行创建名称不同但含义相同的公共字段。

## 2. 加载接口

```python
load_kev_json(file_path: PathLike) -> tuple[KevMetadata, pd.DataFrame]
```

行为：

- 使用UTF-8读取；
- 只完成结构读取，不清洗业务字段；
- 返回顶层元数据和含11个原始字段的DataFrame；
- `cwes`必须保持list；
- 文件不存在抛`KevFileNotFoundError`；
- JSON无法解析抛`KevJsonDecodeError`；
- 缺少顶层字段抛`KevTopLevelSchemaError`。

## 3. 校验接口

```python
validate_raw_kev(metadata: KevMetadata, df: pd.DataFrame) -> ValidationReport
```

- 尽量一次收集全部问题；
- `ValidationReport.is_valid`仅在无`ERROR/FATAL`时为True；
- `FATAL`表示后续分析不应继续；
- 不修改输入。

## 4. 清洗接口

```python
prepare_kev_dataframe(df: pd.DataFrame) -> pd.DataFrame
```

- 输入必须通过关键结构校验；
- 返回新DataFrame；
- 原始11字段位于前部并保留；
- 追加7个冻结衍生字段；
- 日期列在内存中为`datetime64[ns]`、无时区、日期归一化；
- 不排序；保留输入行顺序，排序由各分析模块负责。

## 5. 时间分析接口

```python
analyze_added_time(df: pd.DataFrame) -> TimeAnalysisResult
```

返回：

- `monthly_counts`：2021-11至2026-07完整月序列；
- `annual_summary`：年度计数、首月、末月、覆盖月数、完整性；
- `same_period_comparison`：至少实现1月至7月同期比较；
- `figures`：以逻辑名称映射到Figure对象。

## 6. 期限分析接口

```python
analyze_deadlines(df: pd.DataFrame) -> DeadlineAnalysisResult
```

返回描述统计、精确天数频数、按年统计、分组统计及Figure对象。

## 7. 勒索状态分析接口

```python
analyze_ransomware_status(df: pd.DataFrame) -> RansomwareAnalysisResult
```

比例字段保存小数；年度交叉表须包含`Known`、`Unknown`、`total`、`known_share`、`unknown_share`。

## 8. 厂商分析接口

```python
analyze_vendors(df: pd.DataFrame) -> VendorAnalysisResult
```

- 厂商排序：`record_count DESC, vendor_clean ASC`；
- 厂商产品排序：`record_count DESC, vendor_clean ASC, product_clean ASC`；
- Top30必须排序后截取；
- `share`与`cumulative_share`为小数；
- `HHI=sum(share**2)`，不乘10000。

## 9. CWE接口

```python
build_cwe_long_table(df: pd.DataFrame) -> pd.DataFrame
analyze_cwe(df: pd.DataFrame) -> CweAnalysisResult
```

长表一行对应一个唯一的`CVE-CWE`关系；计数使用`nunique(cveID)`。如原始数据意外存在重复关系，长表必须先按`cveID,cwe`去重。

## 10. 题目指定查询接口

签名禁止修改：

```python
filter_kev(
    df: pd.DataFrame,
    start_date: DateLike | None = None,
    end_date: DateLike | None = None,
    vendor: str | None = None,
    ransomware: str | None = None,
    cwe: str | None = None,
) -> tuple[pd.DataFrame, QuerySummary]
```

规则：

- 日期使用`dateAdded`闭区间；
- 仅给开始日期时筛选`>=start_date`；仅给结束日期时筛选`<=end_date`；
- `start_date>end_date`抛`InvalidDateRangeError`；
- 厂商在`vendor_clean`上执行不区分大小写、非正则、字面子串匹配；空白字符串视为未提供；
- `ransomware`仅接受`Known`、`Unknown`、`None`；
- CWE先去首尾空白并转大写，再校验正则，最后对列表成员精确匹配；
- 多条件使用AND；
- 结果排序：`dateAdded DESC, cveID ASC`，稳定排序`kind="mergesort"`；
- 不修改原DataFrame；
- 空结果保留完整列结构；
- `QuerySummary.max_date`为空时为`None`，不得写字符串`"NaT"`。

## 11. GUI扩展查询接口

题目指定函数不增加`product`参数。GUI额外需求使用独立包装器：

```python
filter_kev_extended(
    df: pd.DataFrame,
    filters: ExtendedKevFilter,
) -> tuple[pd.DataFrame, QuerySummary]
```

`ExtendedKevFilter`在核心条件基础上增加`product`字面子串条件。该函数内部必须复用`filter_kev`，不得复制并分叉核心查询逻辑。

## 12. 导出接口

```python
export_dataframe(df: pd.DataFrame, spec: OutputSpec, root: PathLike) -> Path
export_json(data: Mapping[str, Any], spec: OutputSpec, root: PathLike) -> Path
export_figure(fig: Figure, spec: OutputSpec, root: PathLike) -> Path
write_run_manifest(records: Sequence[ArtifactRecord], root: PathLike) -> Path
```

所有导出必须查阅`contracts/output_registry.yaml`，禁止模块硬编码另一套列名或路径。

## 13. 流水线接口

```python
run_pipeline(config: PipelineConfig) -> RunManifest
```

固定阶段：

1. load；
2. validate；
3. prepare；
4. mandatory analyses；
5. query cases；
6. optional ML；
7. exports；
8. manifest与质量摘要。

任一`FATAL`验证问题必须在第2阶段终止，且不得生成误导性的正式分析表。
