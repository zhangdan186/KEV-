# 成员三PPT页面文稿

## 第9页：CWE多标签结构

- 1,485条记录含CWE，171条为空列表；
- 使用 `explode()` 建立CVE-CWE长表，同一关系去重；
- 总体分母1,485，Known分母294，Unknown分母1,191；
- Top 3：CWE-20为118条、CWE-78为107条、CWE-787为100条；
- 多标签占比之和允许超过100%。

建议图：`outputs/figures/cwe_top20.png` 与 `cwe_known_unknown.png`。

## 第10页：组合查询函数

- 日期按 `dateAdded` 闭区间；
- 厂商不区分大小写的字面子串匹配；
- Known/Unknown严格枚举；
- CWE规范化后在列表成员中精确匹配；
- 多条件按AND组合，结果稳定排序，不修改输入表。

三组案例返回51、34和60条实际记录，均已导出CSV。

## 第11页：GUI功能与界面

- 上传课程原始JSON并复用公共读取、校验、清洗；
- 日期、厂商、产品、状态、CWE组合筛选；
- 月度、厂商和CWE动态图；
- 结果表、CVE详情、数据校验；
- CSV与PNG导出。

建议截图：`screenshots/01-data-overview.png`、`02-combined-query-cwe.png`。

## 第12页配合：机器学习界面

成员二讲解TF-IDF、KMeans和轮廓系数；成员三演示聚类摘要、关键词、代表CVE、二维图和按聚类查看记录。

## 第13页：现场演示

```text
上传JSON -> 查看元数据 -> 输入Microsoft + Known + CWE-119
-> 确认4条结果 -> 切换动态图 -> 查看CVE详情
-> 导出CSV/PNG -> 打开机器学习页
```

现场操作控制在2分钟内，并准备两张GUI截图作为离线备用。
