# 需求追踪矩阵

| 编号 | 题目要求 | 代码模块 | 主要输出 | 测试 | 报告章节 | PPT |
|---|---|---|---|---|---|---|
| R1.1 | 读取顶层元数据与漏洞数组 | `loader.py` | `metadata.json` | T-LOAD-* | 数据读取 | 数据集与架构 |
| R1.2 | 1656条、11字段、count一致 | `validator.py` | `validation_summary.csv` | T-VAL-001~003 | 数据验证 | 数据质量 |
| R1.3 | CVE唯一、格式合法 | `validator.py` | `validation_details.csv` | T-VAL-004~006 | 数据验证 | 数据质量 |
| R1.4 | 日期与dueDate顺序校验 | `validator.py` | `validation_details.csv` | T-VAL-007~009 | 数据验证 | 数据质量 |
| R1.5 | 状态枚举与CWE列表校验 | `validator.py` | `validation_details.csv` | T-VAL-010~013 | 数据验证 | 数据质量 |
| R1.6 | 保留原字段并创建clean字段 | `cleaner.py` | `kev_prepared.csv` | T-CLEAN-* | 数据清洗 | 数据质量 |
| R2.1 | 2021-11至2026-07连续月序列 | `time_analysis.py` | `monthly_added_counts.csv` | T-TIME-001 | 时间分析 | 时间趋势 |
| R2.2 | 年度覆盖范围与不完整年份 | `time_analysis.py` | `annual_added_summary.csv` | T-TIME-002~004 | 时间分析 | 时间趋势 |
| R2.3 | deadline_days及描述统计 | `deadline_analysis.py` | `deadline_*.csv` | T-DEAD-* | 期限分析 | 期限分布 |
| R2.4 | Known/Unknown总体与年度统计 | `ransomware_analysis.py` | `ransomware_*.csv` | T-RAN-* | 状态分析 | 勒索状态 |
| R3.1 | 厂商记录数、占比、累计占比、产品数 | `vendor_analysis.py` | `vendor_summary.csv` | T-VEN-001~004 | 厂商分析 | 厂商分布 |
| R3.2 | 厂商产品组合与稳定Top30 | `vendor_analysis.py` | `vendor_product_top30.csv` | T-VEN-005~007 | 产品分析 | 产品组合 |
| R3.3 | CR5、CR10、HHI | `vendor_analysis.py` | `concentration_metrics.csv` | T-VEN-008~010 | 集中度 | 集中度指标 |
| R4.1 | CWE正确展开及不同CVE计数 | `cwe_analysis.py` | `cve_cwe_long.csv` | T-CWE-001~004 | CWE分析 | CWE结构 |
| R4.2 | 三种正确分母 | `cwe_analysis.py` | `cwe_*_summary.csv` | T-CWE-005~008 | CWE分析 | CWE对比 |
| R4.3 | 指定组合查询函数 | `query.py` | `query_case_*.csv` | T-QRY-* | 查询设计 | 组合查询 |
| R4.4 | 至少三组查询并导出实际记录 | `query.py` | `query_cases_summary.csv` | T-QRY-010 | 查询案例 | 查询演示 |
| O1 | GUI读取原始JSON并筛选 | `app.py` | GUI截图 | T-GUI-* | GUI | 系统演示 |
| O2 | 至少两张动态图、详情与导出 | `app.py` | PNG/CSV | T-GUI-* | GUI | 系统演示 |
| O3 | 其他机器学习分析 | `ml_analysis.py` | `ml_*` | T-ML-* | 机器学习 | 扩展分析 |
