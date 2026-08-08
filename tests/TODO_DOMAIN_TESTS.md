# 业务测试覆盖状态

冻结清单中的业务测试均已实现：

- 数据底座：`test_loader.py`、`test_validator.py`、`test_cleaner.py`、`test_exporters.py`；
- 统计分析：`test_time_analysis.py`、`test_deadline_analysis.py`、`test_ransomware_analysis.py`、`test_vendor_analysis.py`；
- CWE与查询：`test_cwe_analysis.py`、`test_query.py`、`test_query_cases.py`；
- GUI与图表：`test_gui_service.py`、`test_gui_smoke.py`、`test_visualization.py`；
- 机器学习：`test_ml_analysis.py`；
- 集成与契约：`test_pipeline.py`、`test_data_core_pipeline.py`及其他契约测试。

最终交付前仍需在干净环境执行`python -m pytest tests -q`，并完成GUI人工演示检查。
