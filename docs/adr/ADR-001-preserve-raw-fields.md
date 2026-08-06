# ADR-001：保留原始字段并新增clean字段

状态：已接受

决定：`vendorProject`和`product`永不覆盖；仅新增`vendor_clean`和`product_clean`，且只执行`str.strip()`。

理由：题目明确要求保留原字段，并禁止模糊匹配、拼写纠正和主观合并。

后果：所有分组、排序、查询使用clean字段；详情展示可同时显示原字段。
