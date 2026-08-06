# ADR-002：题目指定查询与GUI扩展分离

状态：已接受

决定：保留题目指定`filter_kev(df,start_date,end_date,vendor,ransomware,cwe)`签名；GUI的产品关键词通过`filter_kev_extended`实现。

理由：直接给指定函数增加参数会破坏题目契约；复制查询逻辑又会产生不一致。

后果：扩展函数必须调用核心函数，再应用产品条件。
