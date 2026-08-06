# 协作、分支与变更控制

## 1. 分支

```text
main                 最终稳定版
develop              日常集成
feat/data-core       成员一
feat/stat-analysis   成员二
feat/cwe-query-gui   成员三
```

## 2. 合并顺序

1. 成员一先合并Loader、Validator、Cleaner和公共模型；
2. 成员二、三同步`develop`后开发；
3. 各模块先通过自身测试，再提PR到`develop`；
4. GUI最后集成公共服务；
5. `develop`通过全量Gate后合并`main`。

## 3. 禁止并行修改

以下文件默认由成员一维护，其他人通过PR提出变更：

- `constants.py`；
- `models.py`；
- `errors.py`；
- `contracts/output_registry.yaml`；
- `config/default.yaml`；
- `main.py`；
- 公共文档中的冻结契约。

`app.py`由成员三主责；统计模块由成员二主责。

## 4. PR检查项

- 是否修改公共契约；
- 是否补测试；
- 是否保持输入不可变；
- 是否使用注册表输出；
- 是否使用稳定排序；
- 是否错误解释`Unknown`、`dateAdded`或厂商集中度；
- 是否更新报告对应章节素材；
- 是否引入绝对路径或未冻结依赖。

## 5. 变更请求格式

使用`docs/templates/change-request.md`。破坏性变更必须说明：

- 当前问题；
- 为什么无法在现有契约内解决；
- 受影响调用者和输出；
- 迁移方案；
- 测试方案；
- 三人批准记录。

## 6. 冲突解决优先级

1. 题目原始要求；
2. 本冻结包的机器可读契约；
3. 本冻结包Markdown说明；
4. 个人实现偏好。

发现题目材料本身歧义时，不得自行猜测，应记录为问题并由三人共同确定解释，必要时询问教师。
