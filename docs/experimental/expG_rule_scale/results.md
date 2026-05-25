# Exp-G 规则数可扩展性(单策略 / 单次运行)

引擎所有表循环(rules/sources/xforms/gates)走 bpf_loop + 非冻结 map 计数 → 回调只验证一次;
匹配器无分支 / map 回写,无符号偏移读 → **verifier 成本与规则数无关**。下表为单策略加载结果。

| 规则数(混合 exec/@arg/write) | 单策略加载 |
|---:|:---:|
| 1 | OK |
| 8 | OK |
| 32 | OK |
| 64 | OK |
| 100 | OK |
| 128 | OK |

**结论:128 条混合规则(含 12+ 条 @arg)在一个策略里加载成功**(MAX_TAINT_RULES=128;旧实现 ~1 条 @arg 即 -E2BIG)。
