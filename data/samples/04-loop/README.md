# 场景 04：签发环路

Loop CA 1 与 Loop CA 2 互相签发，叶证书由 CA1 签发。DFS 枚举时出现 CA1→CA2→CA1 闭合环；本场景没有任何信任锚，候选路径以 LOOP / UNTRUSTED_ROOT 逐条淘汰。

建议参数：DNS=loop.example.com，用途=serverAuth。
