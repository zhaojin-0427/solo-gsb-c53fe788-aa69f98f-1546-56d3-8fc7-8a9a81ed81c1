# 场景 07：Name Constraints

ICA 允许子树 .example.com，但显式禁止 evil.example.com（及其子域）。叶证书 SAN 为 www.evil.example.com，在 ICA 节点触发 NAME_CONSTRAINTS（excluded 优先于 permitted）。

建议参数：DNS=www.evil.example.com，用途=serverAuth。
