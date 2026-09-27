# 场景 09：主机名不匹配

叶证书 SAN 为 correct.example.com 与 *.other.example.org；以 DNS=wrong.example.com 校验时 HOSTNAME 失败，证据列出全部已呈现标识符。通配匹配遵循 RFC 6125（不跨标签）。

建议参数：DNS=wrong.example.com，用途=serverAuth。
