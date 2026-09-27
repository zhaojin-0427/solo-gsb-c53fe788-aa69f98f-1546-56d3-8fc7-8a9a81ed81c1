# 场景 08：扩展密钥用途不符

叶证书 EKU 仅含 clientAuth，实验请求用途 serverAuth，叶节点 EXTENDED_KEY_USAGE 失败。

建议参数：DNS=client.example.com，用途=serverAuth。
