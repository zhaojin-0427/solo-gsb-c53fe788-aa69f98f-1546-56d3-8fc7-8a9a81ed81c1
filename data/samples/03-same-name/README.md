# 场景 03：同名主体（同名不同钥）

信任锚为真 Global Trust Root；伪造根与锚 **同名却不同公钥/指纹**，且叶证书链由伪造根签发。图上可见：Rogue ICA → 真锚 的签名失败红虚线边、伪造根的自环边；候选链分别终止于 SIGNATURE（主体名可相连但验签失败的首个节点证据）、UNTRUSTED_ROOT（同名不同钥证据）与 LOOP。

建议参数：DNS=bank.example.com，用途=serverAuth。
