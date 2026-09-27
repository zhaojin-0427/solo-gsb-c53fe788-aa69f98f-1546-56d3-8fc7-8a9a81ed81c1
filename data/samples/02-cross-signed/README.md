# 场景 02：交叉签发

Cross ICA 的同一主体/公钥分别被 Root A、Root B 签发；两个根均为信任锚。叶证书可走出两条不同候选链（长度相同），系统按指纹字典序稳定选出一条，另一条同样有效。

建议参数：DNS=app.example.com，用途=serverAuth。
