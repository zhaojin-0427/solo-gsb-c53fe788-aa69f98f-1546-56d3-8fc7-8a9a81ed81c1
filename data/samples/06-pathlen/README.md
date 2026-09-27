# 场景 06：pathLenConstraint 超限

Root(pathLen=1) → ICA1(pathLen=0) → ICA2(pathLen=0) → Leaf。ICA2 位于 ICA1 之下已使 ICA1 的 pathLen=0 被突破；根的 pathLen=1 同样被两层中间 CA 突破，首个失败按叶→根顺序报告。

建议参数：DNS=deep.example.com，用途=serverAuth。
