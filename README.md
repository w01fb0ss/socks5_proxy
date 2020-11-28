## 简单socks5代理实现（Go）
参考[SOCKS5协议「RFC1928翻译」](https://www.singchia.com/2018/03/21/RFC1928-Socks-Protocol-Version-5/)
1. 服务端返回客户端5 0，未认证
2. cmd只允许connect连接, BIND 和 UDP ASSOCIATE 这两个 cmd 暂不支持。
