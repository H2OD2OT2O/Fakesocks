# Fakesocks
一款用于突破GFW封锁的工具，将流量伪装成合法的socks5代理流量，并具备防重放攻击的功能
# 编译
拉取仓库后直接make client make server即可，需要提前安装mbedtls库。
# 使用
server跑在你的vps上，语法是./server 0.0.0.0 1080 password，第一个参数是监听地址，一般不需要改，第二个参数是监听端口，可以随意设置，第三个参数是密码，不要太简单，但也不要超过32字节。
client跑在本地，它会和server连接，并在本地开放一个正常的socks5代理，连接这个代理即可上网，语法为./client 0.0.0.0 1080 server_addr 1080 www.bing.com password
第一个参数是监听地址，一般不需要修改，第二个参数是监听端口，程序会在这个端口上接受socks5请求，第三个参数是你的vps地址，域名ip都可以，第四个参数是服务器端口，改成和server一样的，接下来是伪装域名，建议用一些没被gfw屏蔽的视频网站域名，最后是密码，同server设置一样。
# 基本原理
不想了解可以不看。
GFW并不会直接封锁socks5，因为socks5是明文协议，通过socks5代理和直接访问对GFW没什么区别，因此我们可以假装在访问一个合法网站，且因为socks5协议只会在握手阶段包含域名信息，我们可以
在socks5握手结束后通过约定好的方式发送真正的地址信息，并用同一个连接进行数据传输，因为握手阶段GFW已经审查过了，所以接下来的流量会全部放行。为了让流量更加合理，我们采取了最常见的
tls协议进行伪装：开始阶段我们的代理会向伪装域名进行正常的tls握手，而当握手结束，我们发送的第一个Application data实际就是我们加密后的Fakesocks协议头，server收到后会尝试进行解密
，如果发现是Fakesocks，则会进行转发处理，否则继续转发给伪装域名的服务器，也就是说我们的server对于非Fakesocks客户端来说，就是一个正常的socks5服务器。
# 存在的问题
由于本人能力有限，程序目前还存在一些问题，主要是速度问题，为了最大程度的伪装，每次连接我们都会和伪装网站进行一次真的tls握手，但在握手完成后马上断开连接，这首先会造成延迟上速度下降，
且频繁的无效tls连接可能引起伪装网站的保护，从而造成我们的代理无法使用，目前油管能自动720p，也能手动调到1080p流畅播放。
