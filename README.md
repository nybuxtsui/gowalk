#简介
gowalk是借鉴goagent，使用go开发的高性能稳定的代理服务器。

#快速体验
```
git clone https://github.com/nybuxtsui/gowalk.git
cd gowalk
./build.sh
./gowalk
```
默认配置文件已经配置了一个测试服务器
默认配置采用自动搜索ip模式，启动时间可能较长，如果自己有ip可以配置在gowalk.conf中，ip格式和goagent相同，`ip="ip1|ip2|ip3"`
第一次运行后，将自动生成的certs目录下的ca.crt添加到浏览器信任CA(授权中心)中

[二进制包下载](http://pan.baidu.com/s/1hq69vAO)

#服务器端部署
1. 运行upload.py直接部署，具体参考goagent的部署方式(感谢goagent提供的部署代码)

#客户端安装
1. 将client目录中的`gowalk.conf.default`重命名为`gowalk.conf`。
2. 配置`gowalk.conf`
3. 进入client目录
4. export GOPATH=$PWD
5. go build gowalk
6. ./gowalk

