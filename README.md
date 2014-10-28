#简介
gowalk是借鉴goagent，使用go开发的高性能稳定的代理服务器。

#服务器端安装
1. 下载  appe ngine SDK for go
2. 修改server/app.yaml，application:设置成你申请的appid
3. 修改server/config.go，const password = ""，在引号内填写需要的访问密码
4. 进入到server目录中，运行sdk中的`goapp deploy .`，部署服务器端。

#客户端安装
1. 将client目录中的`gowalk.conf.default`重命名为`gowalk.conf`。
2. 配置`gowalk.conf`
3. 进入client目录
4. export GOPATH=$PWD
5. go build gowalk
6. ./gowalk

#关于部署证书问题
当采用gowalk作为代理部署gowalk时，需要将gowalk的ca.crt证书复制到go_appengine的lib/cacerts/cacerts.txt文件的末尾

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
