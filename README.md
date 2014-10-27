#简介
gowalk是借鉴goagent，使用go开发的高性能稳定的代理服务器。

#服务器端安装
1. 下载  [appengine SDK for go](https://cloud.google.com/appengine/downloads)
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
