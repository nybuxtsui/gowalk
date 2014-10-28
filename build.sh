export GOPATH=$PWD/client
$GOROOT/bin/go build gowalk
cp ./client/gowalk.conf.default gowalk.conf
