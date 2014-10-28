set GOPATH=%~dp0%client
echo %GOPATH%
%GOROOT%\bin\go build gowalk
copy client\gowalk.conf.default gowalk.conf