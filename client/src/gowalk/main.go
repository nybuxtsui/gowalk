package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/nybuxtsui/ca/depot"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// RANGE获取的默认范围
	rangeSize = 24 * 1024 * 1024
	// GAE请求的并发令牌
	tokenCount = 8
)

type httpsReq struct {
	conn net.Conn
	host string
}

type handler struct {
	ch chan *httpsReq
}

type gowalkConfig struct {
	AppId    []string `toml:"appid"`
	Ip       string   `toml:"ip"`
	Password string   `toml:"password"`
	Listen   string   `toml:"listen"`
	ByPass   []string `toml:"bypass"`
	Profile  string   `toml:"profile"`
}

type Config struct {
	GoWalk gowalkConfig `toml:"gowalk"`
}

// 查询有效IP地址请求
type IpReq struct {
	ch chan string
}

var (
	// 避免尽量重连
	client = &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost:   tokenCount,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			Dial: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 10 * time.Minute,
			}).Dial,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	certPool *x509.CertPool
	config   Config
	reqCh    = make(chan IpReq, 100)
	goodCh   = make(chan string, 100)
	suspCh   = make(chan string, 100)
	badCh    = make(chan string, 100)
	tokenCh  = make(chan int, tokenCount)
	appIndex = 0
)

/*
handler模拟成Listener接口，供Server()函数使用
Accept的net.Conn来源为https的代理请求
https的代理程序流程为
client -> (CONNECT) -> server
server -> (OK) -> client
client -> (SSL握手) -> server
所以https代理先由普通的http代理模块处理
当接收到CONNECT请求的时候，应答OK，并且将该连接通过channel转发到Accept函数里面
Accept接受到channel后，完成SSL握手
握手完成后，返回出net.Conn对象，就好像接收到一个标准的连接
*/
func (h *handler) Accept() (net.Conn, error) {
	for {
		// 从channle中拿出一个连接
		req := <-h.ch
		config := tls.Config{
			ClientAuth:         tls.VerifyClientCertIfGiven,
			ClientCAs:          certPool,
			InsecureSkipVerify: true,
			Certificates:       make([]tls.Certificate, 1),
		}
		// 颁发证书
		cert, err := getCert(req.host)
		if err != nil {
			log.Println("Get cert failed:", err)
			req.conn.Close()
			continue
		}
		config.Certificates[0] = cert.toX509Pair()
		// SSL握手
		conn := tls.Server(req.conn, &config)
		// 返回连接
		return conn, nil
	}
}

// handle模拟的Listener没有Close
func (h *handler) Close() error {
	return nil
}

// handle模拟的Listener没有Addr
// 别人也不会用
func (h *handler) Addr() net.Addr {
	return nil
}

func (h *handler) onConnect(w http.ResponseWriter, r *http.Request) {
	// CONNECT是https请求，请求附带了地址和端口，用:分割
	addr := strings.Split(r.URL.String(), ":")
	if len(addr) != 2 || len(addr[0]) <= 2 {
		log.Println("URL too short")
		http.Error(w, "BadRequest", http.StatusBadRequest)
		return
	}

	// 劫持该连接
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Println("Can not hijacker")
		http.Error(w, "InternalServerError", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Println("Hijack failed:", err)
		http.Error(w, "InternalServerError", http.StatusInternalServerError)
		return
	}
	// 返回连接成功
	bufrw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
	bufrw.Flush()

	// 检查是否是bypass站点
	for _, domain := range config.GoWalk.ByPass {
		if strings.HasSuffix(addr[0], domain) {
			log.Println("BYPASS:", r.URL.String())
			// 获取IP
			var ip = getGoodIp()
			if ip == "" {
				log.Println("All IP bad")
				http.Error(w, "All IP bad", http.StatusBadGateway)
				return
			}
			// 直连
			peer, err := net.Dial("tcp", ip+":"+addr[1])
			if err != nil {
				log.Println("BYPASS dial bypass failed:", err)
				conn.Close()
			}
			proxy := func(c1, c2 net.Conn) {
				defer func() {
					c1.Close()
					c2.Close()
				}()
				buf := make([]byte, 1024*32)
				for {
					n, err := c1.Read(buf)
					if err != nil {
						if !strings.HasSuffix(err.Error(), "use of closed network connection") && err != io.EOF {
							log.Println("BYBASS read failed:", err)
						}
						return
					}
					_, err = c2.Write(buf[0:n])
					if err != nil {
						if !strings.HasSuffix(err.Error(), "use of closed network connection") && err != io.EOF {
							log.Println("BYPASS write failed:", err)
						}
						return
					}
				}
			}
			// 开正反代理
			go proxy(peer, conn)
			go proxy(conn, peer)
			return
		}
	}
	// 通过channel发送到handle.Accept()里面
	h.ch <- &httpsReq{conn, addr[0][2:]}
}

func requestToHttpData(r *http.Request) *HttpData {
	var data = &HttpData{Header: make(http.Header)}
	data.Method = r.Method
	data.Url = r.URL.String()
	if data.Url[0] == '/' {
		data.Url = "https://" + r.Host + r.URL.String()
	}
	data.Header = r.Header

	data.Body = r.Body
	return data
}

func parseRange(s string) (int, int, bool) {
	part := strings.Split(s, "/")
	if len(part) != 2 {
		return 0, 0, false
	}
	r := strings.Split(part[0], "-")
	if len(r) != 2 {
		return 0, 0, false
	}
	total, err := strconv.ParseInt(part[1], 10, 32)
	if err != nil {
		return 0, 0, false
	}
	curr, err := strconv.ParseInt(r[1], 10, 32)
	if err != nil {
		return 0, 0, false
	}
	return int(total), int(curr), true
}

func getGoodIp() string {
	var ch = make(chan string, 1)
	reqCh <- IpReq{ch}
	return <-ch
}

func goodIpWorker() {
	var goodIp []string
	if len(config.GoWalk.Ip) != 0 {
		goodIp = strings.Split(config.GoWalk.Ip, "|")
		log.Println("Use IP:", goodIp)
	} else {
		goodIp = make([]string, 0, 5)
	}
	for {
		select {
		case req := <-reqCh:
			if len(goodIp) > 0 {
				req.ch <- goodIp[0]
				//req.ch <- goodIp[rand.Intn(len(goodIp))]
			} else {
				req.ch <- ""
			}
		case ip := <-goodCh:
			goodIp = append(goodIp, ip)
		case ip := <-suspCh:
			for i, v := range goodIp {
				if v == ip {
					goodIp[i], goodIp[len(goodIp)-1] = goodIp[len(goodIp)-1], goodIp[i]
					goodIp = goodIp[:len(goodIp)-1]
					badCh <- ip
					break
				}
			}
		}
	}
}

type badIpDef struct {
	count int
	t     int64
}

func badIpWorker() {
	var badIp = make(map[string]badIpDef)
	for {
		t := time.NewTimer(10 * time.Second)
		select {
		case ip := <-badCh:
			t.Stop()
			badIp[ip] = badIpDef{1, time.Now().Add(30 * time.Second).Unix()}
		case <-t.C:
			var now = time.Now().Unix()
			for k, v := range badIp {
				if now <= v.t {
					continue
				}
				resp, err := client.Get("https://" + k)
				if err == nil {
					defer resp.Body.Close()
				}
				if err == nil && resp.StatusCode == 200 {
					goodCh <- k
					delete(badIp, k)
				} else {
					log.Println("IP Bad:", k, err)
					// 最大2分钟
					v.count = (v.count + 1) % 12
					v.t = now + int64(v.count*10)
					badIp[k] = v
				}
			}
		}
	}
}

// 对于google自己的地址，我们直接将请求发送过去，而不通过GAE代理
func (h *handler) bypass(w http.ResponseWriter, r *http.Request) {
	closeNotify := w.(http.CloseNotifier).CloseNotify()
	var body io.Reader
	if r.Method == "POST" || r.Method == "PUT" {
		body = r.Body
	}
	// 获取令牌
	<-tokenCh
	defer func() {
		tokenCh <- 1
	}()
retry:
	// 获取IP
	var ip = getGoodIp()
	if ip == "" {
		log.Println("All IP bad")
		http.Error(w, "All IP bad", http.StatusBadGateway)
		return
	}
	// 构建Request对象
	r.URL.Scheme = "https"
	r.URL.Host = ip
	log.Println("Forward:", r.Method, r.URL.String())
	req, err := http.NewRequest(r.Method, r.URL.String(), body)
	if err != nil {
		log.Println("Create request failed:", err)
		http.Error(w, "InternalServerError", http.StatusInternalServerError)
		return
	}
	if r.ContentLength != 0 {
		req.ContentLength = r.ContentLength
	}
	req.Header = r.Header
	req.Host = r.Host
	// 发送请求
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		suspCh <- ip
		goto retry
	}
	defer resp.Body.Close()
	// 应答给客户端
	for k, i := range resp.Header {
		for _, v := range i {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.StatusCode >= 400 {
		log.Println("################ Bypass failed:", r.Host, r.URL.String(), resp.StatusCode)
	}
	buff := make([]byte, 8*1024)
	for {
		select {
		case <-closeNotify:
			return
		default:
		}
		n, err := resp.Body.Read(buff)
		if n != 0 {
			if resp.StatusCode >= 400 {
				log.Printf("    :%s\n", buff[:n])
			}
			w.Write(buff[:n])
		}
		if err != nil {
			if err != io.EOF {
				log.Println("Bypass failed:", err)
			}
			break
		}
	}
	return
}

// 普通代理
func (h *handler) onProxy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme == "" {
		for _, domain := range config.GoWalk.ByPass {
			if strings.HasSuffix(r.Host, domain) {
				h.bypass(w, r)
				return
			}
		}
	}
	closeNotify := w.(http.CloseNotifier).CloseNotify()

	var pos = 0
	var data = requestToHttpData(r)
	data.Password = config.GoWalk.Password
	var autoRange = false
	var curr int
	var total int

	// 获取令牌
	<-tokenCh
	defer func() {
		tokenCh <- 1
	}()

	for {
		if autoRange {
			// 已经处于自动分块模式
			data.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", pos, pos+rangeSize-1))
		} else {
			// 没处于自动分块模式
			if data.Header.Get("Range") == "" {
				// 客户端没有请求分块，则进入自动分块模式
				autoRange = true
				data.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", pos, pos+rangeSize-1))
			}
		}

		var buff = new(bytes.Buffer)
		var err = encode(data, buff, closeNotify)
		if err != nil {
			log.Println("Encode content failed:", err)
			http.Error(w, "InternalServerError", http.StatusInternalServerError)
			return
		}

	retry:
		select {
		case <-closeNotify:
			// 如果客户端已经关闭连接，那我们也不做了，节省点资源
			return
		default:
		}
		var ip = getGoodIp()
		if ip == "" {
			log.Println("All IP bad")
			http.Error(w, "All IP bad", http.StatusBadGateway)
			return
		}

		var req *http.Request
		req, err = http.NewRequest("POST", "https://"+ip, buff)
		req.Host = config.GoWalk.AppId[appIndex] + ".appspot.com"
		appIndex = (appIndex + 1) % len(config.GoWalk.AppId)
		req.Header.Set("Connection", "keep-alive")
		//req.Header.Add("User-Agent", "Mozilla/5.0")
		//req.Header.Add("Accept-Encoding", "compress, gzip")

		var resp *http.Response
		resp, err = client.Transport.RoundTrip(req)
		if err != nil {
			suspCh <- ip
			log.Println("Fetch failed:", err)
			goto retry
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			// GAE代理程序出错
			buff, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				suspCh <- ip
				log.Println("Read content failed:", err)
				http.Error(w, "InternalServerError", http.StatusInternalServerError)
				return
			}
			http.Error(w, string(buff), resp.StatusCode)
			return
		}

		var data2 *HttpData
		data2, err = decode(resp.Body)
		if err != nil {
			log.Println("Decode content failed:", err)
			http.Error(w, "InternalServerError", http.StatusInternalServerError)
			return
		}
		defer data2.Body.Close()
		if autoRange && data2.Status == 206 {
			// 服务器端分段返回，则通过Content-Range计算curr和total
			curr = -1
			total = -1
		} else {
			// 不是返回206则表示服务器端没有分段返回
			autoRange = false
		}
		for k, i := range data2.Header {
			for _, v := range i {
				if autoRange && k == "Content-Range" {
					// 如果是autoRange并且看到Content-Range的头
					// 那这个头不能返回给客户端，需要内部消化掉
					// 在此处重新计算curr和total
					// autoRange的第二个包，修改的header其实不会再返回给客户端
					var ok bool
					total, curr, ok = parseRange(v)
					if !ok || curr == -1 || total == -1 {
						log.Println("Unknown range mode:", v)
						http.Error(w, "InternalServerError", http.StatusInternalServerError)
						return
					}
					continue
				}
				w.Header().Add(k, v)
			}
		}
		if autoRange {
			if curr == -1 || total == -1 {
				log.Println("Range header not found")
				http.Error(w, "InternalServerError", http.StatusInternalServerError)
				return
			}
			if pos == 0 {
				// autorange，第一个包，返回200，返回header
				w.WriteHeader(200)
			}
			pos = curr + 1
		} else {
			w.WriteHeader(data2.Status)
		}
		temp := make([]byte, 8*1024)
		for {
			n, err := data2.Body.Read(temp)
			if n != 0 {
				w.Write(temp[0:n])
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Println("Write data failed:", err)
				return
			}
		}
		if autoRange && pos < total {
			// autoRange模式，数据取完，继续循环
			continue
		} else {
			// 只要有一个没满足，则这次请求结束
			break
		}
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("Process:", r.Method, r.URL)
	if r.Method == "CONNECT" {
		h.onConnect(w, r)
	} else {
		h.onProxy(w, r)
	}
}

func main() {
	var err error

	runtime.GOMAXPROCS(runtime.NumCPU())
	log.Println("Start...")

	for i := 0; i < tokenCount; i++ {
		tokenCh <- 1
	}

	_, err = toml.DecodeFile("gowalk.conf", &config)
	if err != nil {
		log.Fatalln("Read config file failed:", err)
		return
	}

	go goodIpWorker()
	go badIpWorker()

	if config.GoWalk.Ip == "" {
		IpInit()
	}

	certPool = x509.NewCertPool()
	certLib, err = depot.NewFileDepot("certs")
	if err != nil {
		log.Fatalln("NewFileDepot failed:", err)
	}
	capem, err := loadCA().cert.Export()
	if err != nil {
		log.Fatalln("Export CA Pem failed:", err)
	}
	if ok := certPool.AppendCertsFromPEM(capem); !ok {
		log.Fatalln("AppendCertsFromPEM failed")
	}

	h := &handler{
		ch: make(chan *httpsReq, 10),
	}
	go func() {
		server := &http.Server{
			Handler:   h,
			TLSConfig: &tls.Config{},
		}
		// 用户https的，第二http服务器
		server.Serve(h)
	}()

	if config.GoWalk.Profile != "" {
		go func() {
			log.Println(http.ListenAndServe(config.GoWalk.Profile, nil))
		}()
	}

	// 对外服务的第一http服务器
	log.Fatalln("Listen failed:", http.ListenAndServe(config.GoWalk.Listen, h))
}
