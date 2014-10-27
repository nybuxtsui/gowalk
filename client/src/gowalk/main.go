package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/nybuxtsui/ca/depot"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	rangeSize = 1572864
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
}

type Config struct {
	GoWalk gowalkConfig `toml:"gowalk"`
}

type IpReq struct {
	ch chan string
}

var (
	client = &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost:   20,
			ResponseHeaderTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			Dial: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
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
)

func (h *handler) Accept() (net.Conn, error) {
	for {
		req := <-h.ch
		config := tls.Config{
			ClientAuth:         tls.VerifyClientCertIfGiven,
			ClientCAs:          certPool,
			InsecureSkipVerify: true,
			Certificates:       make([]tls.Certificate, 1),
		}
		cert, err := getCert(req.host)
		if err != nil {
			log.Println("Get cert failed:", err)
			req.conn.Close()
			continue
		}
		config.Certificates[0] = cert.toX509Pair()
		conn := tls.Server(req.conn, &config)
		return conn, nil
	}
}

func (h *handler) Close() error {
	return nil
}

func (h *handler) Addr() net.Addr {
	return nil
}

func (h *handler) onConnect(w http.ResponseWriter, r *http.Request) {
	addr := strings.Split(r.URL.String(), ":")
	if len(addr) != 2 || len(addr[0]) <= 2 {
		log.Println("URL too short")
		http.Error(w, "BadRequest", http.StatusBadRequest)
		return
	}

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
	bufrw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
	bufrw.Flush()
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

	data.Body, _ = ioutil.ReadAll(r.Body)
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
	goodIp = strings.Split(config.GoWalk.Ip, "|")
	log.Println("Use IP:", goodIp)
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

func badIpWorker() {
	var badIp = make(map[string]bool)
	for {
		t := time.NewTimer(10 * time.Second)
		select {
		case ip := <-badCh:
			t.Stop()
			badIp[ip] = false
		case <-t.C:
			for k, _ := range badIp {
				resp, err := client.Get(k)
				if err == nil && resp.StatusCode == 200 {
					goodCh <- k
					delete(badIp, k)
				} else {
					log.Println("IP Bad:", k)
				}
			}
		}
	}
}

func (h *handler) forward(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Method == "POST" {
		var err error
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println("Read content failed:", err)
			http.Error(w, "InternalServerError", http.StatusInternalServerError)
			return
		}
	}
retry:
	var ip = getGoodIp()
	if ip == "" {
		log.Println("All IP bad")
		http.Error(w, "All IP bad", http.StatusBadGateway)
		return
	}
	r.URL.Scheme = "https"
	r.URL.Host = ip
	req, err := http.NewRequest(r.Method, r.URL.String(), bytes.NewReader(body))
	if err != nil {
		log.Println("Create request failed:", err)
		http.Error(w, "InternalServerError", http.StatusInternalServerError)
		return
	}
	req.Host = r.Host
	req.Header = r.Header
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		suspCh <- ip
		goto retry
	}
	defer resp.Body.Close()
	for k, i := range resp.Header {
		for _, v := range i {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	buff := make([]byte, 4*1024)
	for {
		n, err := resp.Body.Read(buff)
		if n != 0 {
			w.Write(buff[:n])
		}
		if err != nil {
			break
		}
	}
	return
}
func (h *handler) onProxy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme == "" && (strings.HasSuffix(r.Host, ".google.com") || strings.HasPrefix(r.Host, ".googleusercontent.com") || strings.HasSuffix(r.Host, ".gstatic.com")) {
		h.forward(w, r)
		return
	}

	var pos = 0
	var data = requestToHttpData(r)
	data.Password = config.GoWalk.Password
	var autoRange = false
	var curr int
	var total int

	for {
		if autoRange {
			data.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", pos, pos+rangeSize-1))
		} else {
			if data.Header.Get("Range") == "" {
				autoRange = true
				data.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", pos, pos+rangeSize-1))
			}
		}

		var buff, err = encode(data)

	retry:
		var ip = getGoodIp()
		if ip == "" {
			log.Println("All IP bad")
			http.Error(w, "All IP bad", http.StatusBadGateway)
			return
		}
		var req *http.Request
		req, err = http.NewRequest("POST", "https://"+ip, bytes.NewReader(buff))
		req.Host = config.GoWalk.AppId[rand.Intn(len(config.GoWalk.AppId))] + ".appspot.com"

		var resp *http.Response
		resp, err = client.Transport.RoundTrip(req)
		if err != nil {
			suspCh <- ip
			log.Println("Fetch failed:", err)
			goto retry
		}
		defer resp.Body.Close()
		buff, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			suspCh <- ip
			log.Println("Read content failed:", err)
			http.Error(w, "InternalServerError", http.StatusInternalServerError)
			return
		}

		if resp.StatusCode != 200 {
			http.Error(w, string(buff), resp.StatusCode)
			return
		}
		var data2 *HttpData
		data2, err = decode(buff)
		if err != nil {
			log.Println("Decode content failed:", err)
			http.Error(w, "InternalServerError", http.StatusInternalServerError)
			return
		}
		if autoRange && data2.Status == 206 {
			curr = -1
			total = -1
		} else {
			autoRange = false
		}
		for k, i := range data2.Header {
			for _, v := range i {
				if autoRange && k == "Content-Range" {
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
				w.WriteHeader(200)
			}
			pos = curr + 1
		} else {
			w.WriteHeader(data2.Status)
		}
		w.Write(data2.Body)
		if autoRange && pos < total {
			continue
		} else {
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

	_, err = toml.DecodeFile("gowalk.conf", &config)
	if err != nil {
		log.Fatalln("Read config file failed:", err)
		return
	}

	go goodIpWorker()
	go badIpWorker()

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
			TLSConfig: &tls.Config{
			//ClientAuth:         tls.VerifyClientCertIfGiven,
			//ClientCAs:          certPool,
			//InsecureSkipVerify: true,
			},
		}
		server.Serve(h)
	}()

	log.Fatalln("Listen failed:", http.ListenAndServe(config.GoWalk.Listen, h))
}
