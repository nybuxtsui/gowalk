package main

import (
	"bytes"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type IpDefine struct {
	pos   int
	ip    string
	count int
}

var (
	ips   = make([]IpDefine, 0, 250)
	total = 0

	ipdone  sync.WaitGroup
	iptotal int32
)

func calcIpCount(ip string) int {
	var count = 1
	var p = strings.Split(ip, ".")
	for i := 3; i >= 0; i-- {
		var n = strings.Split(p[i], "-")
		if len(n) == 2 {
			var s, _ = strconv.ParseInt(n[0], 10, 32)
			var e, _ = strconv.ParseInt(n[1], 10, 32)
			count = count * int(e-s)
		}
	}
	return count
}

func importIpv4Range(ip string) {
	var c = calcIpCount(ip)
	total += c
	ips = append(ips, IpDefine{total - 1, ip, c})
}

func randomIp() string {
	var r = new(bytes.Buffer)
	var p = rand.Intn(total)
	var i = sort.Search(
		len(ips),
		func(i int) bool {
			return ips[i].pos >= p
		},
	)
	var ip = ips[i]
	for _, p := range strings.Split(ip.ip, ".") {
		var n = strings.Split(p, "-")
		var node string
		if len(n) == 2 {
			var s, _ = strconv.ParseInt(n[0], 10, 32)
			var e, _ = strconv.ParseInt(n[1], 10, 32)
			node = strconv.FormatInt(int64(rand.Int31n(int32(e-s+1))+int32(s)), 10)
		} else {
			node = p
		}
		if r.Len() != 0 {
			r.WriteByte('.')
		}
		r.WriteString(node)
	}
	return r.String()
}

func IpInit() {
	rand.Seed(time.Now().UnixNano())
	importIpv4Range("1.179.248-255.0-255")
	importIpv4Range("103.246.187.0-255")
	importIpv4Range("103.25.178.4-59")
	importIpv4Range("106.162.192.148-187")
	importIpv4Range("106.162.198.84-123")
	importIpv4Range("106.162.216.20-123")
	importIpv4Range("107.167.160-191.0-255")
	importIpv4Range("107.178.192-255.0-255")
	importIpv4Range("107.188.128-255.0-255")
	importIpv4Range("108.170.192-255.0-255")
	importIpv4Range("108.177.0-127.0-255")
	importIpv4Range("108.59.80-95.0-255")
	importIpv4Range("109.232.83.64-127")
	importIpv4Range("111.168.255.20-187")
	importIpv4Range("111.92.162.4-59")
	importIpv4Range("113.197.105-106.0-255")
	importIpv4Range("118.174.24-27.0-255")
	importIpv4Range("12.216.80.0-255")
	importIpv4Range("121.78.74.68-123")
	importIpv4Range("123.205.250-251.68-190")
	importIpv4Range("142.250-251.0-255.0-255")
	importIpv4Range("146.148.0-127.0-255")
	importIpv4Range("149.126.86.1-59")
	importIpv4Range("149.3.177.0-255")
	importIpv4Range("162.216.148-151.0-255")
	importIpv4Range("162.222.176-183.0-255")
	importIpv4Range("163.28.116.1-59")
	importIpv4Range("163.28.83.143-187")
	importIpv4Range("172.217.0-255.0-255")
	importIpv4Range("172.253.0-255.0-255")
	importIpv4Range("173.194.0-255.0-255")
	importIpv4Range("173.255.112-127.0-255")
	importIpv4Range("178.45.251.4-123")
	importIpv4Range("178.60.128.1-63")
	importIpv4Range("185.25.28-29.0-255")
	importIpv4Range("192.119.16-31.0-255")
	importIpv4Range("192.158.28-31.0-255")
	importIpv4Range("192.178-179.0-255.0-255")
	importIpv4Range("192.200.224-255.0-255")
	importIpv4Range("193.120.166.64-127")
	importIpv4Range("193.134.255.0-255")
	importIpv4Range("193.142.125.0-255")
	importIpv4Range("193.186.4.0-255")
	importIpv4Range("193.192.226.128-191")
	importIpv4Range("193.192.250.128-191")
	importIpv4Range("193.200.222.0-255")
	importIpv4Range("193.247.193.0-255")
	importIpv4Range("193.90.147.0-123")
	importIpv4Range("193.92.133.0-63")
	importIpv4Range("194.100.132.128-143")
	importIpv4Range("194.110.194.0-255")
	importIpv4Range("194.78.20.16-31")
	importIpv4Range("194.78.99.0-255")
	importIpv4Range("195.100.224.112-127")
	importIpv4Range("195.141.3.24-27")
	importIpv4Range("195.205.170.64-79")
	importIpv4Range("195.229.194.88-95")
	importIpv4Range("195.244.106.0-255")
	importIpv4Range("195.244.120.144-159")
	importIpv4Range("195.249.20.192-255")
	importIpv4Range("195.65.133.128-135")
	importIpv4Range("195.76.16.136-143")
	importIpv4Range("195.81.83.176-207")
	importIpv4Range("196.3.58-59.0-255")
	importIpv4Range("197.199.253-254.1-59")
	importIpv4Range("197.84.128.0-63")
	importIpv4Range("199.192.112-115.0-255")
	importIpv4Range("199.223.232-239.0-255")
	importIpv4Range("202.39.143.1-123")
	importIpv4Range("203.116.165.129-255")
	importIpv4Range("203.117.34-37.132-187")
	importIpv4Range("203.165.13-14.210-251")
	importIpv4Range("203.211.0.4-59")
	importIpv4Range("203.66.124.129-251")
	importIpv4Range("207.223.160-175.0-255")
	importIpv4Range("208.117.224-255.0-255")
	importIpv4Range("208.65.152-155.0-255")
	importIpv4Range("209.85.128-255.0-255")
	importIpv4Range("210.139.253.20-251")
	importIpv4Range("210.153.73.20-123")
	importIpv4Range("210.242.125.20-59")
	importIpv4Range("210.61.221.65-187")
	importIpv4Range("212.154.168.224-255")
	importIpv4Range("212.162.51.64-127")
	importIpv4Range("212.181.117.144-159")
	importIpv4Range("212.188.10.0-255")
	importIpv4Range("212.188.15.0-255")
	importIpv4Range("212.188.7.0-255")
	importIpv4Range("213.186.229.0-63")
	importIpv4Range("213.187.184.68-71")
	importIpv4Range("213.240.44.0-31")
	importIpv4Range("213.252.15.0-31")
	importIpv4Range("213.31.219.80-87")
	importIpv4Range("216.21.160-175.0-255")
	importIpv4Range("216.239.32-63.0-255")
	importIpv4Range("216.58.192-223.0-255")
	importIpv4Range("217.149.45.16-31")
	importIpv4Range("217.163.7.0-255")
	importIpv4Range("217.193.96.38")
	importIpv4Range("217.28.250.44-47")
	importIpv4Range("217.28.253.32-33")
	importIpv4Range("217.30.152.192-223")
	importIpv4Range("217.33.127.208-223")
	importIpv4Range("218.176.242.4-251")
	importIpv4Range("218.189.25.129-187")
	importIpv4Range("218.253.0.76-187")
	importIpv4Range("23.228.128-191.0-255")
	importIpv4Range("23.236.48-63.0-255")
	importIpv4Range("23.251.128-159.0-255")
	importIpv4Range("23.255.128-255.0-255")
	importIpv4Range("24.156.131.0-255")
	importIpv4Range("31.209.137.0-255")
	importIpv4Range("31.7.160.192-255")
	importIpv4Range("37.228.69.0-63")
	importIpv4Range("41.206.96.1-251")
	importIpv4Range("41.84.159.12-30")
	importIpv4Range("60.199.175.1-187")
	importIpv4Range("61.219.131.65-251")
	importIpv4Range("62.0.54.64-127")
	importIpv4Range("62.1.38.64-191")
	importIpv4Range("62.116.207.0-63")
	importIpv4Range("62.197.198.193-251")
	importIpv4Range("62.20.124.48-63")
	importIpv4Range("62.201.216.196-251")
	importIpv4Range("63.243.168.0-255")
	importIpv4Range("64.15.112-127.0-255")
	importIpv4Range("64.233.160-191.0-255")
	importIpv4Range("64.9.224-255.0-255")
	importIpv4Range("66.102.0-15.0-255")
	importIpv4Range("66.185.84.0-255")
	importIpv4Range("66.249.64-95.0-255")
	importIpv4Range("69.17.141.0-255")
	importIpv4Range("70.32.128-159.0-255")
	importIpv4Range("72.14.192-255.0-255")
	importIpv4Range("74.125.0-255.0-255")
	importIpv4Range("77.109.131.208-223")
	importIpv4Range("77.40.222.224-231")
	importIpv4Range("77.42.248-255.0-255")
	importIpv4Range("77.66.9.64-123")
	importIpv4Range("78.8.8.176-191")
	importIpv4Range("8.15.202.0-255")
	importIpv4Range("8.22.56.0-255")
	importIpv4Range("8.34.208-223.0-255")
	importIpv4Range("8.35.192-207.0-255")
	importIpv4Range("8.6.48-55.0-255")
	importIpv4Range("8.8.4.0-255")
	importIpv4Range("8.8.8.0-255")
	importIpv4Range("80.227.152.32-39")
	importIpv4Range("80.228.65.128-191")
	importIpv4Range("80.231.69.0-63")
	importIpv4Range("80.239.168.192-255")
	importIpv4Range("80.80.3.176-191")
	importIpv4Range("81.175.29.128-191")
	importIpv4Range("81.93.175.232-239")
	importIpv4Range("82.135.118.0-63")
	importIpv4Range("83.100.221.224-255")
	importIpv4Range("83.141.89.124-127")
	importIpv4Range("83.145.196.128-191")
	importIpv4Range("83.220.157.100-103")
	importIpv4Range("83.94.121.128-255")
	importIpv4Range("84.233.219.144-159")
	importIpv4Range("84.235.77.1-251")
	importIpv4Range("85.182.250.0-191")
	importIpv4Range("86.127.118.128-191")
	importIpv4Range("87.244.198.160-191")
	importIpv4Range("88.159.13.192-255")
	importIpv4Range("89.207.224-231.0-255")
	importIpv4Range("89.96.249.160-175")
	importIpv4Range("92.45.86.16-31")
	importIpv4Range("93.123.23.1-59")
	importIpv4Range("93.183.211.192-255")
	importIpv4Range("93.94.217-218.0-31")
	importIpv4Range("94.200.103.64-71")
	importIpv4Range("94.40.70.0-63")
	importIpv4Range("95.143.84.128-191")
	//ip range
	importIpv4Range("61.19.1-2.0-127")
	importIpv4Range("61.19.8.0-127")
	importIpv4Range("113.21.24.0-127")
	//thx for alienwaresky
	importIpv4Range("118.143.88.16-123")
	importIpv4Range("202.86.162.20-187")
	importIpv4Range("139.175.107.20-187")
	importIpv4Range("223.26.69.16-59")
	importIpv4Range("220.255.5-6.20-251")
	importIpv4Range("202.65.246.84-123")
	importIpv4Range("103.1.139.148-251")
	importIpv4Range("116.92.194.148-187")
	importIpv4Range("58.145.238.20-59")
	//
	importIpv4Range("41.201.128.20-59")
	importIpv4Range("41.201.164.20-59")
	importIpv4Range("222.255.120.15-59")
	//odns
	importIpv4Range("119.81.145.120-127")
	importIpv4Range("119.81.142.202")
	importIpv4Range("23.239.5.106")
	importIpv4Range("74.207.242.141")
	importIpv4Range("91.213.30.143-187")

	// 至少等待4个ip可用
	ipdone.Add(4)
	log.Println("IP没有配置，搜索中，请耐心等待...")

	// 先并发搜索4个IP
	// 并发为了提高性能，但是会影响后续使用
	// 所以找到后就关闭这100个并发
	// 然后留5个慢慢搜索
	for i := 0; i < 95; i++ {
		go checkworker(4)
	}
	for i := 0; i < 5; i++ {
		go checkworker(20)
	}

	ipdone.Wait()
	log.Println("IP搜索完成，开始工作")
}

func checkworker(max int32) {
	for {
		if atomic.LoadInt32(&iptotal) >= max {
			break
		}
		var ip = randomIp()

		c, err := net.DialTimeout("tcp", ip+":443", time.Millisecond*100)
		if err != nil {
			continue
		}
		c.Close()

		req, err := http.NewRequest("GET", "https://"+ip, nil)
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				resp.Body.Close()
				goodCh <- ip
				log.Println("Found IP:", ip, err)
				atomic.AddInt32(&iptotal, 1)
				func() {
					defer func() {
						recover()
					}()
					ipdone.Done()
				}()
			}
		}
	}
}
