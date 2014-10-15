package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/nybuxtsui/ca/depot"
	"log"
	"net"
	"net/http"
	"strings"
)

type httpsReq struct {
	conn net.Conn
	host string
}

type handler struct {
	ch chan *httpsReq
}

var (
	client   *http.Client
	certPool *x509.CertPool
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
			log.Println("getCert failed:", err)
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

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("req:", r.Method, r.URL, r.Header)
	if r.Method == "CONNECT" {
		addr := strings.Split(r.URL.String(), ":")
		if len(addr) != 2 || len(addr[0]) <= 2 {
			log.Println("bad https req")
			http.Error(w, "bad connect req", http.StatusBadRequest)
			return
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			log.Println("webserver doesn't support hijacking")
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			log.Println(err)
			return
		}
		bufrw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		bufrw.Flush()
		h.ch <- &httpsReq{conn, addr[0][2:]}
		log.Println("hijack")
	} else {
		fmt.Fprintf(w, "%v", r.URL)
	}
}

func main() {
	var err error

	log.Println("start...")
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
			Handler: h,
			TLSConfig: &tls.Config{
				ClientAuth:         tls.VerifyClientCertIfGiven,
				ClientCAs:          certPool,
				InsecureSkipVerify: true,
			},
		}
		server.Serve(h)
	}()

	http.ListenAndServe(":8080", h)
}
