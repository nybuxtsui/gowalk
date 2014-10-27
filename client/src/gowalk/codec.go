package main

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var (
	// 格式错误
	ErrFormat = errors.New("format")
)

type HttpData struct {
	Method   string
	Url      string
	Password string
	Status   int
	Header   http.Header
	Body     io.ReadCloser
}

const (
	X_GW_Method = "X-GW-METHOD"
	X_GW_URL    = "X-GW-URL"
	X_GW_Status = "X-GW-STATUS"
	X_GW_PWD    = "X-GW-PWD"
)

func encode(data *HttpData, w io.Writer, cn <-chan bool) (err error) {
	zw := gzip.NewWriter(w)
	if data.Method != "" {
		zw.Write([]byte(X_GW_Method))
		zw.Write([]byte{':'})
		zw.Write([]byte(data.Method))
		zw.Write([]byte{'\n'})
	}
	if data.Url != "" {
		zw.Write([]byte(X_GW_URL))
		zw.Write([]byte{':'})
		zw.Write([]byte(data.Url))
		zw.Write([]byte{'\n'})
	}
	if data.Password != "" {
		zw.Write([]byte(X_GW_PWD))
		zw.Write([]byte{':'})
		zw.Write([]byte(data.Password))
		zw.Write([]byte{'\n'})
	}
	if data.Status != 0 {
		zw.Write([]byte(X_GW_Status))
		zw.Write([]byte{':'})
		zw.Write([]byte(strconv.FormatInt(int64(data.Status), 10)))
		zw.Write([]byte{'\n'})
	}
	for k, i := range data.Header {
		for _, v := range i {
			zw.Write([]byte(k))
			zw.Write([]byte{':'})
			zw.Write([]byte(v))
			zw.Write([]byte{'\n'})
		}
	}
	zw.Write([]byte{'\n'})
	buf := make([]byte, 8*1024)
	for {
		select {
		case <-cn:
			return io.EOF
		default:
		}
		buf = buf[:cap(buf)]
		n, err := data.Body.Read(buf)
		if n != 0 {
			zw.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	err = zw.Close()
	return
}

type BufGzipReader struct {
	r *bufio.Reader
	z *gzip.Reader
}

func (r *BufGzipReader) Close() error {
	return r.z.Close()
}

func (r *BufGzipReader) Read(p []byte) (n int, err error) {
	return r.r.Read(p)
}

func decode(_r io.Reader) (data *HttpData, err error) {
	zr, err := gzip.NewReader(_r)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && zr != nil {
			zr.Close()
		}
	}()
	r := &BufGzipReader{bufio.NewReader(zr), zr}

	data = &HttpData{Header: make(http.Header)}
	for {
		line, err := r.r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if len(line) == 1 {
			// 遇到空行,迭代结束
			break
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			return nil, ErrFormat
		}
		key := kv[0]
		value := kv[1][0 : len(kv[1])-1]
		if key == "" {
			return nil, ErrFormat
		} else if key == X_GW_Method {
			data.Method = value
		} else if key == X_GW_URL {
			data.Url = value
		} else if key == X_GW_PWD {
			data.Password = value
		} else if key == X_GW_Status {
			var code int64
			code, err = strconv.ParseInt(value, 10, 32)
			if err != nil {
				return nil, ErrFormat
			}
			data.Status = int(code)
		} else {
			data.Header.Add(key, value)
		}
	}
	data.Body = r
	return
}
