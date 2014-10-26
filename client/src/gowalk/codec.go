package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
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
	Body     []byte
}

const (
	X_GW_Method = "X-GW-METHOD"
	X_GW_URL    = "X-GW-URL"
	X_GW_Status = "X-GW-STATUS"
	X_GW_PWD    = "X-GW-PWD"
)

func encode(data *HttpData) (ret []byte, err error) {
	var buff = new(bytes.Buffer)

	if data.Method != "" {
		buff.WriteString(X_GW_Method)
		buff.WriteByte(':')
		buff.WriteString(data.Method)
		buff.WriteByte('\n')
	}
	if data.Url != "" {
		buff.WriteString(X_GW_URL)
		buff.WriteByte(':')
		buff.WriteString(data.Url)
		buff.WriteByte('\n')
	}
	if data.Password != "" {
		buff.WriteString(X_GW_PWD)
		buff.WriteByte(':')
		buff.WriteString(data.Password)
		buff.WriteByte('\n')
	}
	if data.Status != 0 {
		buff.WriteString(X_GW_Status)
		buff.WriteByte(':')
		buff.WriteString(strconv.FormatInt(int64(data.Status), 10))
		buff.WriteByte('\n')
	}
	for k, i := range data.Header {
		for _, v := range i {
			buff.WriteString(k)
			buff.WriteByte(':')
			buff.WriteString(v)
			buff.WriteByte('\n')
		}
	}
	buff.WriteByte('\n')
	buff.Write(data.Body)

	t := new(bytes.Buffer)
	tt := gzip.NewWriter(t)
	_, err = tt.Write(buff.Bytes())
	if err != nil {
		tt.Close()
		return
	}
	tt.Close()
	ret = t.Bytes()

	return
}

func decode(buf []byte) (data *HttpData, err error) {
	var t *gzip.Reader
	t, err = gzip.NewReader(bytes.NewBuffer(buf))
	if err != nil {
		log.Println("Decompress failed:", err)
		return nil, err
	}
	defer t.Close()
	buf, err = ioutil.ReadAll(t)
	if err != nil {
		log.Println("Decompress content failed:", err)
		return nil, err
	}

	data = &HttpData{Header: make(http.Header)}
	var key string
	for {
		var pos = bytes.IndexAny(buf, ":\n")
		if pos == -1 {
			return nil, ErrFormat
		}
		if pos == 0 && buf[pos] == '\n' {
			// 过滤最后一个\n,并且迭代结束
			buf = buf[pos+1:]
			break
		}

		if buf[pos] == '\n' {
			return nil, ErrFormat
		}
		key = string(buf[0:pos])
		buf = buf[pos+1:]

		pos = bytes.IndexByte(buf, '\n')
		if pos == -1 {
			return nil, ErrFormat
		}

		var value = string(buf[0:pos])
		buf = buf[pos+1:]

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

	data.Body = buf
	return
}
