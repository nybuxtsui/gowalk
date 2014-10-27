package main

import (
	"appengine"
	"appengine/urlfetch"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	version = "0.1"
)

func init() {
	http.HandleFunc("/", handler)
}

func handler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		fmt.Fprint(w, "version:", version)
	default:
		proxy(w, r)
	}
}

func proxy(w http.ResponseWriter, r *http.Request) error {
	c := appengine.NewContext(r)
	client := urlfetch.Client(c)
	client.Transport.(*urlfetch.Transport).Deadline = time.Second * 60

	var buff, err = ioutil.ReadAll(r.Body)
	if err != nil {
		c.Errorf("Read request body failed: %v", err)
		http.Error(w, "InternalServerError", http.StatusInternalServerError)
		return err
	}

	var data *HttpData
	data, err = decode(buff)
	if data.Password != password {
		c.Errorf("Password not match: %v, %v", data.Password, password)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return err
	}
	c.Infof("Fetch: %v %v", data.Method, data.Url)

	req, err := http.NewRequest(data.Method, data.Url, bytes.NewBuffer(data.Body))
	if err != nil {
		c.Errorf("Create request failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	for k, i := range data.Header {
		for _, v := range i {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Transport.RoundTrip(req)
	if err != nil {
		c.Errorf("Fetch failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()

	data.Status = resp.StatusCode
	data.Method = ""
	data.Url = ""
	data.Header = resp.Header
	data.Body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		c.Errorf("Read response failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	buff, err = encode(data)
	if err != nil {
		c.Errorf("Encode response failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	w.Write(buff)
	return nil
}
