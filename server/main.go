package main

import (
	"appengine"
	"appengine/urlfetch"
	"fmt"
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

	data, err := decode(r.Body)
	if err != nil {
		c.Errorf("decode failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	defer data.Body.Close()

	if data.Password != password {
		c.Errorf("Password not match: %v, %v", data.Password, password)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return err
	}
	c.Infof("Fetch: %v %v", data.Method, data.Url)

	req, err := http.NewRequest(data.Method, data.Url, data.Body)
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
	data.Body = resp.Body
	err = encode(data, w)
	if err != nil {
		c.Errorf("Encode response failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return err
	}
	return nil
}
