package bittrex

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

type Client struct {
	apiKey      string
	apiSecret   string
	httpClient  *http.Client
	httpTimeout time.Duration
	debug       bool
}

// NewClient return a new Bittrex HTTP Client
func NewClient(apiKey, apiSecret string) (c *Client) {
	return &Client{apiKey, apiSecret, &http.Client{}, 30 * time.Second, false}
}

// NewClientWithCustomHttpConfig returns a new Bittrex HTTP Client using the predefined http Client
func NewClientWithCustomHttpConfig(apiKey, apiSecret string, httpClient *http.Client) (c *Client) {
	timeout := httpClient.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{apiKey, apiSecret, httpClient, timeout, false}
}

// NewClientWithCustomTimeout returns a new Bittrex HTTP Client with custom timeout
func NewClientWithCustomTimeout(apiKey, apiSecret string, timeout time.Duration) (c *Client) {
	return &Client{apiKey, apiSecret, &http.Client{}, timeout, false}
}

func (c Client) dumpRequest(r *http.Request) {
	if r == nil {
		log.Print("dumpReq ok: <nil>")
		return
	}
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Print("dumpReq err:", err)
	} else {
		log.Print("dumpReq ok:", string(dump))
	}
}

func (c Client) dumpResponse(r *http.Response) {
	if r == nil {
		log.Print("dumpResponse ok: <nil>")
		return
	}
	dump, err := httputil.DumpResponse(r, true)
	if err != nil {
		log.Print("dumpResponse err:", err)
	} else {
		log.Print("dumpResponse ok:", string(dump))
	}
}

// doTimeoutRequest do a HTTP request with timeout
func (c *Client) doTimeoutRequest(timer *time.Timer, req *http.Request) (*http.Response, error) {
	// Do the request in the background so we can check the timeout
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		if c.debug {
			c.dumpRequest(req)
		}
		resp, err := c.httpClient.Do(req)
		if c.debug {
			c.dumpResponse(resp)
		}
		done <- result{resp, err}
	}()
	// Wait for the read or the timeout
	select {
	case r := <-done:
		return r.resp, r.err
	case <-timer.C:
		return nil, errors.New("timeout on reading data from Bittrex API")
	}
}

// do prepare and process HTTP request to Bittrex API
func (c *Client) do(method string, resource string, payload string, authNeeded bool) (response []byte, err error) {
	connectTimer := time.NewTimer(c.httpTimeout)

	var rawurl string
	if strings.HasPrefix(resource, "http") {
		rawurl = resource
	} else {
		rawurl = fmt.Sprintf("%s%s/%s", API_BASE, API_VERSION, resource)
	}

	req, err := http.NewRequest(method, rawurl, strings.NewReader(payload))
	if err != nil {
		return
	}
	if method == "POST" || method == "PUT" {
		req.Header.Add("Content-Type", "application/json;charset=utf-8")
	}
	req.Header.Add("Accept", "application/json")

	// Auth
	if authNeeded {
		if len(c.apiKey) == 0 || len(c.apiSecret) == 0 {
			err = errors.New("You need to set API Key and API Secret to call this method")
			return
		}
		nonce := time.Now().UnixNano()
		q := req.URL.Query()
		q.Set("apikey", c.apiKey)
		q.Set("nonce", fmt.Sprintf("%d", nonce))
		req.URL.RawQuery = q.Encode()
		mac := hmac.New(sha512.New, []byte(c.apiSecret))
		_, err = mac.Write([]byte(req.URL.String()))
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Add("apisign", sig)
	}

	resp, err := c.doTimeoutRequest(connectTimer, req)
	if err != nil {
		return
	}

	defer resp.Body.Close()
	response, err = ioutil.ReadAll(resp.Body)
	//fmt.Println(fmt.Sprintf("reponse %s", response), err)
	if err != nil {
		return response, err
	}
	if resp.StatusCode != 200 {
		err = errors.New(resp.Status)
	}
	return response, err
}
