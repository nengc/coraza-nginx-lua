package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

const (
	httpStatusBlocked int = 403
	httpStatusError   int = 401
)

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func main() {
	// 修复 WAF 配置
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRequestBodyAccess().
		WithRequestBodyLimit(100 * 1024). // 设置请求体大小限制为 100KB
		WithDirectivesFromFile("/src/coraza.conf").
		WithDirectivesFromFile("/src/coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("/src/coreruleset/rules/*.conf"))
	if err != nil {
		panic(err)
	}
	fmt.Println("Starting POC")
	if err := http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("New transaction request")
		id := r.Header.Get("X-Coraza-ID")
		uri := r.Header.Get("X-Coraza-URL")
		if id == "" {
			http.Error(w, "X-Coraza-ID cannot be empty", httpStatusError)
			fmt.Println("X-Coraza-ID cannot be empty")
			return
		}
		if uri == "" {
			http.Error(w, "X-Coraza-URL cannot be empty", httpStatusError)
			fmt.Println("X-Coraza-URL cannot be empty")
			return
		}
		u, err := url.Parse(uri)
		if err != nil {
			http.Error(w, err.Error(), httpStatusError)
			fmt.Println(err.Error())
			return
		}
		*r.URL = *u

		for _, h := range []string{"X-Coraza-ID", "X-Coraza-URL"} {
			r.Header.Del(h)
		}
		tx := waf.NewTransactionWithID(id)
		defer func() {
			tx.ProcessLogging()
			tx.Close()
		}()
		w.Header().Set("X-Coraza-Id", id)
		if it, err := processRequest(tx, r); err != nil {
			http.Error(w, err.Error(), httpStatusError)
			fmt.Println("Request error:", err)
		} else if it != nil {
			w.WriteHeader(httpStatusBlocked)
			fmt.Fprint(w, it.RuleID)
			fmt.Println("Request blocked")
		} else if _, err := w.Write([]byte("ok")); err != nil {
			fmt.Println(err)
			fmt.Println("Response error")
			return
		}
		fmt.Printf("Transaction %s ok\n", id)
	})); err != nil {
		panic(err)
	}
}

func processRequest(tx types.Transaction, req *http.Request) (*types.Interruption, error) {
	var (
		client string
		cport  int
	)
	// IMPORTANT: Some http.Request.RemoteAddr implementations will not contain port or contain IPV6: [2001:db8::1]:8080
	idx := strings.LastIndexByte(req.RemoteAddr, ':')
	if idx != -1 {
		client = req.RemoteAddr[:idx]
		cport, _ = strconv.Atoi(req.RemoteAddr[idx+1:])
	}

	var in *types.Interruption
	// There is no socket access in the request object, so we neither know the server client nor port.
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}
	// Host will always be removed from req.Headers(), so we manually add it
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
	}

	in = tx.ProcessRequestHeaders()
	if in != nil {
		return in, nil
	}
	if req.Body != nil && req.Body != http.NoBody {
		// 修复：使用新的 API 处理请求体
		// 首先读取整个请求体
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return tx.Interruption(), err
		}
		_ = req.Body.Close()
		
		// 将请求体写入事务 - WriteRequestBody 返回写入的字节数和可能的错误
		_, err = tx.WriteRequestBody(bodyBytes)
		if err != nil {
			return tx.Interruption(), err
		}
		
		// 重新设置请求体为读取的数据
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	return tx.ProcessRequestBody()
}
