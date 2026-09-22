package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	upstreams []string
	ttft      time.Duration
	reqCount  atomic.Int64
	client    *http.Client
)

const maxBodyBytes = 10 << 20

func main() {
	listen := os.Getenv("LISTEN_ADDR")
	if listen == "" {
		listen = "127.0.0.1:18080"
	}
	upstreams = splitUpstreams(os.Getenv("UPSTREAMS"))
	ttftMs := 5000
	if v := os.Getenv("TTFT_TIMEOUT_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			ttftMs = n
		}
	}
	ttft = time.Duration(ttftMs) * time.Millisecond

	client = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        1024,
			MaxIdleConnsPerHost: 512,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
			DialContext: (&net.Dialer{
				Timeout: 2 * time.Second,
			}).DialContext,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "proxy_requests_total %d\n", reqCount.Load())
	})
	mux.HandleFunc("/v1/chat/completions", handleChat)

	srv := &http.Server{Addr: listen, Handler: mux}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	if err := srv.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}

func splitUpstreams(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isStream(body []byte) bool {
	var req struct {
		Stream bool `json:"stream"`
	}
	json.Unmarshal(body, &req)
	return req.Stream
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	reqCount.Add(1)
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, 413, "request body too large")
		} else {
			writeError(w, 400, "failed to read request body")
		}
		return
	}
	stream := isStream(body)

	for _, up := range upstreams {
		ok, _ := tryUpstream(w, r, up, body, stream)
		if ok {
			return
		}
		if r.Context().Err() != nil {
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(502)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{"message": "all upstreams failed", "type": "upstream_error"},
	})
}

func tryUpstream(w http.ResponseWriter, r *http.Request, up string, body []byte, stream bool) (bool, error) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", up+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	for k, vv := range r.Header {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		io.Copy(io.Discard, resp.Body)
		return false, fmt.Errorf("upstream status %d", resp.StatusCode)
	}

	if !stream {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		w.Write(data)
		return true, nil
	}

	br := bufio.NewReader(resp.Body)
	type chunkRes struct {
		data []byte
		err  error
	}
	ch := make(chan chunkRes, 1)
	go func() {
		buf := make([]byte, 4096)
		n, err := br.Read(buf)
		ch <- chunkRes{buf[:n], err}
	}()

	var firstErr error
	select {
	case cr := <-ch:
		firstErr = cr.err
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if len(cr.data) > 0 {
			w.Write(cr.data)
		}
		flush(w)
		streamRest(w, r, br, firstErr)
		return true, nil
	case <-time.After(ttft):
		cancel()
		<-ch
		return false, fmt.Errorf("ttft timeout")
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func streamRest(w http.ResponseWriter, r *http.Request, br *bufio.Reader, firstErr error) {
	if firstErr == io.EOF {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			flush(w)
		}
		if err != nil {
			return
		}
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{"message": msg, "type": "invalid_request_error"},
	})
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		lk := strings.ToLower(k)
		if lk == "transfer-encoding" || lk == "connection" || lk == "keep-alive" ||
			lk == "proxy-connection" || lk == "te" || lk == "trailer" ||
			lk == "upgrade" || lk == "content-length" {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func flush(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}