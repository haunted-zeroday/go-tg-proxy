// tgws.go
// go mod init tgws
// go get github.com/gorilla/websocket
// go build -ldflags="-s -w" -o tg_ws_proxy.exe
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultPort   = 1080
	recvBuf       = 65536
	sendBuf       = 65536
	wsPoolSize    = 4
	wsPoolMaxAge  = 120 * time.Second
	dcFailCooldown = 60 * time.Second
)


type ipRange struct{ lo, hi uint32 }

var tgRanges = []ipRange{
	{ipToU32("185.76.151.0"), ipToU32("185.76.151.255")},
	{ipToU32("149.154.160.0"), ipToU32("149.154.175.255")},
	{ipToU32("91.105.192.0"), ipToU32("91.105.193.255")},
	{ipToU32("91.108.0.0"), ipToU32("91.108.255.255")},
}

func ipToU32(s string) uint32 {
	ip := net.ParseIP(s).To4()
	return binary.BigEndian.Uint32(ip)
}

func isTelegramIP(ip string) bool {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return false
	}
	n := binary.BigEndian.Uint32(parsed)
	for _, r := range tgRanges {
		if n >= r.lo && n <= r.hi {
			return true
		}
	}
	return false
}

type dcInfo struct {
	dc      int
	isMedia bool
}

var ipToDC = map[string]dcInfo{
	// DC1
	"149.154.175.50": {1, false}, "149.154.175.51": {1, false},
	"149.154.175.53": {1, false}, "149.154.175.54": {1, false},
	"149.154.175.52": {1, true},
	// DC2
	"149.154.167.41":  {2, false}, "149.154.167.50": {2, false},
	"149.154.167.51":  {2, false}, "149.154.167.220": {2, false},
	"95.161.76.100":   {2, false},
	"149.154.167.151": {2, true}, "149.154.167.222": {2, true},
	"149.154.167.223": {2, true}, "149.154.162.123": {2, true},
	// DC3
	"149.154.175.100": {3, false}, "149.154.175.101": {3, false},
	"149.154.175.102": {3, true},
	// DC4
	"149.154.167.91":  {4, false}, "149.154.167.92": {4, false},
	"149.154.164.250": {4, true}, "149.154.166.120": {4, true},
	"149.154.166.121": {4, true}, "149.154.167.118": {4, true},
	"149.154.165.111": {4, true},
	// DC5
	"91.108.56.100":  {5, false}, "91.108.56.101": {5, false},
	"91.108.56.116":  {5, false}, "91.108.56.126": {5, false},
	"149.154.171.5":  {5, false},
	"91.108.56.102":  {5, true}, "91.108.56.128": {5, true},
	"91.108.56.151":  {5, true},
}

// ─── dcKey ──────────────────────────────────────────────────────────

type dcKey struct {
	dc      int
	isMedia bool
}

// ─── Global state ───────────────────────────────────────────────────

var (
	dcOpt       = map[int]string{}   // dc -> target IP
	dcOptMu     sync.RWMutex

	wsBlacklist   = map[dcKey]bool{}
	wsBlacklistMu sync.RWMutex

	dcFailUntil   = map[dcKey]time.Time{}
	dcFailUntilMu sync.RWMutex

	tlsConfig = &tls.Config{InsecureSkipVerify: true}

	verbose bool
)

// ─── Stats ──────────────────────────────────────────────────────────

type Stats struct {
	connectionsTotal       int64
	connectionsWS          int64
	connectionsTCPFallback int64
	connectionsHTTPRejected int64
	connectionsPassthrough int64
	wsErrors               int64
	bytesUp                int64
	bytesDown              int64
	poolHits               int64
	poolMisses             int64
}

func (s *Stats) summary() string {
	hits := atomic.LoadInt64(&s.poolHits)
	misses := atomic.LoadInt64(&s.poolMisses)
	return fmt.Sprintf("total=%d ws=%d tcp_fb=%d http_skip=%d pass=%d err=%d pool=%d/%d up=%s down=%s",
		atomic.LoadInt64(&s.connectionsTotal),
		atomic.LoadInt64(&s.connectionsWS),
		atomic.LoadInt64(&s.connectionsTCPFallback),
		atomic.LoadInt64(&s.connectionsHTTPRejected),
		atomic.LoadInt64(&s.connectionsPassthrough),
		atomic.LoadInt64(&s.wsErrors),
		hits, hits+misses,
		humanBytes(atomic.LoadInt64(&s.bytesUp)),
		humanBytes(atomic.LoadInt64(&s.bytesDown)),
	)
}

var stats Stats

func humanBytes(n int64) string {
	f := float64(n)
	for _, unit := range []string{"B", "KB", "MB", "GB"} {
		if math.Abs(f) < 1024 {
			return fmt.Sprintf("%.1f%s", f, unit)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1fTB", f)
}

// ─── WebSocket helpers ──────────────────────────────────────────────

const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

func xorMask(data, mask []byte) []byte {
	if len(data) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ mask[i%4]
	}
	return out
}

func buildWSFrame(opcode byte, data []byte, masked bool) []byte {
	var buf []byte
	buf = append(buf, 0x80|opcode) // FIN=1

	length := len(data)
	var maskBit byte
	if masked {
		maskBit = 0x80
	}

	if length < 126 {
		buf = append(buf, maskBit|byte(length))
	} else if length < 65536 {
		buf = append(buf, maskBit|126)
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(length))
		buf = append(buf, b...)
	} else {
		buf = append(buf, maskBit|127)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(length))
		buf = append(buf, b...)
	}

	if masked {
		maskKey := make([]byte, 4)
		rand.Read(maskKey)
		buf = append(buf, maskKey...)
		buf = append(buf, xorMask(data, maskKey)...)
	} else {
		buf = append(buf, data...)
	}
	return buf
}


type WsHandshakeError struct {
	StatusCode int
	StatusLine string
	Headers    map[string]string
	Location   string
}

func (e *WsHandshakeError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.StatusLine)
}

func (e *WsHandshakeError) IsRedirect() bool {
	switch e.StatusCode {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}


type RawWebSocket struct {
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex // protects writes
	closed bool
}

func wsConnect(ip, domain, path string, timeout time.Duration) (*RawWebSocket, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", ip+":443", &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	})
	if err != nil {
		return nil, err
	}

	setSockOpts(conn)

	wsKey := make([]byte, 16)
	rand.Read(wsKey)
	keyStr := base64.StdEncoding.EncodeToString(wsKey)

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Protocol: binary\r\n"+
			"Origin: https://web.telegram.org\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
			"AppleWebKit/537.36 (KHTML, like Gecko) "+
			"Chrome/131.0.0.0 Safari/537.36\r\n"+
			"\r\n",
		path, domain, keyStr,
	)

	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(req))
	if err != nil {
		conn.Close()
		return nil, err
	}

	reader := bufio.NewReaderSize(conn, recvBuf)

	var responseLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		responseLines = append(responseLines, line)
	}

	conn.SetDeadline(time.Time{}) // clear deadline

	if len(responseLines) == 0 {
		conn.Close()
		return nil, &WsHandshakeError{0, "empty response", nil, ""}
	}

	firstLine := responseLines[0]
	parts := strings.SplitN(firstLine, " ", 3)
	statusCode := 0
	if len(parts) >= 2 {
		statusCode, _ = strconv.Atoi(parts[1])
	}

	if statusCode == 101 {
		return &RawWebSocket{conn: conn, reader: reader}, nil
	}

	headers := map[string]string{}
	for _, hl := range responseLines[1:] {
		idx := strings.Index(hl, ":")
		if idx >= 0 {
			k := strings.TrimSpace(strings.ToLower(hl[:idx]))
			v := strings.TrimSpace(hl[idx+1:])
			headers[k] = v
		}
	}
	conn.Close()
	return nil, &WsHandshakeError{
		StatusCode: statusCode,
		StatusLine: firstLine,
		Headers:    headers,
		Location:   headers["location"],
	}
}

func (ws *RawWebSocket) Send(data []byte) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.closed {
		return fmt.Errorf("WebSocket closed")
	}
	frame := buildWSFrame(wsOpBinary, data, true)
	_, err := ws.conn.Write(frame)
	return err
}

func (ws *RawWebSocket) SendBatch(parts [][]byte) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.closed {
		return fmt.Errorf("WebSocket closed")
	}
	var buf []byte
	for _, part := range parts {
		buf = append(buf, buildWSFrame(wsOpBinary, part, true)...)
	}
	_, err := ws.conn.Write(buf)
	return err
}

func (ws *RawWebSocket) Recv() ([]byte, error) {
	for !ws.closed {
		opcode, payload, err := ws.readFrame()
		if err != nil {
			ws.closed = true
			return nil, err
		}

		switch opcode {
		case wsOpClose:
			ws.closed = true
			// Send close reply
			closePayload := payload
			if len(closePayload) > 2 {
				closePayload = closePayload[:2]
			}
			ws.mu.Lock()
			ws.conn.Write(buildWSFrame(wsOpClose, closePayload, true))
			ws.mu.Unlock()
			return nil, io.EOF

		case wsOpPing:
			ws.mu.Lock()
			ws.conn.Write(buildWSFrame(wsOpPong, payload, true))
			ws.mu.Unlock()
			continue

		case wsOpPong:
			continue

		case wsOpText, wsOpBinary:
			return payload, nil

		default:
			continue
		}
	}
	return nil, io.EOF
}

func (ws *RawWebSocket) Close() {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.closed {
		return
	}
	ws.closed = true
	ws.conn.Write(buildWSFrame(wsOpClose, []byte{}, true))
	ws.conn.Close()
}

func (ws *RawWebSocket) readFrame() (byte, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(ws.reader, hdr); err != nil {
		return 0, nil, err
	}

	opcode := hdr[0] & 0x0F
	isMasked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)

	if length == 126 {
		b := make([]byte, 2)
		if _, err := io.ReadFull(ws.reader, b); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(b))
	} else if length == 127 {
		b := make([]byte, 8)
		if _, err := io.ReadFull(ws.reader, b); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(b)
	}

	var maskKey []byte
	if isMasked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(ws.reader, maskKey); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(ws.reader, payload); err != nil {
			return 0, nil, err
		}
	}

	if isMasked {
		payload = xorMask(payload, maskKey)
	}

	return opcode, payload, nil
}

// ─── Socket options ─────────────────────────────────────────────────

func setSockOpts(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(recvBuf)
		tc.SetWriteBuffer(sendBuf)
	}
	// For TLS connections, try to get underlying
	if tlsConn, ok := conn.(*tls.Conn); ok {
		_ = tlsConn // can't easily set TCP opts on TLS wrapper in Go stdlib
	}
}

// ─── HTTP transport detection ───────────────────────────────────────

func isHTTPTransport(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return string(data[:5]) == "POST " ||
		string(data[:4]) == "GET " ||
		string(data[:5]) == "HEAD " ||
		(len(data) >= 8 && string(data[:8]) == "OPTIONS ")
}

// ─── DC extraction from init packet ────────────────────────────────

func dcFromInit(data []byte) (dc int, isMedia bool, ok bool) {
	if len(data) < 64 {
		return 0, false, false
	}

	key := make([]byte, 32)
	copy(key, data[8:40])
	iv := make([]byte, 16)
	copy(iv, data[40:56])

	block, err := aes.NewCipher(key)
	if err != nil {
		debugLog("DC extraction failed: %v", err)
		return 0, false, false
	}
	stream := cipher.NewCTR(block, iv)
	keystream := make([]byte, 64)
	stream.XORKeyStream(keystream, keystream)

	plain := make([]byte, 8)
	for i := 0; i < 8; i++ {
		plain[i] = data[56+i] ^ keystream[56+i]
	}

	proto := binary.LittleEndian.Uint32(plain[0:4])
	dcRaw := int16(binary.LittleEndian.Uint16(plain[4:6]))

	debugLog("dc_from_init: proto=0x%08X dc_raw=%d plain=%x", proto, dcRaw, plain)

	if proto == 0xEFEFEFEF || proto == 0xEEEEEEEE || proto == 0xDDDDDDDD {
		dcVal := int(dcRaw)
		if dcVal < 0 {
			dcVal = -dcVal
		}
		if dcVal >= 1 && dcVal <= 5 {
			return dcVal, dcRaw < 0, true
		}
	}
	return 0, false, false
}

func patchInitDC(data []byte, dc int) []byte {
	if len(data) < 64 {
		return data
	}

	newDC := make([]byte, 2)
	binary.LittleEndian.PutUint16(newDC, uint16(int16(dc)))

	key := make([]byte, 32)
	copy(key, data[8:40])
	iv := make([]byte, 16)
	copy(iv, data[40:56])

	block, err := aes.NewCipher(key)
	if err != nil {
		return data
	}
	stream := cipher.NewCTR(block, iv)
	ks := make([]byte, 64)
	stream.XORKeyStream(ks, ks)

	patched := make([]byte, len(data))
	copy(patched, data)
	patched[60] = ks[60] ^ newDC[0]
	patched[61] = ks[61] ^ newDC[1]

	debugLog("init patched: dc_id -> %d", dc)
	return patched
}

// ─── MsgSplitter ────────────────────────────────────────────────────

type MsgSplitter struct {
	stream cipher.Stream
}

func newMsgSplitter(initData []byte) (*MsgSplitter, error) {
	if len(initData) < 56 {
		return nil, fmt.Errorf("init data too short")
	}
	key := make([]byte, 32)
	copy(key, initData[8:40])
	iv := make([]byte, 16)
	copy(iv, initData[40:56])

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	// Skip init packet (64 bytes of keystream)
	skip := make([]byte, 64)
	stream.XORKeyStream(skip, skip)

	return &MsgSplitter{stream: stream}, nil
}

func (s *MsgSplitter) Split(chunk []byte) [][]byte {
	plain := make([]byte, len(chunk))
	s.stream.XORKeyStream(plain, chunk)

	var boundaries []int
	pos := 0
	for pos < len(plain) {
		first := plain[pos]
		var msgLen int
		if first == 0x7f {
			if pos+4 > len(plain) {
				break
			}
			v := uint32(plain[pos+1]) | uint32(plain[pos+2])<<8 | uint32(plain[pos+3])<<16
			msgLen = int(v) * 4
			pos += 4
		} else {
			msgLen = int(first) * 4
			pos += 1
		}
		if msgLen == 0 || pos+msgLen > len(plain) {
			break
		}
		pos += msgLen
		boundaries = append(boundaries, pos)
	}

	if len(boundaries) <= 1 {
		return [][]byte{chunk}
	}

	var parts [][]byte
	prev := 0
	for _, b := range boundaries {
		parts = append(parts, chunk[prev:b])
		prev = b
	}
	if prev < len(chunk) {
		parts = append(parts, chunk[prev:])
	}
	return parts
}

// ─── WS domains ─────────────────────────────────────────────────────

func wsDomains(dc int, isMedia bool) []string {
	if isMedia {
		return []string{
			fmt.Sprintf("kws%d-1.web.telegram.org", dc),
			fmt.Sprintf("kws%d.web.telegram.org", dc),
		}
	}
	return []string{
		fmt.Sprintf("kws%d.web.telegram.org", dc),
		fmt.Sprintf("kws%d-1.web.telegram.org", dc),
	}
}

// ─── WS Pool ────────────────────────────────────────────────────────

type poolEntry struct {
	ws      *RawWebSocket
	created time.Time
}

type WsPool struct {
	mu        sync.Mutex
	idle      map[dcKey][]poolEntry
	refilling map[dcKey]bool
}

func newWsPool() *WsPool {
	return &WsPool{
		idle:      make(map[dcKey][]poolEntry),
		refilling: make(map[dcKey]bool),
	}
}

func (p *WsPool) Get(dc int, isMedia bool, targetIP string, domains []string) *RawWebSocket {
	key := dcKey{dc, isMedia}
	p.mu.Lock()

	bucket := p.idle[key]
	now := time.Now()
	for len(bucket) > 0 {
		entry := bucket[0]
		bucket = bucket[1:]
		p.idle[key] = bucket

		age := now.Sub(entry.created)
		if age > wsPoolMaxAge || entry.ws.closed {
			go entry.ws.Close()
			continue
		}

		atomic.AddInt64(&stats.poolHits, 1)
		mediaStr := ""
		if isMedia {
			mediaStr = "m"
		}
		debugLog("WS pool hit for DC%d%s (age=%.1fs, left=%d)", dc, mediaStr, age.Seconds(), len(bucket))
		p.scheduleRefill(key, targetIP, domains)
		p.mu.Unlock()
		return entry.ws
	}

	atomic.AddInt64(&stats.poolMisses, 1)
	p.scheduleRefill(key, targetIP, domains)
	p.mu.Unlock()
	return nil
}

func (p *WsPool) scheduleRefill(key dcKey, targetIP string, domains []string) {
	if p.refilling[key] {
		return
	}
	p.refilling[key] = true
	go p.refill(key, targetIP, domains)
}

func (p *WsPool) refill(key dcKey, targetIP string, domains []string) {
	defer func() {
		p.mu.Lock()
		delete(p.refilling, key)
		p.mu.Unlock()
	}()

	p.mu.Lock()
	needed := wsPoolSize - len(p.idle[key])
	p.mu.Unlock()

	if needed <= 0 {
		return
	}

	type result struct {
		ws *RawWebSocket
	}
	ch := make(chan result, needed)

	for i := 0; i < needed; i++ {
		go func() {
			ws := connectOneWS(targetIP, domains)
			ch <- result{ws}
		}()
	}

	for i := 0; i < needed; i++ {
		r := <-ch
		if r.ws != nil {
			p.mu.Lock()
			p.idle[key] = append(p.idle[key], poolEntry{r.ws, time.Now()})
			p.mu.Unlock()
		}
	}

	mediaStr := ""
	if key.isMedia {
		mediaStr = "m"
	}
	p.mu.Lock()
	count := len(p.idle[key])
	p.mu.Unlock()
	debugLog("WS pool refilled DC%d%s: %d ready", key.dc, mediaStr, count)
}

func connectOneWS(targetIP string, domains []string) *RawWebSocket {
	for _, domain := range domains {
		ws, err := wsConnect(targetIP, domain, "/apiws", 8*time.Second)
		if err != nil {
			if he, ok := err.(*WsHandshakeError); ok && he.IsRedirect() {
				continue
			}
			return nil
		}
		return ws
	}
	return nil
}

func (p *WsPool) Warmup(dcOpts map[int]string) {
	for dc, targetIP := range dcOpts {
		if targetIP == "" {
			continue
		}
		for _, isMedia := range []bool{false, true} {
			domains := wsDomains(dc, isMedia)
			key := dcKey{dc, isMedia}
			p.mu.Lock()
			p.scheduleRefill(key, targetIP, domains)
			p.mu.Unlock()
		}
	}
	log.Printf("WS pool warmup started for %d DC(s)", len(dcOpts))
}

var wsPool = newWsPool()

// ─── SOCKS5 reply ───────────────────────────────────────────────────

func socks5Reply(status byte) []byte {
	return []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}

// ─── Logging helpers ────────────────────────────────────────────────

func debugLog(format string, args ...interface{}) {
	if verbose {
		log.Printf("DEBUG "+format, args...)
	}
}

// ─── readExactly ────────────────────────────────────────────────────

func readExactly(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// ─── TCP pipe ───────────────────────────────────────────────────────

func tcpPipe(src io.Reader, dst net.Conn, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	buf := make([]byte, recvBuf)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// ─── Bridge WS ──────────────────────────────────────────────────────

func bridgeWS(client net.Conn, ws *RawWebSocket, label string,
	dc int, dst string, port int, isMedia bool, splitter *MsgSplitter) {

	dcTag := "DC?"
	if dc > 0 {
		mediaStr := ""
		if isMedia {
			mediaStr = "m"
		}
		dcTag = fmt.Sprintf("DC%d%s", dc, mediaStr)
	}
	dstTag := fmt.Sprintf("%s:%d", dst, port)

	var upBytes, downBytes int64
	var upPackets, downPackets int64
	startTime := time.Now()

	done := make(chan struct{}, 2)

	// TCP -> WS
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, recvBuf)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				atomic.AddInt64(&stats.bytesUp, int64(n))
				upBytes += int64(n)
				upPackets++

				if splitter != nil {
					parts := splitter.Split(chunk)
					if len(parts) > 1 {
						if serr := ws.SendBatch(parts); serr != nil {
							return
						}
					} else {
						if serr := ws.Send(parts[0]); serr != nil {
							return
						}
					}
				} else {
					if serr := ws.Send(chunk); serr != nil {
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// WS -> TCP
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			data, err := ws.Recv()
			if err != nil || data == nil {
				return
			}
			atomic.AddInt64(&stats.bytesDown, int64(len(data)))
			downBytes += int64(len(data))
			downPackets++
			if _, werr := client.Write(data); werr != nil {
				return
			}
		}
	}()

	<-done // wait for first goroutine to finish

	elapsed := time.Since(startTime).Seconds()
	log.Printf("[%s] %s (%s) WS session closed: ^%s (%d pkts) v%s (%d pkts) in %.1fs",
		label, dcTag, dstTag,
		humanBytes(upBytes), upPackets,
		humanBytes(downBytes), downPackets,
		elapsed)

	ws.Close()
	client.Close()
}

// ─── Bridge TCP ─────────────────────────────────────────────────────

func bridgeTCP(client, remote net.Conn, label string) {
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, recvBuf)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				atomic.AddInt64(&stats.bytesUp, int64(n))
				if _, werr := remote.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, recvBuf)
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				atomic.AddInt64(&stats.bytesDown, int64(n))
				if _, werr := client.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	client.Close()
	remote.Close()
}

// ─── TCP fallback ───────────────────────────────────────────────────

func tcpFallback(client net.Conn, dst string, port int, init []byte, label string, dc int, isMedia bool) bool {
	addr := fmt.Sprintf("%s:%d", dst, port)
	remote, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Printf("[%s] TCP fallback connect to %s failed: %v", label, addr, err)
		return false
	}

	atomic.AddInt64(&stats.connectionsTCPFallback, 1)
	remote.Write(init)
	bridgeTCP(client, remote, label)
	return true
}

// ─── Handle client ──────────────────────────────────────────────────

func handleClient(conn net.Conn) {
	atomic.AddInt64(&stats.connectionsTotal, 1)
	label := conn.RemoteAddr().String()
	setSockOpts(conn)

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// -- SOCKS5 greeting --
	hdr, err := readExactly(conn, 2)
	if err != nil {
		debugLog("[%s] read greeting failed: %v", label, err)
		return
	}
	if hdr[0] != 5 {
		debugLog("[%s] not SOCKS5 (ver=%d)", label, hdr[0])
		return
	}
	nmethods := int(hdr[1])
	if _, err := readExactly(conn, nmethods); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // no auth

	// -- SOCKS5 CONNECT --
	req, err := readExactly(conn, 4)
	if err != nil {
		return
	}
	cmd := req[1]
	atyp := req[3]

	if cmd != 1 {
		conn.Write(socks5Reply(0x07))
		return
	}

	var dst string
	switch atyp {
	case 1: // IPv4
		raw, err := readExactly(conn, 4)
		if err != nil {
			return
		}
		dst = net.IP(raw).String()
	case 3: // domain
		dlenBuf, err := readExactly(conn, 1)
		if err != nil {
			return
		}
		domainBytes, err := readExactly(conn, int(dlenBuf[0]))
		if err != nil {
			return
		}
		dst = string(domainBytes)
	case 4: // IPv6
		raw, err := readExactly(conn, 16)
		if err != nil {
			return
		}
		dst = net.IP(raw).String()
	default:
		conn.Write(socks5Reply(0x08))
		return
	}

	portBuf, err := readExactly(conn, 2)
	if err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	// IPv6 check
	if strings.Contains(dst, ":") {
		log.Printf("[%s] IPv6 address detected: %s:%d — not supported", label, dst, port)
		conn.Write(socks5Reply(0x05))
		return
	}

	// -- Non-Telegram -> passthrough --
	if !isTelegramIP(dst) {
		atomic.AddInt64(&stats.connectionsPassthrough, 1)
		debugLog("[%s] passthrough -> %s:%d", label, dst, port)
		remote, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", dst, port), 10*time.Second)
		if err != nil {
			log.Printf("[%s] passthrough failed to %s: %v", label, dst, err)
			conn.Write(socks5Reply(0x05))
			return
		}
		conn.Write(socks5Reply(0x00))
		conn.SetDeadline(time.Time{})

		done := make(chan struct{}, 2)
		go tcpPipe(conn, remote, done)
		go tcpPipe(remote, conn, done)
		<-done
		conn.Close()
		remote.Close()
		return
	}

	// -- Telegram DC --
	conn.Write(socks5Reply(0x00))
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	init, err := readExactly(conn, 64)
	if err != nil {
		debugLog("[%s] client disconnected before init", label)
		return
	}

	conn.SetDeadline(time.Time{}) // clear deadline for bridging

	// HTTP transport -> reject
	if isHTTPTransport(init) {
		atomic.AddInt64(&stats.connectionsHTTPRejected, 1)
		debugLog("[%s] HTTP transport to %s:%d (rejected)", label, dst, port)
		return
	}

	// -- Extract DC ID --
	dc, isMedia, dcOk := dcFromInit(init)
	initPatched := false

	if !dcOk {
		if info, found := ipToDC[dst]; found {
			dc = info.dc
			isMedia = info.isMedia
			dcOptMu.RLock()
			_, hasDC := dcOpt[dc]
			dcOptMu.RUnlock()
			if hasDC {
				patchDC := dc
				if !isMedia {
					patchDC = -dc
				}
				init = patchInitDC(init, patchDC)
				initPatched = true
				dcOk = true
			}
		}
	}

	dcOptMu.RLock()
	targetIP, hasDC := dcOpt[dc]
	dcOptMu.RUnlock()

	if !dcOk || !hasDC {
		log.Printf("[%s] unknown DC%d for %s:%d -> TCP passthrough", label, dc, dst, port)
		tcpFallback(conn, dst, port, init, label, dc, isMedia)
		return
	}

	key := dcKey{dc, isMedia}
	now := time.Now()
	mediaTag := ""
	if isMedia {
		mediaTag = " media"
	}

	// -- WS blacklist check --
	wsBlacklistMu.RLock()
	blacklisted := wsBlacklist[key]
	wsBlacklistMu.RUnlock()

	if blacklisted {
		debugLog("[%s] DC%d%s WS blacklisted -> TCP %s:%d", label, dc, mediaTag, dst, port)
		ok := tcpFallback(conn, dst, port, init, label, dc, isMedia)
		if ok {
			log.Printf("[%s] DC%d%s TCP fallback closed", label, dc, mediaTag)
		}
		return
	}

	// -- Cooldown check --
	dcFailUntilMu.RLock()
	failUntil := dcFailUntil[key]
	dcFailUntilMu.RUnlock()

	if now.Before(failUntil) {
		remaining := failUntil.Sub(now).Seconds()
		debugLog("[%s] DC%d%s WS cooldown (%.0fs) -> TCP", label, dc, mediaTag, remaining)
		ok := tcpFallback(conn, dst, port, init, label, dc, isMedia)
		if ok {
			log.Printf("[%s] DC%d%s TCP fallback closed", label, dc, mediaTag)
		}
		return
	}

	// -- Try WebSocket --
	domains := wsDomains(dc, isMedia)
	var ws *RawWebSocket
	wsFailedRedirect := false
	allRedirects := true

	ws = wsPool.Get(dc, isMedia, targetIP, domains)
	if ws != nil {
		log.Printf("[%s] DC%d%s (%s:%d) -> pool hit via %s", label, dc, mediaTag, dst, port, targetIP)
	} else {
		for _, domain := range domains {
			url := fmt.Sprintf("wss://%s/apiws", domain)
			log.Printf("[%s] DC%d%s (%s:%d) -> %s via %s", label, dc, mediaTag, dst, port, url, targetIP)

			var connectErr error
			ws, connectErr = wsConnect(targetIP, domain, "/apiws", 10*time.Second)
			if connectErr == nil {
				allRedirects = false
				break
			}

			atomic.AddInt64(&stats.wsErrors, 1)
			if he, ok := connectErr.(*WsHandshakeError); ok {
				if he.IsRedirect() {
					wsFailedRedirect = true
					log.Printf("[%s] DC%d%s got %d from %s -> %s",
						label, dc, mediaTag, he.StatusCode, domain, he.Location)
					continue
				}
				allRedirects = false
				log.Printf("[%s] DC%d%s WS handshake: %s", label, dc, mediaTag, he.StatusLine)
			} else {
				allRedirects = false
				errStr := connectErr.Error()
				if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "x509") {
					log.Printf("[%s] DC%d%s SSL error: %v", label, dc, mediaTag, connectErr)
				} else {
					log.Printf("[%s] DC%d%s WS connect failed: %v", label, dc, mediaTag, connectErr)
				}
			}
		}
	}

	// -- WS failed -> fallback --
	if ws == nil {
		if wsFailedRedirect && allRedirects {
			wsBlacklistMu.Lock()
			wsBlacklist[key] = true
			wsBlacklistMu.Unlock()
			log.Printf("[%s] DC%d%s blacklisted for WS (all 302)", label, dc, mediaTag)
		} else if wsFailedRedirect {
			dcFailUntilMu.Lock()
			dcFailUntil[key] = now.Add(dcFailCooldown)
			dcFailUntilMu.Unlock()
		} else {
			dcFailUntilMu.Lock()
			dcFailUntil[key] = now.Add(dcFailCooldown)
			dcFailUntilMu.Unlock()
			log.Printf("[%s] DC%d%s WS cooldown for %ds", label, dc, mediaTag, int(dcFailCooldown.Seconds()))
		}

		log.Printf("[%s] DC%d%s -> TCP fallback to %s:%d", label, dc, mediaTag, dst, port)
		ok := tcpFallback(conn, dst, port, init, label, dc, isMedia)
		if ok {
			log.Printf("[%s] DC%d%s TCP fallback closed", label, dc, mediaTag)
		}
		return
	}

	// -- WS success --
	dcFailUntilMu.Lock()
	delete(dcFailUntil, key)
	dcFailUntilMu.Unlock()
	atomic.AddInt64(&stats.connectionsWS, 1)

	var splitter *MsgSplitter
	if initPatched {
		splitter, _ = newMsgSplitter(init)
	}

	// Send init packet
	if err := ws.Send(init); err != nil {
		log.Printf("[%s] DC%d%s failed to send init: %v", label, dc, mediaTag, err)
		ws.Close()
		tcpFallback(conn, dst, port, init, label, dc, isMedia)
		return
	}

	bridgeWS(conn, ws, label, dc, dst, port, isMedia, splitter)
}

// ─── Stats logging goroutine ────────────────────────────────────────

func logStatsPeriodically() {
	for {
		time.Sleep(60 * time.Second)
		wsBlacklistMu.RLock()
		var blKeys []string
		for k := range wsBlacklist {
			mediaStr := ""
			if k.isMedia {
				mediaStr = "m"
			}
			blKeys = append(blKeys, fmt.Sprintf("DC%d%s", k.dc, mediaStr))
		}
		wsBlacklistMu.RUnlock()
		sort.Strings(blKeys)
		bl := "none"
		if len(blKeys) > 0 {
			bl = strings.Join(blKeys, ", ")
		}
		log.Printf("stats: %s | ws_bl: %s", stats.summary(), bl)
	}
}

// ─── Main ───────────────────────────────────────────────────────────

type dcIPFlag []string

func (f *dcIPFlag) String() string { return strings.Join(*f, ",") }
func (f *dcIPFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	port := flag.Int("port", defaultPort, fmt.Sprintf("Listen port (default %d)", defaultPort))
	host := flag.String("host", "127.0.0.1", "Listen host (default 127.0.0.1)")
	verboseFlag := flag.Bool("v", false, "Debug logging")

	var dcIPs dcIPFlag
	flag.Var(&dcIPs, "dc-ip", "Target IP for a DC, e.g. -dc-ip 2:149.154.167.220")

	flag.Parse()
	verbose = *verboseFlag

	if len(dcIPs) == 0 {
		dcIPs = dcIPFlag{"2:149.154.167.220", "4:149.154.167.220"}
	}

	// Parse DC IPs
	for _, entry := range dcIPs {
		idx := strings.Index(entry, ":")
		if idx < 0 {
			log.Fatalf("Invalid --dc-ip format %q, expected DC:IP", entry)
		}
		dcStr := entry[:idx]
		ipStr := entry[idx+1:]
		dcNum, err := strconv.Atoi(dcStr)
		if err != nil {
			log.Fatalf("Invalid DC number in %q: %v", entry, err)
		}
		if net.ParseIP(ipStr) == nil {
			log.Fatalf("Invalid IP in %q", entry)
		}
		dcOptMu.Lock()
		dcOpt[dcNum] = ipStr
		dcOptMu.Unlock()
	}

	log.SetFlags(log.Ltime)

	listenAddr := fmt.Sprintf("%s:%d", *host, *port)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}

	log.Println(strings.Repeat("=", 60))
	log.Println("  Telegram WS Bridge Proxy (Go)")
	log.Printf("  Listening on   %s", listenAddr)
	log.Println("  Target DC IPs:")
	dcOptMu.RLock()
	for dc, ip := range dcOpt {
		log.Printf("    DC%d: %s", dc, ip)
	}
	dcOptMu.RUnlock()
	log.Println(strings.Repeat("=", 60))
	log.Printf("  Configure Telegram Desktop:")
	log.Printf("    SOCKS5 proxy -> %s  (no user/pass)", listenAddr)
	log.Println(strings.Repeat("=", 60))

	go logStatsPeriodically()

	dcOptMu.RLock()
	dcOptCopy := make(map[int]string)
	for k, v := range dcOpt {
		dcOptCopy[k] = v
	}
	dcOptMu.RUnlock()
	wsPool.Warmup(dcOptCopy)

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("Shutting down. Final stats: %s", stats.summary())
		ln.Close()
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("Accept error: %v", err)
			return
		}
		go handleClient(conn)
	}
}