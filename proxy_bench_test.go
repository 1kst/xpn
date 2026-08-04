package xpfw

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// startEchoBackend serves as the "backend" a proxied connection is relayed to.
func startEchoBackend(t testing.TB) (addr string, stop func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
		<-done
	}
}

// fakeClientHello builds a single-record TLS ClientHello carrying serverName.
func fakeClientHello(serverName string) []byte {
	var ext []byte
	host := []byte(serverName)
	sni := append([]byte{0x00}, byte(len(host)>>8), byte(len(host)))
	sni = append(sni, host...)
	list := append([]byte{byte(len(sni) >> 8), byte(len(sni))}, sni...)
	ext = append(ext, 0x00, 0x00, byte(len(list)>>8), byte(len(list)))
	ext = append(ext, list...)

	body := make([]byte, 34)   // version + random
	body = append(body, 0x00)  // session_id length
	body = append(body, 0, 2, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)       // compression
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// runProxiedConnections drives concurrent connections through handleSNIConn and
// reports the heap in use while they are all live, which is the number that
// determines a node's real memory footprint.
func runProxiedConnections(t testing.TB, concurrency, payloadRounds int) (heapInUseMB float64, totalAllocMB float64) {
	backend, stopBackend := startEchoBackend(t)
	defer stopBackend()

	configMu.Lock()
	prev := globalConfig
	globalConfig.DefaultBackend = backend
	configMu.Unlock()
	defer func() {
		configMu.Lock()
		globalConfig = prev
		configMu.Unlock()
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var serving sync.WaitGroup
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			serving.Add(1)
			go func(c net.Conn) {
				defer serving.Done()
				handleSNIConn(c, ctx)
			}(c)
		}
	}()

	hello := fakeClientHello("bench.example.com")
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}

	var clients sync.WaitGroup
	hold := make(chan struct{})
	ready := make(chan struct{}, concurrency)

	for i := 0; i < concurrency; i++ {
		clients.Add(1)
		go func() {
			defer clients.Done()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				ready <- struct{}{}
				return
			}
			defer c.Close()

			c.SetDeadline(time.Now().Add(20 * time.Second))
			if _, err := c.Write(hello); err != nil {
				ready <- struct{}{}
				return
			}
			// Drain the echoed handshake so the relay is fully established.
			echoed := make([]byte, len(hello))
			io.ReadFull(c, echoed)

			for r := 0; r < payloadRounds; r++ {
				if _, err := c.Write(payload); err != nil {
					break
				}
				back := make([]byte, len(payload))
				if _, err := io.ReadFull(c, back); err != nil {
					break
				}
			}

			ready <- struct{}{}
			<-hold // keep the connection open so the peak is measured live
		}()
	}

	for i := 0; i < concurrency; i++ {
		<-ready
	}

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	heapInUseMB = float64(ms.HeapInuse) / (1024 * 1024)
	totalAllocMB = float64(ms.TotalAlloc) / (1024 * 1024)

	close(hold)
	clients.Wait()
	ln.Close()
	serving.Wait()
	return heapInUseMB, totalAllocMB
}

// TestProxyMemoryFootprint records the live heap for a realistic number of
// concurrent proxied connections. Buffers are pooled, so the footprint should
// track concurrency rather than the total number of connections served.
func TestProxyMemoryFootprint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory footprint test in -short mode")
	}
	const concurrency = 200

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	heap, total := runProxiedConnections(t, concurrency, 4)

	perConnKB := (heap - float64(before.HeapInuse)/(1024*1024)) * 1024 / concurrency
	t.Logf("concurrency=%d  live heap=%.2f MB  total alloc=%.2f MB  ~%.1f KB/conn",
		concurrency, heap, total, perConnKB)

	// The old code allocated a fixed 64 KiB bufio reader plus two 64 KiB copy
	// buffers per connection: 192 KiB that could never be reused. Pooling has to
	// keep the live cost per connection well under that.
	if perConnKB > 150 {
		t.Errorf("per-connection heap %.1f KB is higher than expected; buffer pooling may have regressed", perConnKB)
	}
}

// benchSink defeats escape analysis so the "allocate per connection" arms are
// genuinely heap allocations, as they were in the real code path.
var benchSink any

// BenchmarkRelayBufferChurn contrasts pooled acquisition with the previous
// per-connection allocation, which is what drove GC pressure under load.
func BenchmarkRelayBufferChurn(b *testing.B) {
	b.Run("pooled-32k", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p := copyBufPool.Get().(*[]byte)
			(*p)[0] = byte(i)
			copyBufPool.Put(p)
		}
	})
	b.Run("per-connection-64k", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := make([]byte, 64*1024)
			buf[0] = byte(i)
			benchSink = &buf
		}
	})
}

// BenchmarkHandshakeReader does the same for the ClientHello reader.
func BenchmarkHandshakeReader(b *testing.B) {
	b.Run("pooled-20k", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			br := handshakeReaderPool.Get().(*bufio.Reader)
			handshakeReaderPool.Put(br)
		}
	})
	b.Run("per-connection-64k", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			br := bufio.NewReaderSize(nil, 64*1024)
			benchSink = br
		}
	})
}

// TestFragmentedClientHelloIsParsed covers the RFC 8446 §5.1 case: a handshake
// message split across several records used to be reported as truncated, which
// sent the connection to the default backend instead of its configured one.
func TestFragmentedClientHelloIsParsed(t *testing.T) {
	hello := fakeClientHello("split.example.com")
	handshake := hello[5:] // strip the single record header

	// Chunk sizes below 4 matter: the handshake length prefix is only readable
	// once 4 bytes have arrived, so the reassembly buffer must already be owned
	// by then rather than still aliasing the reader's internal buffer.
	for _, chunk := range []int{1, 2, 3, 4, 5, 7, 16, 64} {
		t.Run(fmt.Sprintf("chunk-%d", chunk), func(t *testing.T) {
			var framed []byte
			for off := 0; off < len(handshake); off += chunk {
				end := min(off+chunk, len(handshake))
				part := handshake[off:end]
				framed = append(framed, 0x16, 0x03, 0x01, byte(len(part)>>8), byte(len(part)))
				framed = append(framed, part...)
			}

			// Backed by a bytes.Reader so every fragment is already available:
			// net.Pipe is synchronous, so the reader would only ever hold what
			// had been peeked, which hides the corruption this checks for.
			br := bufio.NewReaderSize(bytes.NewReader(framed), handshakeBufSize)
			sni, peeked, err := peekClientHelloSNI(br)
			if err != nil {
				t.Fatalf("parse fragmented ClientHello: %v", err)
			}
			if sni != "split.example.com" {
				t.Errorf("sni = %q, want %q", sni, "split.example.com")
			}

			// The consumed records come back as peeked and the caller relays them
			// verbatim, so they must be byte-identical to what the client sent.
			// Reassembling fragments into a slice that still aliases the reader's
			// internal buffer appends over that buffer and silently corrupts the
			// handshake that gets forwarded.
			forwarded := append([]byte(nil), peeked...)
			rest := make([]byte, br.Buffered())
			if _, err := io.ReadFull(br, rest); err != nil {
				t.Fatalf("read remaining bytes: %v", err)
			}
			forwarded = append(forwarded, rest...)
			if !bytes.Equal(forwarded, framed) {
				firstDiff := -1
				for i := 0; i < len(forwarded) && i < len(framed); i++ {
					if forwarded[i] != framed[i] {
						firstDiff = i
						break
					}
				}
				t.Errorf("forwarded bytes differ from what the client sent: got %d bytes, want %d, first differing offset %d",
					len(forwarded), len(framed), firstDiff)
			}
		})
	}
}
