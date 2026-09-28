package xpfw

import (
	"encoding/binary"
	"strings"
	"testing"
)

// clientHelloWith builds a TLS record wrapping a ClientHello with the given
// ciphers, extensions and (optional) supported-groups list, enough to exercise
// the JA3 parser.
func clientHelloWith(ciphers []uint16, exts []uint16, curves []uint16) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)          // client_version TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id len 0
	cs := make([]byte, 2+2*len(ciphers))     // cipher suites
	binary.BigEndian.PutUint16(cs, uint16(2*len(ciphers)))
	for i, c := range ciphers {
		binary.BigEndian.PutUint16(cs[2+2*i:], c)
	}
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // compression: len 1, null

	var extBytes []byte
	for _, e := range exts {
		var data []byte
		if e == 0x000a { // supported_groups
			data = make([]byte, 2+2*len(curves))
			binary.BigEndian.PutUint16(data, uint16(2*len(curves)))
			for i, c := range curves {
				binary.BigEndian.PutUint16(data[2+2*i:], c)
			}
		}
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr, e)
		binary.BigEndian.PutUint16(hdr[2:], uint16(len(data)))
		extBytes = append(extBytes, hdr...)
		extBytes = append(extBytes, data...)
	}
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(extBytes)))
	body = append(body, extLen...)
	body = append(body, extBytes...)

	hs := make([]byte, 4)
	hs[0] = 0x01 // ClientHello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func TestJA3StableAndGREASEStripped(t *testing.T) {
	plain := clientHelloWith([]uint16{0x1301, 0x1302}, []uint16{0x000a, 0x0000}, []uint16{0x001d, 0x0017})
	withGrease := clientHelloWith([]uint16{0x0a0a, 0x1301, 0x1302}, []uint16{0x1a1a, 0x000a, 0x0000}, []uint16{0x0a0a, 0x001d, 0x0017})

	h1 := parseJA3Hash(plain)
	h2 := parseJA3Hash(withGrease)
	if h1 == "" {
		t.Fatal("no JA3 for a valid ClientHello")
	}
	if h1 != h2 {
		t.Errorf("GREASE changed the JA3 hash: %s vs %s", h1, h2)
	}
	// The canonical string has the five comma-separated fields.
	s := ja3String(plain)
	if got := strings.Count(s, ","); got != 4 {
		t.Errorf("JA3 string %q has %d commas, want 4", s, got)
	}
	if !strings.HasPrefix(s, "771,4865-4866,") { // 771=0x303, 4865=0x1301, 4866=0x1302
		t.Errorf("JA3 string = %q, want version+ciphers prefix", s)
	}
}

func TestJA3RejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00}, // record says handshake but body truncated
		[]byte("GET / HTTP/1.1\r\n\r\n"),           // not TLS at all
		{0x16, 0x03, 0x01, 0xff, 0xff},             // length past the buffer
	} {
		if h := parseJA3Hash(b); h != "" {
			t.Errorf("garbage produced a JA3: %q", h)
		}
	}
}

func TestExtractUA(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\nAccept: */*\r\n\r\n"
	if got := extractUA([]byte(req)); got != "Mozilla/5.0 zgrab/0.x" {
		t.Errorf("UA = %q", got)
	}
	// Case-insensitive header name.
	if got := extractUA([]byte("POST /a HTTP/1.0\r\nuser-agent: masscan\r\n\r\n")); got != "masscan" {
		t.Errorf("lowercase UA = %q", got)
	}
	// Not HTTP, or no UA present.
	if got := extractUA([]byte("\x16\x03\x01\x00\x10random-tls-ish")); got != "" {
		t.Errorf("non-HTTP produced a UA: %q", got)
	}
	if got := extractUA([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); got != "" {
		t.Errorf("missing UA produced: %q", got)
	}
	// Control characters are stripped and the value is bounded.
	long := "GET / HTTP/1.1\r\nUser-Agent: " + strings.Repeat("A", 500) + "\r\n\r\n"
	if got := extractUA([]byte(long)); len(got) > 200 {
		t.Errorf("UA not bounded: %d chars", len(got))
	}
}
