package xpfw

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// TLS ClientHello (JA3) and, for plain-HTTP probes, User-Agent fingerprinting.
// Both read only the bytes already peeked to route the connection; neither
// decrypts anything or keeps payload. JA3 is the useful one here: the traffic
// is almost all TLS, and a JA3 hash groups probes by the client library that
// made them even when each probe re-randomises its bytes, which the raw
// first-packet hash cannot. The User-Agent is best-effort: a probe rarely sends
// a full HTTP request, but when it does the UA often names the scanner.

// isGREASE reports whether a TLS value is a GREASE placeholder (RFC 8701).
// JA3 excludes them so a client that varies its GREASE still hashes alike.
func isGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v)
	return hi == lo && lo&0x0f == 0x0a
}

// clientHelloBody reassembles the ClientHello handshake body from the peeked
// record bytes: concatenate TLS record payloads, then strip the handshake
// header. Returns nil on anything malformed, which is fine — JA3 is only
// meaningful for a real ClientHello.
func clientHelloBody(peeked []byte) []byte {
	var hs []byte
	off := 0
	for off+5 <= len(peeked) {
		if peeked[off] != 0x16 { // not a handshake record
			return nil
		}
		recLen := int(binary.BigEndian.Uint16(peeked[off+3 : off+5]))
		start := off + 5
		end := start + recLen
		if end > len(peeked) {
			end = len(peeked) // truncated last record: take what we have
		}
		hs = append(hs, peeked[start:end]...)
		off = end
		if end != start+recLen {
			break
		}
	}
	// handshake header: type(1)=0x01 ClientHello, length(3)
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil
	}
	body := hs[4:]
	return body
}

// parseJA3Hash returns the md5 hex of the JA3 string for a ClientHello, or ""
// when the bytes are not a parseable ClientHello.
func parseJA3Hash(peeked []byte) string {
	s := ja3String(peeked)
	if s == "" {
		return ""
	}
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ja3String builds the canonical JA3 string:
//
//	TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
//
// with values in decimal, joined by '-', GREASE removed. It walks the
// ClientHello with bounds checks at every step and gives up (returning "") the
// moment anything does not fit, so a crafted or truncated hello cannot panic.
func ja3String(peeked []byte) string {
	b := clientHelloBody(peeked)
	// version(2) + random(32) + session_id_len(1)
	if len(b) < 35 {
		return ""
	}
	version := binary.BigEndian.Uint16(b[0:2])
	p := 34
	sidLen := int(b[p])
	p++
	if p+sidLen > len(b) {
		return ""
	}
	p += sidLen

	// cipher suites
	if p+2 > len(b) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if p+csLen > len(b) || csLen%2 != 0 {
		return ""
	}
	var ciphers []string
	for i := 0; i < csLen; i += 2 {
		c := binary.BigEndian.Uint16(b[p+i : p+i+2])
		if !isGREASE(c) {
			ciphers = append(ciphers, strconv.Itoa(int(c)))
		}
	}
	p += csLen

	// compression methods
	if p+1 > len(b) {
		return ""
	}
	compLen := int(b[p])
	p++
	if p+compLen > len(b) {
		return ""
	}
	p += compLen

	// extensions are optional in the wire format; JA3 then uses empty fields.
	var exts, curves, formats []string
	if p+2 <= len(b) {
		extLen := int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2
		end := p + extLen
		if end > len(b) {
			end = len(b)
		}
		for p+4 <= end {
			etype := binary.BigEndian.Uint16(b[p : p+2])
			elen := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
			p += 4
			if p+elen > end {
				break
			}
			data := b[p : p+elen]
			p += elen
			if !isGREASE(etype) {
				exts = append(exts, strconv.Itoa(int(etype)))
			}
			switch etype {
			case 0x000a: // supported_groups (elliptic curves)
				if len(data) >= 2 {
					n := int(binary.BigEndian.Uint16(data[0:2]))
					d := data[2:]
					for i := 0; i+2 <= n && i+2 <= len(d); i += 2 {
						v := binary.BigEndian.Uint16(d[i : i+2])
						if !isGREASE(v) {
							curves = append(curves, strconv.Itoa(int(v)))
						}
					}
				}
			case 0x000b: // ec_point_formats
				if len(data) >= 1 {
					n := int(data[0])
					d := data[1:]
					for i := 0; i < n && i < len(d); i++ {
						formats = append(formats, strconv.Itoa(int(d[i])))
					}
				}
			}
		}
	}

	return strings.Join([]string{
		strconv.Itoa(int(version)),
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(curves, "-"),
		strings.Join(formats, "-"),
	}, ",")
}

// httpMethods are the request-line verbs that mark a plain-HTTP probe.
var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH "}

// extractUA pulls the User-Agent out of a plain-HTTP first packet, or "" when
// the bytes are not HTTP or carry no UA. The value is bounded and stripped of
// control characters; nothing else from the request is kept.
func extractUA(peeked []byte) string {
	if len(peeked) < 4 {
		return ""
	}
	head := peeked
	if len(head) > 4096 {
		head = head[:4096]
	}
	s := string(head)
	looksHTTP := false
	for _, m := range httpMethods {
		if strings.HasPrefix(s, m) {
			looksHTTP = true
			break
		}
	}
	if !looksHTTP {
		return ""
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) < len("user-agent:") {
			continue
		}
		if strings.EqualFold(line[:len("user-agent:")], "user-agent:") {
			return sanitizeUA(strings.TrimSpace(line[len("user-agent:"):]))
		}
	}
	return ""
}

func sanitizeUA(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 200 {
			break
		}
	}
	return b.String()
}
