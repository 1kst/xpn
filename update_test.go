package xpfw

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"time"
)

func TestValidateBinaryURL(t *testing.T) {
	// Plain HTTP is refused: the sha256 companion comes from the same origin, so
	// over an unprotected transport an on-path attacker can swap both files and
	// have the node install and run their binary as root.
	rejected := []string{
		"http://github.com/1kst/xpn/releases/download/v1.1.11/xpn-node-linux-amd64.tar.gz",
		"http://evil.example.com/x.tar.gz",
		"ftp://github.com/x.tar.gz",
		"://broken",
		"https://",
	}
	for _, u := range rejected {
		if err := validateBinaryURL(u); err == nil {
			t.Errorf("validateBinaryURL(%q) = nil, want an error", u)
		}
	}

	// An unapproved host is refused, not merely logged: the URL arrives in an
	// unauthenticated heartbeat response, so accepting an arbitrary https host
	// would let a hijacked response install and run any binary as root.
	if err := validateBinaryURL("https://attacker.example/pkg.tar.gz"); err == nil {
		t.Error("an unapproved host must be rejected, not warned about")
	}

	accepted := []string{
		"https://github.com/1kst/xpn/releases/download/v1.1.11/xpn-node-linux-amd64.tar.gz",
		"https://github.com/1kst/xpn/releases/latest/download/xpn-node-linux-amd64.tar.gz",
		"https://objects.github.com/whatever.tar.gz",
	}
	for _, u := range accepted {
		if err := validateBinaryURL(u); err != nil {
			t.Errorf("validateBinaryURL(%q) = %v, want nil", u, err)
		}
	}

	// A mirror becomes usable only after the operator opts in explicitly.
	t.Setenv(allowedBinaryHostsEnv, "mirror.example.com, cdn.example.net")
	for _, u := range []string{
		"https://mirror.example.com/xpn/xpn-node-linux-amd64.tar.gz",
		"https://CDN.example.net/xpn.tar.gz",
	} {
		if err := validateBinaryURL(u); err != nil {
			t.Errorf("validateBinaryURL(%q) with allowlist = %v, want nil", u, err)
		}
	}
	if err := validateBinaryURL("https://other.example.org/x.tar.gz"); err == nil {
		t.Error("a host outside the allowlist must still be rejected")
	}
}

func TestPanelChannelIsSecure(t *testing.T) {
	// A plain-HTTP control channel cannot authenticate a "replace your own
	// executable" instruction, so sendHeartbeat refuses updates when this is
	// false rather than trusting the response.
	cases := map[string]bool{
		"https://panel.example.com:8888": true,
		"HTTPS://panel.example.com":      true,
		"http://panel.example.com:8888":  false,
		"panel.example.com:8888":         false,
		"":                               false,
	}
	for raw, want := range cases {
		panelConfigMu.Lock()
		panelConfig.PanelURL = raw
		panelConfigMu.Unlock()
		if got := panelChannelIsSecure(); got != want {
			t.Errorf("panelChannelIsSecure() with panel_url %q = %v, want %v", raw, got, want)
		}
	}
}

func TestLooksLikeLinuxExecutable(t *testing.T) {
	elf := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}
	if !looksLikeLinuxExecutable(elf) {
		t.Error("ELF magic should be accepted")
	}

	// A matching sha256 only proves the archive arrived intact. Installing a
	// non-executable payload would leave systemd restart-looping with no working
	// binary, so the magic is checked before the swap.
	for name, payload := range map[string][]byte{
		"empty":      {},
		"too short":  {0x7f, 'E'},
		"shell text": []byte("#!/bin/sh\necho hi\n"),
		"html page":  []byte("<!DOCTYPE html><html>404</html>"),
		"pe binary":  {'M', 'Z', 0x90, 0x00},
	} {
		if looksLikeLinuxExecutable(payload) {
			t.Errorf("%s should not be accepted as an ELF executable", name)
		}
	}
}

// buildTarGz produces a gzipped tar containing the given entries.
func buildTarGz(t *testing.T, entries []struct {
	name     string
	typeflag byte
	body     []byte
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     0o755,
			Size:     int64(len(e.body)),
			ModTime:  time.Unix(1, 0),
		}
		if e.typeflag == tar.TypeDir {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("write tar body: %v", err)
			}
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// extractNodeBinary mirrors the selection loop in updateBinaryAndExit so the
// entry-filtering rules can be exercised without touching the filesystem or
// replacing the running executable.
func extractNodeBinary(t *testing.T, archive []byte) []byte {
	t.Helper()
	gzr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if pathBase(hdr.Name) == "xpn-node" {
			var out bytes.Buffer
			out.ReadFrom(tr)
			return out.Bytes()
		}
	}
}

func pathBase(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimSuffix(name, "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

func TestArchiveEntrySelection(t *testing.T) {
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x90}, 64)...)

	t.Run("picks the regular file", func(t *testing.T) {
		archive := buildTarGz(t, []struct {
			name     string
			typeflag byte
			body     []byte
		}{
			{"README.md", tar.TypeReg, []byte("docs")},
			{"dist/xpn-node", tar.TypeReg, elf},
		})
		got := extractNodeBinary(t, archive)
		if !bytes.Equal(got, elf) {
			t.Errorf("extracted %d bytes, want the %d byte ELF payload", len(got), len(elf))
		}
	})

	t.Run("skips a directory entry with the same name", func(t *testing.T) {
		// Matching on the base name alone would treat this directory as the
		// binary and yield an empty payload.
		archive := buildTarGz(t, []struct {
			name     string
			typeflag byte
			body     []byte
		}{
			{"xpn-node/", tar.TypeDir, nil},
			{"xpn-node/xpn-node", tar.TypeReg, elf},
		})
		got := extractNodeBinary(t, archive)
		if !bytes.Equal(got, elf) {
			t.Errorf("directory entry was not skipped: extracted %d bytes", len(got))
		}
	})

	t.Run("skips a symlink entry", func(t *testing.T) {
		archive := buildTarGz(t, []struct {
			name     string
			typeflag byte
			body     []byte
		}{
			{"xpn-node", tar.TypeSymlink, nil},
		})
		if got := extractNodeBinary(t, archive); len(got) != 0 {
			t.Errorf("symlink entry should yield nothing, got %d bytes", len(got))
		}
	})
}

func TestBinarySizeGuards(t *testing.T) {
	if minBinaryPayloadSize >= maxBinaryPayloadSize {
		t.Fatal("min payload size must be below max")
	}
	if maxBinaryArchiveSize <= 0 || maxBinaryPayloadSize <= 0 {
		t.Fatal("size caps must be positive; an unbounded read lets a hostile URL exhaust node memory")
	}
	// A real xpn-node build is well over 1 MiB, so the floor rejects truncated
	// downloads without rejecting genuine releases.
	if minBinaryPayloadSize > 8<<20 {
		t.Errorf("min payload size %d is high enough to reject real builds", minBinaryPayloadSize)
	}
}
