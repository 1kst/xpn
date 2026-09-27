package xpfw

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	neturl "net/url"
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

	// The pin is the repository, not the host. GitHub lets anyone publish a
	// release, so a host-only check meant every account on it could supply the
	// binary this node installs and runs as root.
	for _, u := range []string{
		"https://github.com/attacker/evil/releases/download/v1/xpn-node-linux-amd64.tar.gz",
		"https://objects.github.com/whatever.tar.gz",
		"https://raw.githubusercontent.com/1kst/xpn/main/x.tar.gz",
		// Neighbouring paths that a plain string prefix would have accepted.
		"https://github.com/1kst/xpn-evil/releases/download/v1/x.tar.gz",
		"https://github.com/1kst/xpnrelease/x.tar.gz",
		// Traversal back out of the pinned path.
		"https://github.com/1kst/xpn/releases/../../attacker/evil/releases/download/v1/x.tar.gz",
		// A look-alike host, and an off-port impostor.
		"https://github.com.attacker.example/1kst/xpn/releases/download/v1/x.tar.gz",
		"https://github.com:8443/1kst/xpn/releases/download/v1/x.tar.gz",
		// Credentials that make the real host look like a path component.
		"https://github.com@attacker.example/1kst/xpn/releases/download/v1/x.tar.gz",
		// Plain HTTP, whatever the path.
		"http://github.com/1kst/xpn/releases/download/v1/x.tar.gz",
		// ".." spelled with escapes, which path.Clean does not fold.
		"https://github.com/1kst/xpn/releases/%2e%2e/%2e%2e/%2e%2e/evil/repo/raw/main/xpn-node-linux-amd64.tar.gz",
		// A release older than the floor: it would accept anything on the next beat.
		"https://github.com/1kst/xpn/releases/download/v1.1.11/xpn-node-linux-amd64.tar.gz",
		"https://github.com/1kst/xpn/releases/download/v1.1.18/xpn-node-linux-amd64.tar.gz",
		// Under the pinned path but not a release asset of this project.
		"https://github.com/1kst/xpn/releases/download/v1.2.0/other.tar.gz",
		"https://github.com/1kst/xpn/releases/tag/v1.2.0",
	} {
		if err := validateBinaryURL(u); err == nil {
			t.Errorf("validateBinaryURL(%q) = nil, want a refusal", u)
		}
	}

	for _, u := range []string{
		"https://github.com/1kst/xpn/releases/download/v1.1.19/xpn-node-linux-amd64.tar.gz",
		"https://github.com/1kst/xpn/releases/download/v1.2.0/xpn-node-linux-arm64.tar.gz",
		"https://github.com/1kst/xpn/releases/latest/download/xpn-node-linux-arm64.tar.gz",
		// The companion checksum, which is derived by appending to the archive URL.
		"https://github.com/1kst/xpn/releases/download/v1.1.19/xpn-node-linux-amd64.tar.gz.sha256",
		// Explicit default port, and mixed case in the scheme and host.
		"https://GitHub.com:443/1kst/xpn/releases/download/v1.1.20/xpn-node-linux-amd64.tar.gz",
	} {
		if err := validateBinaryURL(u); err != nil {
			t.Errorf("validateBinaryURL(%q) = %v, want nil", u, err)
		}
	}

	// A mirror becomes usable only when the operator pins one, and what they pin
	// is a whole prefix: a host-only escape hatch would have re-opened the hole
	// this closes.
	t.Setenv(allowedBinaryPrefixEnv, "https://mirror.example.com/xpn/builds/")
	if err := validateBinaryURL("https://mirror.example.com/xpn/builds/v1/xpn-node-linux-amd64.tar.gz"); err != nil {
		t.Errorf("a pinned mirror path was refused: %v", err)
	}
	for _, u := range []string{
		// Right host, outside the pinned path.
		"https://mirror.example.com/elsewhere/x.tar.gz",
		// Right path, different host.
		"https://other.example.org/xpn/builds/x.tar.gz",
	} {
		if err := validateBinaryURL(u); err == nil {
			t.Errorf("validateBinaryURL(%q) = nil, want a refusal even with a mirror pinned", u)
		}
	}
	// The project's own origin keeps working alongside a pinned mirror.
	if err := validateBinaryURL("https://github.com/1kst/xpn/releases/download/v1.1.19/xpn-node-linux-amd64.tar.gz"); err != nil {
		t.Errorf("the built-in origin stopped working once a mirror was pinned: %v", err)
	}
}

// TestBinaryRedirectsAreConstrained covers the hop between the pinned URL and the
// bytes. A GitHub release download redirects to its asset host, and redirects
// used to be followed with no check at all -- so the origin test applied to the
// first URL only, and an open redirect under the pinned path would have led the
// download anywhere.
func TestBinaryRedirectsAreConstrained(t *testing.T) {
	client := binaryDownloadClient(5 * time.Second)
	if client.CheckRedirect == nil {
		t.Fatal("the download client follows redirects without checking them")
	}

	req := func(raw string) *http.Request {
		u, err := neturl.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return &http.Request{URL: u}
	}

	// Where GitHub actually sends a release download today, and where it used to.
	for _, ok := range []string{
		"https://release-assets.githubusercontent.com/github-production-release-asset/1/2",
		"https://objects.githubusercontent.com/x",
		"https://github.com/1kst/xpn/releases/download/v1/x.tar.gz",
	} {
		if err := client.CheckRedirect(req(ok), nil); err != nil {
			t.Errorf("redirect to %q was refused: %v", ok, err)
		}
	}

	for _, bad := range []string{
		"https://attacker.example/payload.tar.gz",
		"http://objects.githubusercontent.com/x",
		"https://githubusercontent.com.attacker.example/x",
		// Hosts under githubusercontent.com that serve what any account uploads.
		"https://raw.githubusercontent.com/attacker/repo/main/x.tar.gz",
		"https://gist.githubusercontent.com/attacker/1/raw/x.tar.gz",
	} {
		if err := client.CheckRedirect(req(bad), nil); err == nil {
			t.Errorf("redirect to %q was allowed", bad)
		}
	}

	// The chain is bounded, so a redirect loop cannot stall an update forever.
	via := make([]*http.Request, maxBinaryRedirects)
	if err := client.CheckRedirect(req("https://objects.githubusercontent.com/x"), via); err == nil {
		t.Error("an over-long redirect chain was allowed")
	}
}

// TestConstructedURLsSatisfyOurOwnPin keeps the builders and the validator from
// drifting apart: a node that built a URL it would then refuse could not update
// itself at all.
func TestConstructedURLsSatisfyOurOwnPin(t *testing.T) {
	for _, u := range []string{DefaultBinaryURL(), binaryURLForVersion(NodeVersion), binaryURLForVersion("")} {
		if err := validateBinaryURL(u); err != nil {
			t.Errorf("this node builds a URL it would refuse: %s -> %v", u, err)
		}
		if err := validateBinaryURL(u + ".sha256"); err != nil {
			t.Errorf("the checksum URL derived from %s would be refused: %v", u, err)
		}
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

// TestReleaseVersionOrder: the floor is compared numerically, so v1.1.100 is
// newer than v1.1.19 and not older.
func TestReleaseVersionOrder(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.1.19", "v1.1.19", 0},
		{"v1.1.18", "v1.1.19", -1},
		{"v1.1.100", "v1.1.19", 1},
		{"v2.0.0", "v1.9.9", 1},
		{"garbage", "v1.1.19", -1},
	}
	for _, c := range cases {
		if got := compareReleaseVersions(c.a, c.b); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestUpdateForRunningVersionIsIgnored: reinstalling the version already running
// restarts the node, cutting every connection, for nothing.
func TestUpdateForRunningVersionIsIgnored(t *testing.T) {
	startBinaryUpdate("", NodeVersion)
	if binaryUpdateRunning.Load() {
		t.Error("an update to the running version was started")
	}
}
