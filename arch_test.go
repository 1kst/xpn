package xpfw

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// buildELF cross-compiles a trivial program for goarch and returns the bytes.
// A real toolchain artefact is used rather than a hand-written header so the
// check is verified against what the release actually ships.
func buildELF(t *testing.T, goarch string) []byte {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	out := filepath.Join(dir, "prog")
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot cross-compile for %s: %v (%s)", goarch, err, combined)
	}
	payload, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read built binary: %v", err)
	}
	return payload
}

// TestRefusesBinaryForAnotherArch is the guard that turns a bricked node back
// into a failed update. An arm64 node used to accept the amd64 asset: the sha256
// matched, the ELF magic matched, so it was installed — and then the kernel
// refused to exec it while systemd restart-looped forever, with the only route
// back being SSH.
func TestRefusesBinaryForAnotherArch(t *testing.T) {
	other := "arm64"
	if runtime.GOARCH == "arm64" {
		other = "amd64"
	}

	foreign := buildELF(t, other)
	if err := checkExecutableMatchesHost(foreign); err == nil {
		t.Fatalf("a %s binary was accepted on a %s host", other, runtime.GOARCH)
	} else {
		t.Logf("correctly refused: %v", err)
	}

	native := buildELF(t, runtime.GOARCH)
	if err := checkExecutableMatchesHost(native); err != nil {
		t.Errorf("the binary for this host was refused: %v", err)
	}
}

// TestArchCheckRejectsGarbage covers input that passes the magic check but is not
// a readable ELF file, which must be refused rather than crashing the updater.
func TestArchCheckRejectsGarbage(t *testing.T) {
	truncated := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}
	if err := checkExecutableMatchesHost(truncated); err == nil {
		t.Error("a truncated ELF header was accepted")
	}
}

// TestArchCheckAbstainsOnUnknownArch documents the deliberate gap: a platform
// this table cannot speak for is not blocked by it.
func TestArchCheckAbstainsOnUnknownArch(t *testing.T) {
	if _, known := expectedELFMachine[runtime.GOARCH]; !known {
		t.Skipf("this host (%s) is already unmapped", runtime.GOARCH)
	}
	saved := expectedELFMachine
	expectedELFMachine = map[string]elf.Machine{}
	t.Cleanup(func() { expectedELFMachine = saved })

	if err := checkExecutableMatchesHost([]byte("not an elf at all")); err != nil {
		t.Errorf("an unmapped architecture should abstain, got: %v", err)
	}
}
