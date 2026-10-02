package schemer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

const (
	testDisplayName = "Schemer Test"
	testExe         = `C:\tools\my tool.exe`
	foreignDefault  = "URL:Fremde Anwendung ✓ 日本語"
)

func regRun(args ...string) error {
	out, err := exec.Command("reg", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("reg %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func regKeyExists(key string) (bool, error) {
	err := exec.Command("reg", "query", key).Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return false, nil
	default:
		return false, fmt.Errorf("reg query %s: %w", key, err)
	}
}

func keyExists(t *testing.T, key string) bool {
	t.Helper()
	ok, err := regKeyExists(key)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func regAdd(t *testing.T, key string, args ...string) {
	t.Helper()
	if err := regRun(append(append([]string{"add", key}, args...), "/f")...); err != nil {
		t.Fatal(err)
	}
}

// regExport returns the raw reg export of key, or nil when key is absent.
func regExport(t *testing.T, key string) []byte {
	t.Helper()
	if !keyExists(t, key) {
		return nil
	}
	file := filepath.Join(t.TempDir(), "export.reg")
	if err := regRun("export", key, file, "/y"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// scratchKeys refuses to run when the scheme's key or backup key already exists.
func scratchKeys(t *testing.T, scheme string) (key, backup string) {
	t.Helper()
	if !strings.HasPrefix(scheme, "schemerselftest") {
		t.Fatalf("scratch scheme %q lacks the schemerselftest prefix", scheme)
	}
	key = `HKCU\Software\Classes\` + scheme
	backup = `HKCU\Software\schemer-` + scheme
	for _, k := range []string{key, backup} {
		if keyExists(t, k) {
			t.Fatalf("%s exists before the test, refusing to touch it", k)
		}
	}
	t.Cleanup(func() {
		for _, k := range []string{key, backup} {
			ok, err := regKeyExists(k)
			if err == nil && ok {
				err = regRun("delete", k, "/f")
			}
			if err != nil {
				t.Errorf("cleanup of %s: %v", k, err)
			}
		}
	})
	return key, backup
}

// regText decodes the UTF-16LE text with a BOM that reg export writes.
func regText(raw []byte) (string, bool) {
	if len(raw) < 2 || len(raw)%2 != 0 || raw[0] != 0xFF || raw[1] != 0xFE {
		return "", false
	}
	units := make([]uint16, len(raw)/2-1)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2+2*i:])
	}
	return string(utf16.Decode(units)), true
}

func unescapeReg(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// regValue is one exported value, decoded when it is a REG_SZ and raw export text otherwise.
type regValue struct {
	sz   bool
	data string
}

func parseRegValue(line string) (name string, v regValue, ok bool) {
	var rest string
	switch {
	case strings.HasPrefix(line, "@="):
		rest = line[2:]
	case strings.HasPrefix(line, `"`):
		i := 1
		for ; i < len(line) && line[i] != '"'; i++ {
			if line[i] == '\\' {
				i++
			}
		}
		if i+1 >= len(line) || line[i+1] != '=' {
			return "", regValue{}, false
		}
		name, rest = unescapeReg(line[1:i]), line[i+2:]
	default:
		return "", regValue{}, false
	}
	if len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"' {
		return name, regValue{sz: true, data: unescapeReg(rest[1 : len(rest)-1])}, true
	}
	return name, regValue{data: rest}, true
}

// parseRegExport maps each exported key, relative to root, to its values by name.
func parseRegExport(t *testing.T, root string, raw []byte) map[string]map[string]regValue {
	t.Helper()
	text, ok := regText(raw)
	if !ok {
		t.Fatalf("reg export of %s is not UTF-16LE with a BOM", root)
	}
	lines := strings.Split(text, "\r\n")
	if lines[0] != "Windows Registry Editor Version 5.00" {
		t.Fatalf("reg export of %s starts with %q", root, lines[0])
	}
	fullRoot := "HKEY_CURRENT_USER" + strings.TrimPrefix(root, "HKCU")

	keys := map[string]map[string]regValue{}
	var values map[string]regValue
	var last string
	for _, line := range lines[1:] {
		switch {
		case line == "":
		case strings.HasPrefix(line, "["):
			name := strings.TrimSuffix(line[1:], "]")
			rel := ""
			if len(name) >= len(fullRoot) {
				rel = name[len(fullRoot):]
			}
			if len(name) < len(fullRoot) || !strings.EqualFold(name[:len(fullRoot)], fullRoot) || (rel != "" && rel[0] != '\\') {
				t.Fatalf("reg export of %s holds the foreign section %q", root, line)
			}
			values = map[string]regValue{}
			keys[rel] = values
		case values == nil:
			t.Fatalf("reg export of %s has %q before any section", root, line)
		case strings.HasPrefix(line, "  "):
			v := values[last]
			v.data += strings.TrimSpace(line)
			values[last] = v
		default:
			name, v, ok := parseRegValue(line)
			if !ok {
				t.Fatalf("reg export of %s has the unparsable line %q", root, line)
			}
			values[name] = v
			last = name
		}
	}
	return keys
}

func assertRegistered(t *testing.T, key, backup, name, exe string, hadKey bool) {
	t.Helper()
	cmd := `"` + exe + `" "%1"`
	want := map[string]map[string]regValue{
		``:                    {"": {sz: true, data: "URL:" + name}, "URL Protocol": {sz: true}},
		`\shell`:              {},
		`\shell\open`:         {},
		`\shell\open\command`: {"": {sz: true, data: cmd}},
	}
	raw := regExport(t, key)
	if raw == nil {
		t.Fatalf("%s is absent while registered", key)
	}
	if got := parseRegExport(t, key, raw); !reflect.DeepEqual(got, want) {
		t.Errorf("%s while registered:\n got %+v\nwant %+v", key, got, want)
	}

	raw = regExport(t, backup)
	if raw == nil {
		t.Fatalf("%s is absent while registered", backup)
	}
	b := parseRegExport(t, backup, raw)
	if got := b[""]["command"]; got != (regValue{sz: true, data: cmd}) {
		t.Errorf("%s command = %+v, want REG_SZ %q", backup, got, cmd)
	}
	if _, ok := b[`\prev`]; ok != hadKey {
		t.Errorf("%s holds prev = %v, want %v", backup, ok, hadKey)
	}
}

func assertRestored(t *testing.T, key, backup string, before []byte) {
	t.Helper()
	if after := regExport(t, key); !bytes.Equal(after, before) {
		was, _ := regText(before)
		is, _ := regText(after)
		t.Errorf("%s changed across register and restore\nbefore:\n%s\nafter:\n%s", key, was, is)
	}
	if keyExists(t, backup) {
		t.Errorf("%s survived restore", backup)
	}
}

// registerCommitted leaves scheme registered the way a killed session does.
func registerCommitted(t *testing.T, scheme, backup string) {
	t.Helper()
	if _, err := registerScheme(scheme, testDisplayName, testExe); err != nil {
		t.Fatal(err)
	}
	raw := regExport(t, backup)
	if raw == nil {
		t.Fatalf("%s is absent after register", backup)
	}
	if _, ok := parseRegExport(t, backup, raw)[""]["command"]; !ok {
		t.Fatalf("%s has no command value after register", backup)
	}
}

func seedNoShell(t *testing.T, key string) {
	t.Helper()
	regAdd(t, key, "/ve", "/d", "URL:Foreign")
	regAdd(t, key, "/v", "URL Protocol", "/d", "")
}

func seedForeign(t *testing.T, key string) {
	t.Helper()
	regAdd(t, key, "/ve", "/d", foreignDefault)
	regAdd(t, key, "/v", "URL Protocol", "/d", "x")
	regAdd(t, key, "/v", "EditFlags", "/t", "REG_DWORD", "/d", "2")
	regAdd(t, key+`\DefaultIcon`, "/ve", "/d", `C:\other\app.exe,0`)
	regAdd(t, key+`\shell\open\command`, "/ve", "/t", "REG_EXPAND_SZ", "/d", `"%LOCALAPPDATA%\x.exe" "%1"`)
	regAdd(t, key+`\shell\open\command`, "/v", "DelegateExecute", "/d", "{00000000-0000-0000-0000-000000000000}")
	regAdd(t, key+`\shell\edit\command`, "/ve", "/d", `"C:\other\edit.exe" "%1"`)

	got := parseRegExport(t, key, regExport(t, key))
	if v := got[""][""]; v != (regValue{sz: true, data: foreignDefault}) {
		t.Fatalf("seeded default = %+v, want REG_SZ %q", v, foreignDefault)
	}
	if v := got[`\shell\open\command`][""]; v.sz || !strings.HasPrefix(v.data, "hex(2):") {
		t.Fatalf("seeded command = %+v, want REG_EXPAND_SZ", v)
	}
}

func TestRegisterSchemeRestoresByteExact(t *testing.T) {
	cases := []struct {
		scheme string
		seed   func(*testing.T, string)
	}{
		{"schemerselftestabsent", nil},
		{"schemerselftestforeign", seedForeign},
	}
	for _, c := range cases {
		t.Run(c.scheme, func(t *testing.T) {
			key, backup := scratchKeys(t, c.scheme)
			if c.seed != nil {
				c.seed(t, key)
			}
			before := regExport(t, key)

			restore, err := registerScheme(c.scheme, testDisplayName, testExe)
			if err != nil {
				t.Fatal(err)
			}
			assertRegistered(t, key, backup, testDisplayName, testExe, before != nil)

			if err := restore(); err != nil {
				t.Fatal(err)
			}
			assertRestored(t, key, backup, before)
		})
	}
}

func TestRegisterSchemeRoundTripsQuotesAndPercents(t *testing.T) {
	const scheme = "schemerselftestquotes"
	key, backup := scratchKeys(t, scheme)
	const awkward = `’ ‘ ‚ ‛ ' " $ ; %PATH%`
	name := "Schemer " + awkward + ` \`
	exe := `C:\tools\` + awkward + `\my tool.exe`

	restore, err := registerScheme(scheme, name, exe)
	if err != nil {
		t.Fatal(err)
	}
	assertRegistered(t, key, backup, name, exe, false)

	if err := restore(); err != nil {
		t.Fatal(err)
	}
	assertRestored(t, key, backup, nil)
}

// assertRoundTrip fails unless registering and restoring scheme leaves key byte-identical.
func assertRoundTrip(t *testing.T, scheme, key, backup string) {
	t.Helper()
	before := regExport(t, key)
	restore, err := registerScheme(scheme, testDisplayName, testExe)
	if err != nil {
		t.Fatalf("control: registerScheme: %v", err)
	}
	if err := restore(); err != nil {
		t.Fatalf("control: restore: %v", err)
	}
	assertRestored(t, key, backup, before)
}

// assertRefused fails unless registerScheme rejects scheme and leaves key unchanged and no backup.
func assertRefused(t *testing.T, scheme, key, backup string) {
	t.Helper()
	before := regExport(t, key)

	restore, err := registerScheme(scheme, testDisplayName, testExe)
	after := regExport(t, key)
	leftBackup := keyExists(t, backup)
	if err == nil {
		t.Errorf("registerScheme accepted a key without URL Protocol")
		if rerr := restore(); rerr != nil {
			t.Errorf("restore: %v", rerr)
		}
	}
	if !bytes.Equal(after, before) {
		was, _ := regText(before)
		is, _ := regText(after)
		t.Errorf("%s changed\nbefore:\n%s\nafter:\n%s", key, was, is)
	}
	if leftBackup {
		t.Errorf("%s exists after registerScheme", backup)
	}
}

func TestRegisterSchemeRefusesNonProtocolKey(t *testing.T) {
	ok, okBackup := scratchKeys(t, "schemerselftestprotocolok")
	seedNoShell(t, ok)
	assertRoundTrip(t, "schemerselftestprotocolok", ok, okBackup)

	const scheme = "schemerselftestprogid"
	key, backup := scratchKeys(t, scheme)
	regAdd(t, key, "/ve", "/d", "Some.ProgID.1")
	regAdd(t, key+`\CurVer`, "/ve", "/d", "Some.ProgID.1")
	regAdd(t, key+`\shell\open\command`, "/ve", "/d", `"C:\other\app.exe" "%1"`)
	assertRefused(t, scheme, key, backup)
}

func TestWaitHealsKilledSessionThroughRegistry(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const scheme = "schemerselftestsessioncallback"
	key, backup := scratchKeys(t, scheme)
	seedForeign(t, key)
	original := regExport(t, key)
	registerCommitted(t, scheme, backup)

	f, _ := callbackFlow(t, scheme, nil)
	f.registrar = nil
	f.Timeout = 10 * time.Second
	opened := make(chan string, 1)
	f.opener = func(rawURL string) error { opened <- rawURL; return nil }
	s := start(t, f)
	defer s.Close()

	waitDone := make(chan waitResult, 1)
	go func() {
		code, err := s.Wait(context.Background())
		waitDone <- waitResult{code, err}
	}()
	var state string
	select {
	case rawURL := <-opened:
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		state = u.Query().Get("state")
	case r := <-waitDone:
		t.Fatalf("Wait returned before opening the browser: %q, %v", r.code, r.err)
	case <-time.After(10 * time.Second):
		t.Fatal("Wait never opened the browser")
	}
	// The display name defaults to the scheme.
	assertRegistered(t, key, backup, scheme, exe, true)
	port, err := portFromFile(scheme)
	if err != nil {
		t.Fatalf("port file while waiting: %v", err)
	}

	if err := HandleCallback(scheme + "://auth/prod?code=the-code&state=" + state); err != nil {
		t.Errorf("HandleCallback: %v", err)
	}
	select {
	case r := <-waitDone:
		if r.err != nil || r.code != "the-code" {
			t.Errorf("Wait = %q, %v, want the-code", r.code, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return")
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	assertRestored(t, key, backup, original)
	if acceptsConnections(port) {
		t.Errorf("port %d still accepts connections after Close", port)
	}
	if fileExists(portFilePath(scheme)) {
		t.Error("the port file survived Close")
	}
}
