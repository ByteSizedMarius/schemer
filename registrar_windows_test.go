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
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"
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

// regKeyExists reports whether the HKCU\ path key exists, a link without a target included.
func regKeyExists(key string) (bool, error) {
	var err error
	for _, options := range []uint32{regOptionOpenLink, 0} {
		k, openErr := regOpen(hkcuRel(key), options, readControl)
		if openErr == nil {
			syscall.RegCloseKey(k)
			return true, nil
		}
		if !errors.Is(openErr, syscall.ERROR_FILE_NOT_FOUND) {
			err = openErr
		}
	}
	if err != nil {
		return false, fmt.Errorf("opening %s: %w", key, err)
	}
	return false, nil
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

// regExport returns the raw reg export of key, or nil when key does not open by name.
func regExport(t *testing.T, key string) []byte {
	t.Helper()
	k, err := regOpen(hkcuRel(key), 0, readControl)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		t.Fatalf("opening %s: %v", key, err)
	}
	syscall.RegCloseKey(k)
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

// scratchKeys refuses to run when the scheme's key, backup key or old-location backup key already exists.
func scratchKeys(t *testing.T, scheme string) (key, backup string) {
	t.Helper()
	if !strings.HasPrefix(scheme, "schemerselftest") {
		t.Fatalf("scratch scheme %q lacks the schemerselftest prefix", scheme)
	}
	key = `HKCU\Software\Classes\` + scheme
	backup = `HKCU\Software\Classes\Local Settings\Software\schemer-` + scheme
	old := `HKCU\Software\schemer-` + scheme
	for _, k := range []string{key, backup, old} {
		if keyExists(t, k) {
			t.Fatalf("%s exists before the test, refusing to touch it", k)
		}
	}
	t.Cleanup(func() {
		for _, k := range []string{key, backup, old} {
			ok, err := regKeyExists(k)
			link := false
			if err == nil && ok {
				link, err = regIsLink(hkcuRel(k))
			}
			switch {
			case err != nil:
			case link:
				err = regDeleteLink(hkcuRel(k))
			case ok:
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

func seedPhase(t *testing.T, backup string) {
	t.Helper()
	regAdd(t, backup, "/v", "phase", "/d", "x")
}

// fakeProfileDir returns a profile directory that a folder lookup without the token accepts.
func fakeProfileDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "AppData", "Local"), 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

var (
	procRegGetKeySecurity = advapi32.NewProc("RegGetKeySecurity")
	procRegSetKeySecurity = advapi32.NewProc("RegSetKeySecurity")
	procSDToSDDL          = advapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	procSDDLToSD          = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procLocalFree         = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")

	ntdll           = syscall.NewLazyDLL("ntdll.dll")
	procNtCreateKey = ntdll.NewProc("NtCreateKey")
	procNtOpenKey   = ntdll.NewProc("NtOpenKey")
	procNtQueryKey  = ntdll.NewProc("NtQueryKey")
	procNtDeleteKey = ntdll.NewProc("NtDeleteKey")
)

const (
	regOptionCreateLink     = 0x2
	regTypeLink             = 6
	readControl             = 0x20000
	daclSecurityInformation = 4
	ownerGroupDACL          = 1 | 2 | daclSecurityInformation
)

var protocolPaths = []string{"", `\DefaultIcon`, `\shell`, `\shell\open`, `\shell\open\command`}

func seedProtocol(t *testing.T, key string) {
	t.Helper()
	regAdd(t, key, "/ve", "/d", "URL:x")
	regAdd(t, key, "/v", "URL Protocol", "/d", "")
	regAdd(t, key+`\DefaultIcon`, "/ve", "/d", `C:\foreign\x.exe,0`)
	regAdd(t, key+`\shell\open\command`, "/ve", "/d", `"C:\foreign\x.exe" "%1"`)
}

func userSID(t *testing.T) string {
	t.Helper()
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := u.User.Sid.String()
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func hkcuRel(key string) string {
	return strings.TrimPrefix(key, `HKCU\`)
}

func regOpen(path string, options, access uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var k syscall.Handle
	if err := syscall.RegOpenKeyEx(hkcu, p, options, access, &k); err != nil {
		return 0, err
	}
	return k, nil
}

// keySDDL reads the owner, group and DACL of the key at path, a link itself rather than its target.
func keySDDL(path string) (string, error) {
	k, err := regOpen(path, regOptionOpenLink, readControl)
	if err != nil {
		return "", err
	}
	defer syscall.RegCloseKey(k)
	return handleSDDL(k)
}

func handleSDDL(k syscall.Handle) (string, error) {
	var n uint32
	r, _, _ := procRegGetKeySecurity.Call(uintptr(k), ownerGroupDACL, 0, uintptr(unsafe.Pointer(&n)))
	if syscall.Errno(r) != syscall.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("RegGetKeySecurity: %w", syscall.Errno(r))
	}
	sd := make([]byte, n)
	if r, _, _ := procRegGetKeySecurity.Call(uintptr(k), ownerGroupDACL, uintptr(unsafe.Pointer(&sd[0])), uintptr(unsafe.Pointer(&n))); r != 0 {
		return "", fmt.Errorf("RegGetKeySecurity: %w", syscall.Errno(r))
	}
	var s *uint16
	if ok, _, err := procSDToSDDL.Call(uintptr(unsafe.Pointer(&sd[0])), 1, ownerGroupDACL, uintptr(unsafe.Pointer(&s)), 0); ok == 0 {
		return "", fmt.Errorf("converting the descriptor to SDDL: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(s)))
	n = 0
	for q := unsafe.Pointer(s); *(*uint16)(q) != 0; q = unsafe.Add(q, 2) {
		n++
	}
	return syscall.UTF16ToString(unsafe.Slice(s, n)), nil
}

// setKeyDACL replaces the DACL of the key at path, a link itself rather than its target.
func setKeyDACL(path, dacl string) error {
	k, err := regOpen(path, regOptionOpenLink, readControl|writeDAC)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)
	return setHandleDACL(k, dacl)
}

func setHandleDACL(k syscall.Handle, dacl string) error {
	p, err := syscall.UTF16PtrFromString(dacl)
	if err != nil {
		return err
	}
	var sd uintptr
	if ok, _, err := procSDDLToSD.Call(uintptr(unsafe.Pointer(p)), 1, uintptr(unsafe.Pointer(&sd)), 0); ok == 0 {
		return fmt.Errorf("parsing %s: %w", dacl, err)
	}
	defer procLocalFree.Call(sd)
	if r, _, _ := procRegSetKeySecurity.Call(uintptr(k), daclSecurityInformation, sd); r != 0 {
		return fmt.Errorf("RegSetKeySecurity: %w", syscall.Errno(r))
	}
	return nil
}

func daclOf(sddl string) string {
	if i := strings.Index(sddl, "D:"); i >= 0 {
		return sddl[i:]
	}
	return ""
}

// withACE puts ace in front of the first ACE of dacl.
func withACE(dacl, ace string) string {
	i := strings.IndexByte(dacl, '(')
	if i < 0 {
		i = len(dacl)
	}
	return dacl[:i] + ace + dacl[i:]
}

func dropAutoInherited(sddl string) string {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return sddl
	}
	i += 2
	j := strings.IndexByte(sddl[i:], '(')
	if j < 0 {
		j = len(sddl) - i
	}
	return sddl[:i] + strings.Replace(sddl[i:i+j], "AI", "", 1) + sddl[i+j:]
}

// treeSDDLs maps each suffix in paths to the security descriptor of key with that suffix.
func treeSDDLs(key string, paths []string) map[string]string {
	got := map[string]string{}
	for _, p := range paths {
		s, err := keySDDL(hkcuRel(key) + p)
		if err != nil {
			s = "unreadable: " + err.Error()
		}
		got[p] = s
	}
	return got
}

func compareSDDLs(t *testing.T, what string, paths []string, want, got map[string]string, mayDropAI bool) {
	t.Helper()
	for _, p := range paths {
		if got[p] == want[p] || mayDropAI && got[p] == dropAutoInherited(want[p]) {
			continue
		}
		t.Errorf("%s: the security descriptor of %q\n got %s\nwant %s", what, p, got[p], want[p])
	}
}

// unlockTree sets dacl on every key top-down and deletes every link it meets without descending into it.
func unlockTree(path, dacl string) error {
	err := setKeyDACL(path, dacl)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	link, err := regIsLink(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if link {
		return regDeleteLink(path)
	}
	k, err := regOpen(path, regOptionOpenLink, syscall.KEY_READ)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer syscall.RegCloseKey(k)
	names, err := subkeys(k)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, n := range names {
		if err := unlockTree(path+`\`+syscall.UTF16ToString(n), dacl); err != nil {
			return err
		}
	}
	return nil
}

// unlockTreesOnCleanup strips the ACLs of keys and deletes their links before scratchKeys deletes them.
func unlockTreesOnCleanup(t *testing.T, keys ...string) {
	t.Helper()
	dacl := "D:(A;OICI;KA;;;" + userSID(t) + ")"
	t.Cleanup(func() {
		for _, k := range keys {
			if err := unlockTree(hkcuRel(k), dacl); err != nil {
				t.Errorf("cleanup of %s: %v", k, err)
			}
		}
	})
}

// createRegLink creates key as a registry link to target, or as a link without SymbolicLinkValue when target is empty, and returns the SymbolicLinkValue it wrote.
func createRegLink(t *testing.T, key, target string) []byte {
	t.Helper()
	p, err := syscall.UTF16PtrFromString(hkcuRel(key))
	if err != nil {
		t.Fatal(err)
	}
	var k syscall.Handle
	var disposition uint32
	r, _, _ := procRegCreateKeyEx.Call(uintptr(hkcu), uintptr(unsafe.Pointer(p)), 0, 0, regOptionCreateLink,
		syscall.KEY_ALL_ACCESS, 0, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&disposition)))
	if r != 0 {
		t.Fatalf("creating %s with REG_OPTION_CREATE_LINK: %v", key, syscall.Errno(r))
	}
	defer syscall.RegCloseKey(k)
	if disposition != 1 {
		t.Fatalf("%s existed before the link was created", key)
	}
	if target == "" {
		return nil
	}
	t.Cleanup(func() {
		if !keyExists(t, target) {
			t.Errorf("the link target %s is gone", target)
		}
	})

	units, err := syscall.UTF16FromString(`\REGISTRY\USER\` + userSID(t) + `\` + hkcuRel(target))
	if err != nil {
		t.Fatal(err)
	}
	var value []byte
	for _, u := range units[:len(units)-1] {
		value = append(value, byte(u), byte(u>>8))
	}
	name, err := syscall.UTF16PtrFromString("SymbolicLinkValue")
	if err != nil {
		t.Fatal(err)
	}
	r, _, _ = procRegSetValueEx.Call(uintptr(k), uintptr(unsafe.Pointer(name)), 0, regTypeLink,
		uintptr(unsafe.Pointer(&value[0])), uintptr(len(value)))
	if r != 0 {
		procNtDeleteKey.Call(uintptr(k))
		t.Fatalf("writing SymbolicLinkValue on %s: %v", key, syscall.Errno(r))
	}
	return value
}

// assertRoundTripKeepsSDDL fails unless registering and restoring scheme brings back key's values and every path's security descriptor, SE_DACL_AUTO_INHERITED aside.
func assertRoundTripKeepsSDDL(t *testing.T, what, scheme, key, backup string, paths []string) {
	t.Helper()
	original := regExport(t, key)
	before := treeSDDLs(key, paths)
	restore, err := registerScheme(scheme, testDisplayName, testExe)
	if err != nil {
		t.Fatalf("%sregisterScheme: %v", what, err)
	}
	if err := restore(); err != nil {
		t.Fatalf("%srestore: %v", what, err)
	}
	assertRestored(t, key, backup, original)
	compareSDDLs(t, what+"after the round trip", paths, before, treeSDDLs(key, paths), true)
	if t.Failed() {
		t.FailNow()
	}
}

const (
	objCaseInsensitive = 0x40
	objOpenLink        = 0x100
)

type unicodeString struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

type objectAttributes struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               *unicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// ntObjectAttributes names the subkey of parent with the counted name, which may hold NUL.
func ntObjectAttributes(parent syscall.Handle, name []uint16) *objectAttributes {
	us := &unicodeString{Length: uint16(2 * len(name)), MaximumLength: uint16(2 * len(name)), Buffer: &name[0]}
	oa := &objectAttributes{RootDirectory: parent, ObjectName: us, Attributes: objCaseInsensitive}
	oa.Length = uint32(unsafe.Sizeof(*oa))
	return oa
}

// ntCreateKey creates or opens the subkey of parent with the counted name and returns its disposition.
func ntCreateKey(parent syscall.Handle, name []uint16, access uint32) (syscall.Handle, uint32, error) {
	oa := ntObjectAttributes(parent, name)
	var h syscall.Handle
	var disposition uint32
	st, _, _ := procNtCreateKey.Call(uintptr(unsafe.Pointer(&h)), uintptr(access), uintptr(unsafe.Pointer(oa)), 0, 0, 0, uintptr(unsafe.Pointer(&disposition)))
	runtime.KeepAlive(oa)
	if st != 0 {
		return 0, 0, fmt.Errorf("NtCreateKey: NTSTATUS 0x%08X", st)
	}
	return h, disposition, nil
}

func ntOpenKey(parent syscall.Handle, name []uint16, access uint32) (syscall.Handle, error) {
	oa := ntObjectAttributes(parent, name)
	oa.Attributes |= objOpenLink
	var h syscall.Handle
	st, _, _ := procNtOpenKey.Call(uintptr(unsafe.Pointer(&h)), uintptr(access), uintptr(unsafe.Pointer(oa)))
	runtime.KeepAlive(oa)
	if st != 0 {
		return 0, fmt.Errorf("NtOpenKey: NTSTATUS 0x%08X", st)
	}
	return h, nil
}

// RegDeleteTreeW cannot remove a key whose name holds a NUL.
func deleteNulKeys(path string) error {
	k, err := regOpen(path, regOptionOpenLink, syscall.KEY_READ)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer syscall.RegCloseKey(k)
	names, err := subkeys(k)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, n := range names {
		n = n[:len(n)-1]
		if !slices.Contains(n, 0) {
			if err := deleteNulKeys(path + `\` + string(utf16.Decode(n))); err != nil {
				return err
			}
			continue
		}
		h, err := ntOpenKey(k, n, deleteAccess)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		st, _, _ := procNtDeleteKey.Call(uintptr(h))
		syscall.RegCloseKey(h)
		if st != 0 {
			return fmt.Errorf("NtDeleteKey under %s: NTSTATUS 0x%08X", path, st)
		}
	}
	return nil
}

func keyValues(k syscall.Handle) ([]string, error) {
	var maxName, maxData uint32
	if err := syscall.RegQueryInfoKey(k, nil, nil, nil, nil, nil, nil, nil, &maxName, &maxData, nil, nil); err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var values []string
	for i := uint32(0); ; i++ {
		name := make([]uint16, maxName+1)
		data := make([]byte, maxData+1)
		nameLen, dataLen := uint32(len(name)), uint32(len(data))
		var typ uint32
		r, _, _ := procRegEnumValue.Call(uintptr(k), uintptr(i), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&nameLen)), 0,
			uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&dataLen)))
		if syscall.Errno(r) == errorNoMoreItems {
			slices.Sort(values)
			return values, nil
		}
		if r != 0 {
			return nil, fmt.Errorf("RegEnumValueW: %w", syscall.Errno(r))
		}
		values = append(values, fmt.Sprintf("%q type %d %x", string(utf16.Decode(name[:nameLen])), typ, data[:dataLen]))
	}
}

// openChild opens the subkey of k with the counted name, a link itself rather than its target.
func openChild(k syscall.Handle, name []uint16) (syscall.Handle, error) {
	if slices.Contains(name, 0) {
		return ntOpenKey(k, name, syscall.KEY_READ)
	}
	p := append(slices.Clone(name), 0)
	var c syscall.Handle
	if err := syscall.RegOpenKeyEx(k, &p[0], regOptionOpenLink, syscall.KEY_READ, &c); err != nil {
		return 0, err
	}
	return c, nil
}

func snapshotKey(b *strings.Builder, k syscall.Handle, path string) error {
	sddl, err := handleSDDL(k)
	if err != nil {
		return fmt.Errorf("%q: %w", path, err)
	}
	fmt.Fprintf(b, "[%q] %s\n", path, sddl)
	values, err := keyValues(k)
	if err != nil {
		return fmt.Errorf("%q: %w", path, err)
	}
	for _, v := range values {
		fmt.Fprintf(b, "  %s\n", v)
	}
	raw, err := subkeys(k)
	if err != nil {
		return fmt.Errorf("%q: %w", path, err)
	}
	slices.SortFunc(raw, slices.Compare)
	for _, n := range raw {
		n = n[:len(n)-1]
		child := path + `\` + string(utf16.Decode(n))
		c, err := openChild(k, n)
		if err != nil {
			return fmt.Errorf("%q: %w", child, err)
		}
		err = snapshotKey(b, c, child)
		syscall.RegCloseKey(c)
		if err != nil {
			return err
		}
	}
	return nil
}

// regSnapshot renders every key of the tree at the HKCU\ path key with its security descriptor and values, never following a link.
func regSnapshot(t *testing.T, key string) string {
	t.Helper()
	k, err := regOpen(hkcuRel(key), regOptionOpenLink, syscall.KEY_READ)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return "absent"
	}
	if err != nil {
		t.Fatalf("opening %s: %v", key, err)
	}
	defer syscall.RegCloseKey(k)
	var b strings.Builder
	if err := snapshotKey(&b, k, ""); err != nil {
		t.Fatalf("reading %s: %v", key, err)
	}
	return b.String()
}

// seedCommitted leaves scheme's seeded tree registered the way a killed session does.
func seedCommitted(t *testing.T, scheme string, seed func(*testing.T, string)) (key, backup string) {
	t.Helper()
	key, backup = scratchKeys(t, scheme)
	unlockTreesOnCleanup(t, key, backup)
	seed(t, key)
	original := regExport(t, key)

	registerCommitted(t, scheme, backup)
	restore, err := registerScheme(scheme, testDisplayName, testExe)
	if err != nil {
		t.Fatalf("control: registerScheme beside a committed backup: %v", err)
	}
	if err := restore(); err != nil {
		t.Fatalf("control: restore: %v", err)
	}
	assertRestored(t, key, backup, original)
	if t.Failed() {
		t.FailNow()
	}
	registerCommitted(t, scheme, backup)
	return key, backup
}

// assertBackupRefused applies change to the committed backup, then expects two calls refused with an error that check accepts, no registry write, and key and backup unchanged.
func assertBackupRefused(t *testing.T, scheme, key, backup string, change func(), check func(what string, err error)) {
	t.Helper()
	t.Cleanup(func() { regFault = nil })
	committed := regSnapshot(t, backup)
	change()
	backupBefore := regSnapshot(t, backup)
	if backupBefore == committed {
		t.Fatal("the change left the backup as committed")
	}
	keyBefore := regSnapshot(t, key)

	for _, what := range []string{"registerScheme", "the second registerScheme"} {
		calls := 0
		regFault = func() error { calls++; return nil }
		restore, err := registerScheme(scheme, testDisplayName, testExe)
		regFault = nil
		if err == nil {
			t.Errorf("%s accepted the backup", what)
			if rerr := restore(); rerr != nil {
				t.Errorf("restore: %v", rerr)
			}
		} else {
			check(what, err)
		}
		if calls != 0 {
			t.Errorf("%s made %d registry writes, want 0", what, calls)
		}
		if got := regSnapshot(t, key); got != keyBefore {
			t.Errorf("after %s, %s changed\nbefore:\n%s\nafter:\n%s", what, key, keyBefore, got)
		}
		if got := regSnapshot(t, backup); got != backupBefore {
			t.Errorf("after %s, %s changed\nbefore:\n%s\nafter:\n%s", what, backup, backupBefore, got)
		}
	}
}

func denyDelete(t *testing.T, key string) {
	t.Helper()
	bare, err := keySDDL(hkcuRel(key))
	if err != nil {
		t.Fatal(err)
	}
	if err := setKeyDACL(hkcuRel(key), withACE(daclOf(bare), "(D;;SD;;;"+userSID(t)+")")); err != nil {
		t.Fatalf("denying DELETE on %s: %v", key, err)
	}
}

// regKeyPath returns the kernel name of the open key k.
func regKeyPath(k syscall.Handle) (string, error) {
	const keyNameInformation = 3
	var n uint32
	procNtQueryKey.Call(uintptr(k), keyNameInformation, 0, 0, uintptr(unsafe.Pointer(&n)))
	if n < 4 {
		return "", fmt.Errorf("NtQueryKey reported a %d-byte name", n)
	}
	// KEY_NAME_INFORMATION is a ULONG byte count followed by the name.
	buf := make([]uint32, (n+3)/4)
	if st, _, _ := procNtQueryKey.Call(uintptr(k), keyNameInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&n))); st != 0 {
		return "", fmt.Errorf("NtQueryKey: NTSTATUS 0x%08X", st)
	}
	name := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[1])), buf[0]/2)
	return string(utf16.Decode(name)), nil
}

// regIsLink reports whether the key at path under HKEY_CURRENT_USER is a registry link, which opens by name as another key or not at all.
func regIsLink(path string) (bool, error) {
	k, err := regOpen(path, regOptionOpenLink, syscall.KEY_QUERY_VALUE)
	if err != nil {
		return false, err
	}
	defer syscall.RegCloseKey(k)
	self, err := regKeyPath(k)
	if err != nil {
		return false, err
	}
	byName, err := regOpen(path, 0, syscall.KEY_QUERY_VALUE)
	if err != nil {
		return true, nil
	}
	defer syscall.RegCloseKey(byName)
	other, err := regKeyPath(byName)
	if err != nil {
		return false, err
	}
	return other != self, nil
}

// regDeleteLink deletes the link at path under HKEY_CURRENT_USER, never its target.
func regDeleteLink(path string) error {
	k, err := regOpen(path, regOptionOpenLink, deleteAccess)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer syscall.RegCloseKey(k)
	if st, _, _ := procNtDeleteKey.Call(uintptr(k)); st != 0 {
		return fmt.Errorf("NtDeleteKey %s: NTSTATUS 0x%08X", path, st)
	}
	return nil
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
	if fileExists(testPortFile(t, scheme)) {
		t.Error("the port file survived Close")
	}
}

func TestRegisterSchemeHealsKilledSessionByPhase(t *testing.T) {
	for _, c := range []struct {
		name, scheme string
		phase        bool
		replaced     bool
	}{
		{"own command", "schemerselftesthealown", false, false},
		{"replaced mid-change", "schemerselftesthealphase", true, true},
		{"replaced", "schemerselftesthealreplaced", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, backup := scratchKeys(t, c.scheme)
			seedForeign(t, key)
			want := regExport(t, key)
			registerCommitted(t, c.scheme, backup)
			if c.phase {
				seedPhase(t, backup)
			}
			if c.replaced {
				if err := regRun("delete", key, "/f"); err != nil {
					t.Fatal(err)
				}
				seedNoShell(t, key)
				if !c.phase {
					want = regExport(t, key)
				}
			}

			restore, err := registerScheme(c.scheme, testDisplayName, testExe)
			if err != nil {
				t.Fatal(err)
			}
			if err := restore(); err != nil {
				t.Fatal(err)
			}
			assertRestored(t, key, backup, want)
		})
	}
}

const portDirChildEnv = "SCHEMER_PORTDIR_CHILD"

func TestPortFileDirIgnoresTheEnvironment(t *testing.T) {
	// The child run prints the directory it resolves.
	if os.Getenv(portDirChildEnv) != "" {
		dir, err := defaultPortFileDir()
		fmt.Printf("dir=%s err=%v\n", dir, err)
		return
	}

	want, err := defaultPortFileDir()
	if err != nil {
		t.Fatal(err)
	}
	if local := filepath.Join(os.Getenv("LOCALAPPDATA"), "schemer"); !strings.EqualFold(want, local) {
		t.Fatalf("defaultPortFileDir = %q, want %q", want, local)
	}

	fake := fakeProfileDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestPortFileDirIgnoresTheEnvironment$", "-test.count=1")
	cmd.Env = append(os.Environ(), portDirChildEnv+"=1")
	for _, v := range []string{"USERPROFILE", "LOCALAPPDATA", "TMP", "TEMP"} {
		cmd.Env = append(cmd.Env, v+"="+fake)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the child: %v\n%s", err, out)
	}
	if line := "dir=" + want + " err=<nil>"; !strings.Contains(string(out), line) {
		t.Errorf("with USERPROFILE, LOCALAPPDATA, TMP and TEMP at %s the child printed\n%s\nwant %s", fake, out, line)
	}
}

func TestRegisterSchemeRefusesTreeItCannotReplace(t *testing.T) {
	for _, c := range []struct {
		name, scheme, subkey string
		defect               func(t *testing.T, key, outside string)
	}{
		{"link", "schemerselftestpflink", "sublink", func(t *testing.T, key, outside string) {
			createRegLink(t, key+`\shell\sublink`, outside)
		}},
		{"empty link", "schemerselftestpfemptylink", "subempty", func(t *testing.T, key, _ string) {
			createRegLink(t, key+`\shell\subempty`, "")
		}},
		// RegOpenKeyExW stops at the NUL and opens the existing shell\open.
		{"NUL in a name", "schemerselftestpfnul", "open\x00x", func(t *testing.T, key, _ string) {
			shell, err := regOpen(hkcuRel(key)+`\shell`, regOptionOpenLink, syscall.KEY_CREATE_SUB_KEY)
			if err != nil {
				t.Fatal(err)
			}
			nul, _, err := ntCreateKey(shell, utf16.Encode([]rune("open\x00x")), syscall.KEY_READ)
			syscall.RegCloseKey(shell)
			if err != nil {
				t.Fatal(err)
			}
			syscall.RegCloseKey(nul)
			t.Cleanup(func() {
				if err := deleteNulKeys(hkcuRel(key)); err != nil {
					t.Errorf("cleanup: %v", err)
				}
			})
		}},
		{"DELETE denied", "schemerselftestpfdeny", "command", func(t *testing.T, key, _ string) {
			denyDelete(t, key+`\shell\open\command`)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, backup := scratchKeys(t, c.scheme)
			outside, outsideBackup := scratchKeys(t, c.scheme+"outside")
			unlockTreesOnCleanup(t, key, backup, outside, outsideBackup)
			seedProtocol(t, key)
			regAdd(t, outside, "/v", "keep", "/d", "outside")
			assertRoundTripKeepsSDDL(t, "control: ", c.scheme, key, backup, protocolPaths)

			c.defect(t, key, outside)
			keyBefore, outsideBefore := regSnapshot(t, key), regSnapshot(t, outside)
			t.Cleanup(func() { regFault = nil })
			writes := 0
			regFault = func() error { writes++; return nil }
			restore, err := registerScheme(c.scheme, testDisplayName, testExe)
			regFault = nil

			root := `HKCU\Software\Classes\` + c.scheme
			switch {
			case err == nil:
				t.Error("registerScheme accepted the tree")
				if err := restore(); err != nil {
					t.Errorf("restore: %v", err)
				}
			case !strings.Contains(err.Error(), root) || strings.Contains(err.Error(), c.subkey):
				t.Errorf("registerScheme = %q, want an error naming %s and not %q", err, root, c.subkey)
			}
			if writes != 0 {
				t.Errorf("registerScheme made %d registry writes, want 0", writes)
			}
			if keyExists(t, backup) {
				t.Errorf("%s exists after registerScheme", backup)
			}
			if got := regSnapshot(t, key); got != keyBefore {
				t.Errorf("%s changed\nbefore:\n%s\nafter:\n%s", key, keyBefore, got)
			}
			if got := regSnapshot(t, outside); got != outsideBefore {
				t.Errorf("%s changed\nbefore:\n%s\nafter:\n%s", outside, outsideBefore, got)
			}
		})
	}
}

func TestRegisterSchemeRoundTripsDenyOutsideItsAccessMask(t *testing.T) {
	const scheme = "schemerselftestpfsetvalue"
	key, backup := scratchKeys(t, scheme)
	unlockTreesOnCleanup(t, key, backup)
	seedProtocol(t, key)
	assertRoundTripKeepsSDDL(t, "control: ", scheme, key, backup, protocolPaths)

	command := hkcuRel(key) + `\shell\open\command`
	sddl, err := keySDDL(command)
	if err != nil {
		t.Fatal(err)
	}
	if err := setKeyDACL(command, withACE(daclOf(sddl), "(D;;0x2;;;"+userSID(t)+")")); err != nil {
		t.Fatalf("denying KEY_SET_VALUE: %v", err)
	}
	assertRoundTripKeepsSDDL(t, "", scheme, key, backup, protocolPaths)
}

func TestRegisterSchemeHealErrorNamesBackup(t *testing.T) {
	const scheme = "schemerselftesthealfault"
	key, backup := scratchKeys(t, scheme)
	seedForeign(t, key)
	original := regExport(t, key)
	t.Cleanup(func() { regFault = nil })

	registerCommitted(t, scheme, backup)
	restore, err := registerScheme(scheme, testDisplayName, testExe)
	if err != nil {
		t.Fatalf("control: registerScheme beside a committed backup: %v", err)
	}
	if err := restore(); err != nil {
		t.Fatalf("control: restore: %v", err)
	}
	assertRestored(t, key, backup, original)

	registerCommitted(t, scheme, backup)
	injected := errors.New("injected fault on every registry write")
	regFault = func() error { return injected }
	_, err = registerScheme(scheme, testDisplayName, testExe)
	regFault = nil
	if !errors.Is(err, injected) || !strings.Contains(fmt.Sprint(err), backup) {
		t.Errorf("registerScheme = %v, want %v wrapped with %s", err, injected, backup)
	}
}

func TestRegisterSchemeRefusesBackupItCannotDelete(t *testing.T) {
	for _, c := range []struct {
		name, scheme, subkey string
		change               func(t *testing.T, backup string)
	}{
		{"DELETE denied on the backup", "schemerselftestbkdeny", "", func(t *testing.T, backup string) {
			denyDelete(t, backup)
		}},
		{"empty link under prev", "schemerselftestbklink", "strayedlink", func(t *testing.T, backup string) {
			createRegLink(t, backup+`\prev\shell\strayedlink`, "")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, backup := seedCommitted(t, c.scheme, seedProtocol)
			assertBackupRefused(t, c.scheme, key, backup, func() { c.change(t, backup) }, func(what string, err error) {
				if !strings.Contains(err.Error(), backup) || c.subkey != "" && strings.Contains(err.Error(), c.subkey) {
					t.Errorf("%s = %q, want an error naming %s and not %q", what, err, backup, c.subkey)
				}
			})
		})
	}
}
