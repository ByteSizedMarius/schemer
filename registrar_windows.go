package schemer

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"unsafe"
)

func defaultPortFileDir() (string, error) {
	dir, err := localAppData()
	if err != nil {
		return "", fmt.Errorf("schemer: locating the local app data folder: %w", err)
	}
	return filepath.Join(dir, "schemer"), nil
}

var (
	shell32                  = syscall.NewLazyDLL("shell32.dll")
	procSHGetKnownFolderPath = shell32.NewProc("SHGetKnownFolderPath")
	ole32                    = syscall.NewLazyDLL("ole32.dll")
	procCoTaskMemFree        = ole32.NewProc("CoTaskMemFree")
)

var folderIDLocalAppData = syscall.GUID{Data1: 0xF1B32785, Data2: 0x6FBA, Data3: 0x4FCF, Data4: [8]byte{0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91}}

func localAppData() (string, error) {
	// LazyProc.Call panics on a proc that fails to load.
	for _, p := range []*syscall.LazyProc{procSHGetKnownFolderPath, procCoTaskMemFree} {
		if err := p.Find(); err != nil {
			return "", fmt.Errorf("loading %s: %w", p.Name, err)
		}
	}
	proc, err := syscall.GetCurrentProcess()
	if err != nil {
		return "", err
	}
	// With the process token, SHGetKnownFolderPath ignores USERPROFILE.
	var tok syscall.Token
	if err := syscall.OpenProcessToken(proc, syscall.TOKEN_QUERY|syscall.TOKEN_IMPERSONATE, &tok); err != nil {
		return "", fmt.Errorf("opening the process token: %w", err)
	}
	defer tok.Close()

	var p *uint16
	r, _, _ := procSHGetKnownFolderPath.Call(uintptr(unsafe.Pointer(&folderIDLocalAppData)), 0, uintptr(tok), uintptr(unsafe.Pointer(&p)))
	if p != nil {
		defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(p)))
	}
	if hr := uint32(r); hr != 0 {
		return "", fmt.Errorf("SHGetKnownFolderPath returned HRESULT 0x%08X", hr)
	}
	if p == nil {
		return "", errors.New("SHGetKnownFolderPath returned no path")
	}
	n := 0
	for q := unsafe.Pointer(p); *(*uint16)(q) != 0; q = unsafe.Add(q, 2) {
		n++
	}
	dir := syscall.UTF16ToString(unsafe.Slice(p, n))
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("SHGetKnownFolderPath returned %q, not an absolute path", dir)
	}
	return dir, nil
}

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKeyEx = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueEx  = advapi32.NewProc("RegSetValueExW")
	procRegCopyTree    = advapi32.NewProc("RegCopyTreeW")
	procRegDeleteTree  = advapi32.NewProc("RegDeleteTreeW")
	procRegDeleteValue = advapi32.NewProc("RegDeleteValueW")
	procRegEnumValue   = advapi32.NewProc("RegEnumValueW")
)

// regFault, when set, runs before every registry write and fails it with its error.
var regFault func() error

// healHook is a test seam that runs in heal after the backup walk, before heal reads the backup.
var healHook func()

const hkcu = syscall.Handle(syscall.HKEY_CURRENT_USER)

// HKEY_CURRENT_USER_LOCAL_SETTINGS (HKCU\Software\Classes\Local Settings) does not roam.
const localSettings = syscall.Handle(0x80000007)

// RegCopyTreeW returns access denied without WRITE_DAC on the destination.
const writeDAC = 0x40000

const (
	deleteAccess      = 0x10000
	regOptionOpenLink = 0x8
	errorNoMoreItems  = syscall.Errno(259)
	classes           = `Software\Classes`
)

// RegCopyTreeW gives each copy its source key's security descriptor before creating the copy's subkeys.
const replaceAccess = syscall.KEY_READ | deleteAccess | syscall.KEY_CREATE_SUB_KEY

// registerScheme points scheme at exePath under HKCU and backs up what it replaces.
func registerScheme(scheme, displayName, exePath string) (func() error, error) {
	key := classes + `\` + scheme
	backup := `Software\schemer-` + scheme
	if err := register(key, backup, "URL:"+displayName, `"`+exePath+`" "%1"`); err != nil {
		return nil, fmt.Errorf("schemer: registering %s://: %w", scheme, err)
	}
	return func() error {
		if err := restore(key, backup); err != nil {
			return fmt.Errorf("schemer: unregistering %s://: %w", scheme, err)
		}
		return nil
	}, nil
}

func register(key, backup, name, cmd string) error {
	if err := heal(key, backup); err != nil {
		return fmt.Errorf(`settling the previous backup HKCU\Software\Classes\Local Settings\%s: %w`, backup, err)
	}
	if err := preflight(key); err != nil {
		return err
	}
	if err := checkProtocol(key); err != nil {
		return err
	}
	if err := backUp(key, backup, cmd); err != nil {
		return errors.Join(fmt.Errorf("backing up the scheme key: %w", err), deleteTree(localSettings, backup))
	}
	if err := write(key, name, cmd); err != nil {
		return errors.Join(fmt.Errorf("writing the scheme key: %w", err), restore(key, backup))
	}
	if err := deleteValue(localSettings, backup, "phase"); err != nil {
		return errors.Join(fmt.Errorf("clearing phase in the backup: %w", err), restore(key, backup))
	}
	return nil
}

// heal puts back or discards the backup a killed session left behind.
func heal(key, backup string) error {
	p, err := syscall.UTF16PtrFromString(backup)
	if err != nil {
		return err
	}
	// Another program can put a link at or under the backup.
	refused := errors.New("it or a key under it is a link or cannot be deleted")
	var b syscall.Handle
	err = syscall.RegOpenKeyEx(localSettings, p, regOptionOpenLink, replaceAccess, &b)
	switch {
	case absent(err):
		return nil
	case err != nil:
		return refused
	case !replaceable(localSettings, p, b):
		syscall.RegCloseKey(b)
		return refused
	}
	if healHook != nil {
		healHook()
	}
	markTyp, mark, err := readValue(b, "command")
	_, _, phaseErr := readValue(b, "phase")
	syscall.RegCloseKey(b)
	if absent(err) {
		return deleteTree(localSettings, backup)
	}
	if err != nil {
		return err
	}
	// With phase set, the scheme key is whatever a killed write or putBack left behind.
	if phaseErr == nil {
		return restore(key, backup)
	}
	if !absent(phaseErr) {
		return phaseErr
	}

	k, err := openKey(hkcu, key, syscall.KEY_QUERY_VALUE)
	if absent(err) {
		return restore(key, backup)
	}
	if err != nil {
		return err
	}
	typ, cmd, err := readCommand(k)
	syscall.RegCloseKey(k)
	switch {
	case err == nil && typ == markTyp && bytes.Equal(cmd, mark):
		return restore(key, backup)
	case err != nil && !absent(err):
		return err
	}
	return deleteTree(localSettings, backup)
}

// preflight checks, without writing, that register can back up and replace the scheme key.
func preflight(key string) error {
	// write creates the scheme key in the target of the HKCU\Software\Classes link.
	c, err := openKey(hkcu, classes, syscall.KEY_CREATE_SUB_KEY)
	if err != nil {
		return errors.New(`HKCU\` + classes + ` does not allow creating keys`)
	}
	syscall.RegCloseKey(c)

	p, err := syscall.UTF16PtrFromString(key)
	if err != nil {
		return err
	}
	var k syscall.Handle
	err = syscall.RegOpenKeyEx(hkcu, p, regOptionOpenLink, replaceAccess, &k)
	if absent(err) {
		return nil
	}
	if err == nil {
		ok := replaceable(hkcu, p, k)
		syscall.RegCloseKey(k)
		if ok {
			return nil
		}
	}
	return errors.New(`HKCU\` + key + ` or a key under it cannot be backed up and replaced`)
}

// replaceable expects k to be parent\name opened with REG_OPTION_OPEN_LINK.
func replaceable(parent syscall.Handle, name *uint16, k syscall.Handle) bool {
	// RegDeleteTreeW deletes the target of a link in the tree.
	link, err := syscall.UTF16PtrFromString("SymbolicLinkValue")
	if err != nil || !absent(syscall.RegQueryValueEx(k, link, nil, nil, nil, nil)) {
		return false
	}
	// A link without SymbolicLinkValue opens only with REG_OPTION_OPEN_LINK.
	var t syscall.Handle
	if err := syscall.RegOpenKeyEx(parent, name, 0, replaceAccess, &t); err != nil {
		return false
	}
	syscall.RegCloseKey(t)
	if !valueNamesCopyable(k) {
		return false
	}
	names, err := subkeys(k)
	if err != nil {
		return false
	}
	for _, n := range names {
		// RegCopyTreeW leaves out a key whose name holds NUL.
		if slices.Contains(n[:len(n)-1], 0) {
			return false
		}
		var c syscall.Handle
		if err := syscall.RegOpenKeyEx(k, &n[0], regOptionOpenLink, replaceAccess, &c); err != nil {
			return false
		}
		ok := replaceable(k, &n[0], c)
		syscall.RegCloseKey(c)
		if !ok {
			return false
		}
	}
	return true
}

// subkeys returns the raw NUL-terminated names of the subkeys of k.
func subkeys(k syscall.Handle) ([][]uint16, error) {
	// Successive RegEnumKeyExW calls must run on one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var names [][]uint16
	for i := uint32(0); ; i++ {
		// Names past 255 UTF-16 units fail with ERROR_MORE_DATA.
		buf := make([]uint16, 256)
		n := uint32(len(buf))
		err := syscall.RegEnumKeyEx(k, i, &buf[0], &n, nil, nil, nil, nil)
		if errors.Is(err, errorNoMoreItems) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		names = append(names, slices.Clone(buf[:n+1]))
	}
}

// valueNamesCopyable reports whether every value name of k enumerates and holds no NUL.
func valueNamesCopyable(k syscall.Handle) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Value names run up to 16383 UTF-16 units.
	buf := make([]uint16, 16384)
	for i := uint32(0); ; i++ {
		n := uint32(len(buf))
		r, _, _ := procRegEnumValue.Call(uintptr(k), uintptr(i), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0, 0, 0, 0)
		if syscall.Errno(r) == errorNoMoreItems {
			return true
		}
		if r != 0 {
			return false
		}
		// RegCopyTreeW cuts a value name at its first NUL.
		if slices.Contains(buf[:n], 0) {
			return false
		}
	}
}

// checkProtocol refuses an existing key without a URL Protocol value.
func checkProtocol(key string) error {
	k, err := openKey(hkcu, key, syscall.KEY_QUERY_VALUE)
	if absent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)
	_, _, err = readValue(k, "URL Protocol")
	if absent(err) {
		return fmt.Errorf(`HKCU\%s exists and is not a URL protocol`, key)
	}
	return err
}

// backUp copies key to backup\prev, then writes the markers heal reads.
func backUp(key, backup, cmd string) error {
	b, err := createKey(localSettings, backup)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(b)

	k, err := openKey(hkcu, key, syscall.KEY_READ)
	if err != nil && !absent(err) {
		return err
	}
	if err == nil {
		defer syscall.RegCloseKey(k)
		prev, err := createKey(b, "prev")
		if err != nil {
			return err
		}
		defer syscall.RegCloseKey(prev)
		if err := copyTree(k, prev); err != nil {
			return err
		}
	}
	if err := setString(b, "command", cmd); err != nil {
		return err
	}
	return setString(b, "phase", "")
}

// write replaces key with a URL protocol whose open verb runs cmd.
func write(key, name, cmd string) error {
	if err := deleteTree(hkcu, key); err != nil {
		return err
	}
	k, err := createKey(hkcu, key)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)
	if err := setString(k, "", name); err != nil {
		return err
	}
	if err := setString(k, "URL Protocol", ""); err != nil {
		return err
	}
	c, err := createKey(k, `shell\open\command`)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(c)
	return setString(c, "", cmd)
}

func restore(key, backup string) error {
	if err := putBack(key, backup); err != nil {
		return err
	}
	// Heal discards a backup without its commit marker, whatever is left of prev.
	if err := deleteValue(localSettings, backup, "command"); err != nil {
		return err
	}
	return deleteTree(localSettings, backup)
}

// putBack replaces key with backup\prev, or deletes it when there is no prev.
func putBack(key, backup string) error {
	b, err := openKey(localSettings, backup, syscall.KEY_READ|syscall.KEY_SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening the backup: %w", err)
	}
	defer syscall.RegCloseKey(b)

	if err := setString(b, "phase", ""); err != nil {
		return err
	}
	if err := deleteTree(hkcu, key); err != nil {
		return err
	}
	prev, err := openKey(b, "prev", syscall.KEY_READ)
	if absent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(prev)
	k, err := createKey(hkcu, key)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)
	return copyTree(prev, k)
}

func absent(err error) bool {
	return errors.Is(err, syscall.ERROR_FILE_NOT_FOUND)
}

func fault() error {
	if regFault == nil {
		return nil
	}
	return regFault()
}

func openKey(parent syscall.Handle, path string, access uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var k syscall.Handle
	if err := syscall.RegOpenKeyEx(parent, p, 0, access, &k); err != nil {
		return 0, err
	}
	return k, nil
}

func readValue(k syscall.Handle, name string) (uint32, []byte, error) {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, nil, err
	}
	var typ, size uint32
	if err := syscall.RegQueryValueEx(k, n, nil, &typ, nil, &size); err != nil {
		return 0, nil, err
	}
	if size == 0 {
		return typ, nil, nil
	}
	data := make([]byte, size)
	if err := syscall.RegQueryValueEx(k, n, nil, &typ, &data[0], &size); err != nil {
		return 0, nil, err
	}
	return typ, data[:size], nil
}

func readCommand(k syscall.Handle) (uint32, []byte, error) {
	c, err := openKey(k, `shell\open\command`, syscall.KEY_QUERY_VALUE)
	if err != nil {
		return 0, nil, err
	}
	defer syscall.RegCloseKey(c)
	return readValue(c, "")
}

func createKey(parent syscall.Handle, path string) (syscall.Handle, error) {
	if err := fault(); err != nil {
		return 0, err
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var k syscall.Handle
	r, _, _ := procRegCreateKeyEx.Call(uintptr(parent), uintptr(unsafe.Pointer(p)), 0, 0, 0,
		syscall.KEY_READ|syscall.KEY_WRITE|writeDAC, 0, uintptr(unsafe.Pointer(&k)), 0)
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return k, nil
}

func setString(k syscall.Handle, name, value string) error {
	if err := fault(); err != nil {
		return err
	}
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	v, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	r, _, _ := procRegSetValueEx.Call(uintptr(k), uintptr(unsafe.Pointer(n)), 0, syscall.REG_SZ,
		uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)*2))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func copyTree(src, dst syscall.Handle) error {
	if err := fault(); err != nil {
		return err
	}
	if r, _, _ := procRegCopyTree.Call(uintptr(src), 0, uintptr(dst)); r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// deleteTree treats an absent path as deleted.
func deleteTree(parent syscall.Handle, path string) error {
	if err := fault(); err != nil {
		return err
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, _ := procRegDeleteTree.Call(uintptr(parent), uintptr(unsafe.Pointer(p)))
	if r != 0 && syscall.Errno(r) != syscall.ERROR_FILE_NOT_FOUND {
		return syscall.Errno(r)
	}
	return nil
}

// deleteValue treats an absent key or value as deleted.
func deleteValue(parent syscall.Handle, path, name string) error {
	if err := fault(); err != nil {
		return err
	}
	k, err := openKey(parent, path, syscall.KEY_SET_VALUE)
	if absent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r, _, _ := procRegDeleteValue.Call(uintptr(k), uintptr(unsafe.Pointer(n)))
	if r != 0 && syscall.Errno(r) != syscall.ERROR_FILE_NOT_FOUND {
		return syscall.Errno(r)
	}
	return nil
}
