package schemer

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKeyEx = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueEx  = advapi32.NewProc("RegSetValueExW")
	procRegCopyTree    = advapi32.NewProc("RegCopyTreeW")
	procRegDeleteTree  = advapi32.NewProc("RegDeleteTreeW")
	procRegDeleteValue = advapi32.NewProc("RegDeleteValueW")
)

// regFault, when set, runs before every registry write and fails it with its error.
var regFault func() error

const hkcu = syscall.Handle(syscall.HKEY_CURRENT_USER)

// RegCopyTreeW returns access denied without WRITE_DAC on the destination.
const writeDAC = 0x40000

// registerScheme points scheme at exePath under HKCU and backs up what it replaces.
func registerScheme(scheme, displayName, exePath string) (func() error, error) {
	key := `Software\Classes\` + scheme
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
		return fmt.Errorf("settling the previous backup: %w", err)
	}
	if err := checkProtocol(key); err != nil {
		return err
	}
	if err := backUp(key, backup, cmd); err != nil {
		return errors.Join(fmt.Errorf("backing up the scheme key: %w", err), deleteTree(hkcu, backup))
	}
	if err := write(key, name, cmd); err != nil {
		return errors.Join(fmt.Errorf("writing the scheme key: %w", err), restore(key, backup))
	}
	return nil
}

// heal puts back or discards the backup a killed session left behind.
func heal(key, backup string) error {
	b, err := openKey(hkcu, backup, syscall.KEY_READ)
	if absent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	markTyp, mark, err := readValue(b, "command")
	syscall.RegCloseKey(b)
	if absent(err) {
		return deleteTree(hkcu, backup)
	}
	if err != nil {
		return err
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
	return deleteTree(hkcu, backup)
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

// backUp copies key to backup\prev and writes cmd last as the commit marker.
func backUp(key, backup, cmd string) error {
	b, err := createKey(hkcu, backup)
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
	return setString(b, "command", cmd)
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
	if err := deleteValue(hkcu, backup, "command"); err != nil {
		return err
	}
	return deleteTree(hkcu, backup)
}

// putBack replaces key with backup\prev, or deletes key when backup holds no prev.
func putBack(key, backup string) error {
	b, err := openKey(hkcu, backup, syscall.KEY_READ)
	if err != nil {
		return fmt.Errorf("opening the backup: %w", err)
	}
	defer syscall.RegCloseKey(b)

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
