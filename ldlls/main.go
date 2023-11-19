package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const PROCESS_ALL_ACCESS = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xFFFF

var (
	psapi                = syscall.NewLazyDLL("psapi.dll")
	enumProcessModules   = psapi.NewProc("EnumProcessModules")
	getModuleFileNameExA = psapi.NewProc("GetModuleFileNameExA")
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: ldlls pid")
		os.Exit(1)
	}

	pid, err := strconv.ParseUint(os.Args[1], 10, 64)

	if err != nil {
		panic(err)
	}

	if err = ListDlls(pid); err != nil {
		panic(err)
	}
}

func ListDlls(pid uint64) error {
	process, err := syscall.OpenProcess(PROCESS_ALL_ACCESS|syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))

	if err != nil {
		return err
	}

	var (
		hmods  [2048]uintptr
		nbytes uint32
	)

	const hmodSize = unsafe.Sizeof(hmods[0])

	if ok, _, err := enumProcessModules.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&hmods)),
		hmodSize*uintptr(len(hmods)),
		uintptr(unsafe.Pointer(&nbytes)),
	); ok == 0 {
		return err
	}

	for _, hmod := range hmods {
		if hmod > 0 {
			var modFilename [200]byte
			var modSize uint32 = 200
			var modName string

			ret, _, _ := getModuleFileNameExA.Call(
				uintptr(process),
				uintptr(hmod),
				uintptr(unsafe.Pointer(&modFilename)),
				uintptr(modSize),
			)

			if ret != 0 {
				for _, char := range modFilename {
					if char == 0 {
						break
					}

					modName += string(char)
				}

				fmt.Println(modName)
			}
		}
	}

	return nil
}
