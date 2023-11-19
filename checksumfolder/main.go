package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	modes = []string{
		"md5",
		"sha1",
		"sha256",
	}
)

type hashFunc func([]byte) string

func main() {
	mode := flag.String("mode", "md5", fmt.Sprintf("mode: %s\n", strings.Join(modes, ", ")))
	rootPath := flag.String("root-path", "", "A root path")

	flag.Parse()

	if err := run(*mode, *rootPath); err != nil {
		panic(err)
	}
}

func run(mode string, rootPath string) error {
	if rootPath == "" {
		return errors.New("root path cannot empty")
	}

	var hash hashFunc

	switch mode {
	case "md5":
		hash = hashMD5
	case "sha1":
		hash = hashSHA1
	case "sha256":
		hash = hashSHA256
	default:
		return errors.New("mode does not exist")
	}

	if err := checksumfolder(hash, rootPath); err != nil {
		return err
	}

	return nil
}

func checksumfolder(hash hashFunc, rootPath string) error {
	entries, err := os.ReadDir(rootPath)

	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			path := fmt.Sprintf("%s\\%s", rootPath, entry.Name())
			data, err := os.ReadFile(path)

			if err != nil {
				fmt.Printf("%s: %s\n", path, err.Error())
			} else {
				fmt.Printf("%s: %s\n", path, hash(data))
			}
		}
	}

	if err != nil {
		return err
	}

	return nil
}

func hashMD5(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func hashSHA1(data []byte) string {
	hash := sha1.Sum(data)
	return hex.EncodeToString(hash[:])
}

func hashSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
