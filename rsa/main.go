package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash"
	"os"
)

const (
	PUBLIC_KEY_FILE  = "./public.pem"
	PRIVATE_KEY_FILE = "./private.pem"
)

func main() {
	mode := flag.String("mode", "encrypt", "Mode: encrypt, decrypt")
	input := flag.String("input", "", "Path to input file")
	output := flag.String("output", "", "Path to output file")

	flag.Parse()

	if err := run(*mode, *input, *output); err != nil {
		panic(err)
	}
}

func run(mode, input, output string) error {
	if input == "" {
		return errors.New("please enter a path to input file")
	}

	if output == "" {
		return errors.New("please enter a path to output file")
	}

	hash := sha1.New()
	switch mode {
	case "encrypt":
		if err := encrypt(hash, input, output); err != nil {
			return err
		}
	case "decrypt":
		if err := decrypt(hash, input, output); err != nil {
			return err
		}
	default:
		return errors.New("mode does not exist")
	}

	return nil
}

func encrypt(hash hash.Hash, input, output string) error {
	pemData, err := os.ReadFile(PUBLIC_KEY_FILE)

	if err != nil {
		return err
	}

	block, _ := pem.Decode(pemData)

	if block == nil {
		return errors.New("not PEM-encoded")
	}

	if got, want := block.Type, "PUBLIC KEY"; got != want {
		return fmt.Errorf("unknown key type %q, want %q", got, want)
	}

	pkixPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return err
	}

	publicKey, ok := pkixPublicKey.(*rsa.PublicKey)

	if !ok {
		return errors.New("public key incorrect")
	}

	in, err := os.ReadFile(input)

	if err != nil {
		return err
	}

	inLen := len(in)

	step := publicKey.Size() - 2*hash.Size() - 2

	var out []byte

	for start := 0; start < inLen; start += step {
		finish := start + step

		if finish > inLen {
			finish = inLen
		}

		outBlock, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, in[start:finish], nil)

		if err != nil {
			return err
		}

		out = append(out, outBlock...)
	}

	if err = os.WriteFile(output, out, os.FileMode(0644)); err != nil {
		return err
	}

	return nil
}

func decrypt(hash hash.Hash, input, output string) error {
	pemData, err := os.ReadFile(PRIVATE_KEY_FILE)

	if err != nil {
		return err
	}

	block, _ := pem.Decode(pemData)

	if block == nil {
		return errors.New("not PEM-encoded")
	}

	if got, want := block.Type, "PRIVATE KEY"; got != want {
		return fmt.Errorf("unknown key type %q, want %q", got, want)
	}

	pkcs8PrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	if err != nil {
		return err
	}

	privateKey, ok := pkcs8PrivateKey.(*rsa.PrivateKey)

	if !ok {
		return errors.New("private key incorrect")
	}

	in, err := os.ReadFile(input)

	if err != nil {
		return err
	}

	inLen := len(in)

	step := privateKey.Size()

	var out []byte

	for start := 0; start < inLen; start += step {
		finish := start + step

		if finish > inLen {
			finish = inLen
		}

		outBlock, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, in[start:finish], nil)

		if err != nil {
			return err
		}

		out = append(out, outBlock...)
	}

	if err = os.WriteFile(output, out, os.FileMode(0644)); err != nil {
		return err
	}

	return nil
}
