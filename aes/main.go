package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"flag"
	"os"
)

const (
	KEY        = "thisissecretkeyusedforaesabcabca"
	IV         = "1234567891234567"
	BLOCK_SIZE = aes.BlockSize
)

func main() {
	mode := flag.String("mode", "encrypt", "mode: encrypt, decrypt")
	input := flag.String("input", "", "A path to input file")
	output := flag.String("output", "", "A path to output file")

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

	switch mode {
	case "encrypt":
		if err := encrypt(input, output); err != nil {
			return err
		}
	case "decrypt":
		if err := decrypt(input, output); err != nil {
			return err
		}
	default:
		return errors.New("mode does not exist")
	}

	return nil
}

func encrypt(input, output string) error {
	block, err := aes.NewCipher([]byte(KEY))

	if err != nil {
		return err
	}

	plainText, err := os.ReadFile(input)

	if err != nil {
		return err
	}

	plainTextPadding := PKCS7Padding(plainText, BLOCK_SIZE)

	cipherText := make([]byte, len(plainTextPadding))

	mode := cipher.NewCBCEncrypter(block, []byte(IV))

	mode.CryptBlocks(cipherText, plainTextPadding)

	cipherTextHex := hex.EncodeToString(cipherText)

	if err = os.WriteFile(output, []byte(cipherTextHex), os.FileMode(0644)); err != nil {
		return err
	}

	return nil
}

func decrypt(input, output string) error {
	block, err := aes.NewCipher([]byte(KEY))

	if err != nil {
		return err
	}

	cipherTextHex, err := os.ReadFile(input)

	if err != nil {
		return err
	}

	cipherText, err := hex.DecodeString(string(cipherTextHex))

	if err != nil {
		return err
	}

	plainTextPadding := make([]byte, len(cipherText))

	mode := cipher.NewCBCDecrypter(block, []byte(IV))

	mode.CryptBlocks(plainTextPadding, cipherText)

	plainText := PKCS7UnPadding(plainTextPadding)

	if err := os.WriteFile(output, plainText, os.FileMode(0644)); err != nil {
		return err
	}

	return nil
}

func PKCS7Padding(cipherText []byte, blockSize int) []byte {
	padding := (blockSize - len(cipherText)%blockSize)

	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(cipherText, padText...)
}

func PKCS7UnPadding(plainTextPadding []byte) []byte {
	length := len(plainTextPadding)

	padding := int(plainTextPadding[length-1])

	return plainTextPadding[:(length - padding)]
}
