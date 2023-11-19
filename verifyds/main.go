package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type CMSG_SIGNER_INFO struct {
	DwVersion               uint32
	Issuer                  windows.CertNameBlob
	SerialNumber            windows.CryptIntegerBlob
	HashAlgorithm           windows.CryptAlgorithmIdentifier
	HashEncryptionAlgorithm windows.CryptAlgorithmIdentifier
	EncryptedHash           windows.CryptDataBlob
	AuthAttrs               windows.CryptAttrBlob
	UnauthAttrs             windows.CryptAttrBlob
}

const (
	CMSG_SIGNER_INFO_PARAM = 6
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: verifyds filepath")
		os.Exit(1)
	}

	path := os.Args[1]

	if err := ExtractDigitalSignature(path); err != nil {
		panic(err)
	}
}

//func ExtractDigitalSignature(filePath string) error {
//	peFile, err := pe.Open(filePath)
//
//	if err != nil {
//		return err
//	}
//
//	defer peFile.Close()
//
//	var vAddr uint32
//	var size uint32
//
//	switch t := peFile.OptionalHeader.(type) {
//	case *pe.OptionalHeader32:
//		vAddr = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
//		size = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
//	case *pe.OptionalHeader64:
//		vAddr = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
//		size = t.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size
//	}
//
//	if vAddr <= 0 || size <= 0 {
//		return errors.New("not signed PE file")
//	}
//
//	f, err := os.Open(filePath)
//
//	if err != nil {
//		return err
//	}
//
//	defer f.Close()
//
//	buf := make([]byte, int64(size))
//
//	f.ReadAt(buf, int64(vAddr+8))
//
//	os.WriteFile("ds.pkcs7", buf, 0644)
//
//	return nil
//}

func ExtractDigitalSignature(path string) error {
	var (
		certStore windows.Handle
		msg       windows.Handle
	)

	utf16Path, err := windows.UTF16PtrFromString(path)

	if err != nil {
		return err
	}

	if err = windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(utf16Path),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		nil,
		nil,
		nil,
		&certStore,
		&msg,
		nil,
	); err != nil {
		return err
	}

	defer func() {
		windows.CertCloseStore(certStore, 0)
	}()

	var (
		crypt32                        = syscall.NewLazyDLL("crypt32.dll")
		procCryptMsgGetParam           = crypt32.NewProc("CryptMsgGetParam")
		procCertFindCertificateInStore = crypt32.NewProc("CertFindCertificateInStore")
	)

	var dwSignerInfo uint32

	if ret, _, err := procCryptMsgGetParam.Call(
		uintptr(msg),
		uintptr(CMSG_SIGNER_INFO_PARAM),
		0,
		0,
		uintptr(unsafe.Pointer(&dwSignerInfo)),
	); ret == 0 {
		return err
	}

	pSignerInfo, err := windows.LocalAlloc(windows.LPTR, dwSignerInfo)

	if err != nil {
		return err
	}

	signerInfo := (*CMSG_SIGNER_INFO)(unsafe.Pointer(pSignerInfo))

	if ret, _, err := procCryptMsgGetParam.Call(
		uintptr(msg),
		uintptr(CMSG_SIGNER_INFO_PARAM),
		0,
		pSignerInfo,
		uintptr(unsafe.Pointer(&dwSignerInfo)),
	); ret == 0 {
		return err
	}

	var certInfo = windows.CertInfo{Issuer: signerInfo.Issuer, SerialNumber: signerInfo.SerialNumber}

	ret, _, err := procCertFindCertificateInStore.Call(
		uintptr(certStore),
		uintptr(windows.PKCS_7_ASN_ENCODING|windows.X509_ASN_ENCODING),
		0,
		uintptr(windows.CERT_FIND_SUBJECT_CERT),
		uintptr(unsafe.Pointer(&certInfo)),
		0,
	)

	if ret == 0 {
		return err
	}

	certContext := (*windows.CertContext)(unsafe.Pointer(ret))

	encodedCertBytes := unsafe.Slice(certContext.EncodedCert, certContext.Length)
	cert, err := x509.ParseCertificate(encodedCertBytes)

	if err != nil {
		return err
	}

	PrintX509CertificateInfo(cert)

	return nil
}

func PrintX509CertificateInfo(cert *x509.Certificate) {
	fmt.Println("Certificate:")
	fmt.Println("----------------")

	fmt.Println("Version: ", cert.Version)
	fmt.Printf("Serial number: %x\n", cert.SerialNumber.Bytes())
	fmt.Println("Issuer: ", cert.Issuer.String())
	fmt.Println("Valid from: ", cert.NotBefore.String())
	fmt.Println("Valid to: ", cert.NotAfter.String())
	fmt.Println("Subject: ", cert.Subject.String())
	fmt.Println("Public key algorithm: ", cert.PublicKeyAlgorithm.String())
	fmt.Printf("Public key: %x\n", cert.PublicKey)
	fmt.Println("Signature algorithm: ", cert.SignatureAlgorithm.String())
	fmt.Printf("Signature: %x\n", cert.Signature)
}
