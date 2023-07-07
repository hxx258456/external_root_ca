package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"time"
)

func main() {
	info, err := os.Stat("testdata/")
	if err != nil {
		panic(err)
	}
	if !info.IsDir() {
		err = os.Mkdir("testdata", 0755)
		if err != nil {
			panic(err)
		}
	}

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var rootCsr = &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Country:      []string{"CN"},
			Province:     []string{"北京"},
			Locality:     []string{"北京"},
			Organization: []string{"org1.example.com"},
			// OrganizationalUnit: []string{"platformDeveloper"},
			CommonName: "ca.org1.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(15, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// DNSNames: []string{
		// 	"*.chinabidding.sygnew.com",
		// },
		// IPAddresses: []net.IP{
		// 	net.IPv4(127, 0, 0, 1),
		// 	net.IPv4(0, 0, 0, 0),
		// },
	}
	rootDer, err := x509.CreateCertificate(rand.Reader, rootCsr, rootCsr, privKey.Public(), privKey)
	if err != nil {
		panic(err)
	}
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootDer,
	}

	pemData := pem.EncodeToMemory(certBlock)

	if err = os.WriteFile("./testdata/ca-cert.pem", pemData, 0644); err != nil {
		panic(err)
	}

	keyDer, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		panic(err)
	}

	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	keyData := pem.EncodeToMemory(keyBlock)

	if err = os.WriteFile("./testdata/ca-key.pem", keyData, 0644); err != nil {
		panic(err)
	}
}

func LoadPair(certFile, keyFile string) (cert *x509.Certificate, err error) {
	if len(certFile) == 0 && len(keyFile) == 0 {
		return nil, errors.New("cert or key has not provided")
	}

	// load cert and key by tls.LoadX509KeyPair
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}

	cert, err = x509.ParseCertificate(tlsCert.Certificate[0])
	return
}
