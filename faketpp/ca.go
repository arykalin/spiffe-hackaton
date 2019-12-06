package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"
)

const (
	CACertPemFile = "../cert_db/trust1.domain.crt"

	CAKeyPemFile = "../cert_db/trust1.domain_key.pem"
)

func signRequest(req x509.CertificateRequest) (cert []byte, err error) {
	template := x509.Certificate{}
	template.Subject = req.Subject
	template.URIs = req.URIs
	template.SerialNumber = big.NewInt(time.Now().UnixNano())
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(time.Hour * 24)
	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	ca, caKey := getCA()
	cert, err = x509.CreateCertificate(rand.Reader, &template, ca, req.PublicKey, caKey)
	return
}

func getCA() (*x509.Certificate, *rsa.PrivateKey) {
	CACertPem, err := ioutil.ReadFile(CACertPemFile)
	if err != nil {
		panic(err)
	}
	p, _ := pem.Decode(CACertPem)
	caCert, _ := x509.ParseCertificate(p.Bytes)

	CAKeyPem, err := ioutil.ReadFile(CAKeyPemFile)
	if err != nil {
		panic(err)
	}
	p, _ = pem.Decode(CAKeyPem)
	key, _ := x509.ParsePKCS1PrivateKey(p.Bytes)
	return caCert, key
}
