package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"net/url"
	"regexp"
	"time"
)

const (
	CACertPemFile = "../cert_db/trust1.domain.crt"

	CAKeyPemFile = "../cert_db/trust1.domain_key.pem"
)

func checkIsCA(req x509.CertificateRequest) bool {
	var oidExtensionBasicConstraints = []int{2, 5, 29, 19}
	var b struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	for _, ext := range req.Extensions {
		if ext.Id.Equal(oidExtensionBasicConstraints) {
			asn1.Unmarshal(ext.Value, &b)
			if b.IsCA == true {
				return true
			}
		}
	}
	return false
}

func signRequest(req x509.CertificateRequest) (cert []byte, err error) {
	template := x509.Certificate{}
	template.Subject = req.Subject
	err = validateSPIFFEURIs(req.URIs)
	if err != nil {
		return
	}
	if checkIsCA(req) {
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	template.URIs = req.URIs
	template.SerialNumber = big.NewInt(time.Now().UnixNano())
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().Add(time.Hour * 24)
	ca, caKey := getCA()
	cert, err = x509.CreateCertificate(rand.Reader, &template, ca, req.PublicKey, caKey)
	return
}

func validateSPIFFEURIs(uris []*url.URL) error {
	if len(uris) != 1 {
		return errors.New("bad length")
	}
	matched, err := regexp.MatchString(hardcodedSPIFFEMasks.Value, uris[0].String())
	if err != nil {
		return err
	}
	if !matched {
		return errors.New("not matched spiffe uri")
	}
	return nil
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
