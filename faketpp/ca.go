package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"
)

const (
	CACertPem = `-----BEGIN CERTIFICATE-----
MIIB4TCCAUKgAwIBAgIIFlcejw0f4DowCgYIKoZIzj0EAwIwEjEQMA4GA1UEAxMH
VGVzdCBDQTAeFw0xOTExMjcxNDU2MDBaFw0yOTExMjcxNDU2MDBaMBIxEDAOBgNV
BAMTB1Rlc3QgQ0EwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABABaJ/GSp/8YJiSX
EyZj76l4crhZuMOQH1zejXCJPikyeDrqUGYD6cFtTb+Qq8dryq2+wq9qi3hr5/pU
uwa+Bh4CkQBdfOBNVHdwQQTOwesAFRoKfdDYFe34J+0BiP8O6D4m/KeeJRNUBEu+
38CHhjdKVPjTSJE3982cEPEr7ZZgRng0GaM/MD0wDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUey4boJ4V1Co+a0QP0DwG1fy1Ps8wCwYDVR0PBAQDAgEGMAoGCCqG
SM49BAMCA4GMADCBiAJCAS27baw1hXG+Tjr0D6ytdk1gqVeCxE9HFT/vgpUfGuhF
PtVVH8G4o6hXhXFMNuhgOFT1eYEEmzv7Rt+gFd+Pqc3WAkIBEI/ZrNq7xQyTyQFo
Gluss4xBQEeWX0POsdRVu9igr+1Ed/RiFysvYuI6N/2ONlnKn85DOXBtVW2yvxTS
NMMtSq8=
-----END CERTIFICATE-----`

	CAKeyPem = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAl1arpwyd4Kz4okyF89bsM7E7GeqSgfjmNXybpPwFgeQs8CyrTIrd
YJFvOTtCx7+o3wHLdiwmVAigf/b9Z3cJ8omgBwYFK4EEACOhgYkDgYYABABaJ/GS
p/8YJiSXEyZj76l4crhZuMOQH1zejXCJPikyeDrqUGYD6cFtTb+Qq8dryq2+wq9q
i3hr5/pUuwa+Bh4CkQBdfOBNVHdwQQTOwesAFRoKfdDYFe34J+0BiP8O6D4m/Kee
JRNUBEu+38CHhjdKVPjTSJE3982cEPEr7ZZgRng0GQ==
-----END EC PRIVATE KEY-----`
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

func getCA() (*x509.Certificate, *ecdsa.PrivateKey) {
	p, _ := pem.Decode([]byte(CACertPem))
	caCert, _ := x509.ParseCertificate(p.Bytes)
	p, _ = pem.Decode([]byte(CAKeyPem))
	key, _ := x509.ParseECPrivateKey(p.Bytes)
	return caCert, key
}
