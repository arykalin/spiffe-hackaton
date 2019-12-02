package main

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/labstack/echo"
	"github.com/mr-tron/base58"
	badRandom "math/rand"
	"net/http"
	"time"
)

const (
	urlResourceAuthorize           = "/vedsdk/authorize/"
	urlResourceCertificateRequest  = "/vedsdk/certificates/request"
	urlResourceCertificateRetrieve = "/vedsdk/certificates/retrieve"
)

func main() {
	badRandom.Seed(time.Now().UnixNano())
	e := echo.New()

	e.POST(urlResourceAuthorize, fakeAuth)
	e.POST(urlResourceCertificateRequest, fakeRequest)
	e.POST(urlResourceCertificateRetrieve, fakeRetrieve)
}

type errorMessage struct {
	Error string `json:"error"`
}

func fakeAuth(c echo.Context) error {
	b := struct {
		APIKey     string
		ValidUntil string
	}{
		"88870cb8-a5f9-44a7-a63e-85a3e5706d32",
		"",
	}
	return c.JSON(http.StatusOK, b)
}

func fakeRequest(c echo.Context) error {
	var body struct {
		PKCS10 string
	}

	err := c.Bind(&body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, errorMessage{err.Error()})
	}
	p, _ := pem.Decode([]byte(body.PKCS10))
	req, err := x509.ParseCertificateRequest(p.Bytes)
	if err != nil {
		return c.JSON(http.StatusBadRequest, errorMessage{err.Error()})
	}
	cert, err := signRequest(*req)
	if err != nil {
		return c.JSON(http.StatusBadRequest, errorMessage{err.Error()})
	}
	certID := randomID()
	encodedCert := pem.EncodeToMemory(&pem.Block{Bytes: cert, Type: "CERTIFICATE"})
	saveToDB(certID, string(encodedCert))
	r := struct {
		CertificateDN string
	}{
		certID,
	}
	return c.JSON(http.StatusOK, r)
}
func fakeRetrieve(c echo.Context) error {
	var body struct {
		CertificateDN string
	}
	err := c.Bind(&body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, errorMessage{err.Error()})
	}
	cert, err := getFromDB(body.CertificateDN)
	if err != nil {
		return c.JSON(http.StatusBadRequest, errorMessage{err.Error()})
	}
	r := struct {
		CertificateData string
	}{
		cert,
	}
	return c.JSON(http.StatusOK, r)
}

func randomID() string {
	buf := make([]byte, 16)
	badRandom.Read(buf)
	return base58.Encode(buf)
}
