package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
	"github.com/mr-tron/base58"
	badRandom "math/rand"
	"net/http"
	"os"
	"os/signal"
	"time"
)

const (
	urlResourceAuthorize           = "/vedsdk/authorize/"
	urlResourceCertificateRequest  = "/vedsdk/certificates/request"
	urlResourceCertificateRetrieve = "/vedsdk/certificates/retrieve"
	urlResourceCertificatePolicy   = "/vedsdk/certificates/checkpolicy"

	listenAddr = ":8080"
	caFile     = "server.crt"
	keyFile    = "server.key"
)

func main() {
	badRandom.Seed(time.Now().UnixNano())
	e := echo.New()

	e.POST(urlResourceAuthorize, fakeAuth)
	e.POST(urlResourceCertificateRequest, fakeRequest)
	e.POST(urlResourceCertificateRetrieve, fakeRetrieve)
	e.POST(urlResourceCertificatePolicy, fakePolicy)
	go func() {
		log.Infof("Start listen http service on %s", listenAddr)
		if err := e.StartTLS(listenAddr, caFile, keyFile); err != nil {
			log.Errorf("shutting down the server: %s", listenAddr)
		} else {
			log.Error("shutting down the server")
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
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
		base64.StdEncoding.EncodeToString([]byte(cert + "\n" + CACertPem)),
	}
	return c.JSON(http.StatusOK, r)
}

func randomID() string {
	buf := make([]byte, 16)
	badRandom.Read(buf)
	return base58.Encode(buf)
}
