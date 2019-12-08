package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
	"github.com/mr-tron/base58"
	"io/ioutil"
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
	urlResourceCertificateImport   = "/vedsdk/certificates/import"

	caFile  = "faketpp/server.crt"
	keyFile = "faketpp/server.key"
)

var listenAddr string

func init() {
	badRandom.Seed(time.Now().UnixNano())
	var jsonConfigPath string
	flag.StringVar(&jsonConfigPath, "policy", "", "")
	flag.StringVar(&listenAddr, "listen", ":8080", "")
	flag.Parse()
	b, err := ioutil.ReadFile(jsonConfigPath)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(b, &currentPolicy)
	if err != nil {
		panic(err)
	}
}

func main() {
	//TODO: import SPIFFE intermediate to fatketpp
	//TODO: get SPIFFE intermediate bundle from faketpp to validate SPIFFE cert
	//TODO: make policy configuration from client
	e := echo.New()
	e.POST(urlResourceAuthorize, fakeAuth)
	e.POST(urlResourceCertificateRequest, fakeRequest)
	e.POST(urlResourceCertificateRetrieve, fakeRetrieve)
	e.POST(urlResourceCertificatePolicy, fakePolicy)
	e.POST(urlResourceCertificateImport, fakeImport)
	go func() {
		log.Infof("Start listen http service on %s", listenAddr)
		if err := e.StartTLS(listenAddr, caFile, keyFile); err != nil {
			log.Errorf("shutting down the server: %s", err)
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

	CACertPem, err := ioutil.ReadFile(CACertPemFile)
	if err != nil {
		panic(err)
	}

	r := struct {
		CertificateData string
	}{
		base64.StdEncoding.EncodeToString([]byte(cert + "\n" + string(CACertPem))),
	}
	return c.JSON(http.StatusOK, r)
}

func fakeImport(c echo.Context) error {
	r := struct {
		CertificateDN      string `json:",omitempty"`
		CertId             string `json:",omitempty"`
		CertificateVaultId int    `json:",omitempty"`
		Guid               string `json:",omitempty"`
		PrivateKeyVaultId  int    `json:",omitempty"`
	}{
		randomID(),
		randomID(),
		0,
		randomID(),
		0,
	}
	return c.JSON(http.StatusOK, r)
}

func randomID() string {
	buf := make([]byte, 16)
	badRandom.Read(buf)
	return base58.Encode(buf)
}
