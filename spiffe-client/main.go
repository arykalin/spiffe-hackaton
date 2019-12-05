package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"github.com/spiffe/go-spiffe/spiffe"
	"io/ioutil"
	"log"
	"net/url"
	"time"

	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
)

func main() {
	buf, err := ioutil.ReadFile("../faketpp/trust.pem")
	if err != nil {
		panic(err)
	}

	config := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
		BaseUrl:       "http://localhost:8080",
		Credentials: &endpoint.Authentication{
			AccessToken: "88870cb8-a5f9-44a7-a63e-85a3e5706d32"},
		Zone:            "default",
		ConnectionTrust: string(buf),
	}

	c, err := vcert.NewClient(config)
	if err != nil {
		log.Fatalf("could not connect to endpoint: %s", err)
	}

	u := url.URL{Scheme: "spiffe", Host: "example.com", Path: "foo"}
	enrollReq := &certificate.Request{
		Subject: pkix.Name{
			CommonName: "",
		},
		URIs: []*url.URL{&u},
	}

	err = c.GenerateRequest(nil, enrollReq)
	if err != nil {
		log.Fatalf("could not generate certificate request: %s", err)
	}

	requestID, err := c.RequestCertificate(enrollReq)
	if err != nil {
		log.Fatalf("could not submit certificate request: %s", err)
	}

	pickupReq := &certificate.Request{
		PickupID: requestID,
		Timeout:  180 * time.Second,
	}
	pcc, err := c.RetrieveCertificate(pickupReq)
	if err != nil {
		log.Fatalf("could not retrieve certificate using requestId %s: %s", requestID, err)
	}

	_ = pcc.AddPrivateKey(enrollReq.PrivateKey, []byte(enrollReq.KeyPassword))

	//pp(pcc)
	fmt.Println(pcc.Certificate)

	// Verify the certificate chain. Allow the remote peer to have any SPIFFE ID as
	// the authorization check will happen via `orig`.
	var certs []*x509.Certificate
	cert, err := x509.ParseCertificate([]byte(pcc.Certificate))
	if err != nil {
		log.Fatalf("%s", err)
	}
	certs = append(certs, cert)
	var roots map[string]*x509.CertPool
	//roots
	verifiedChains, err := spiffe.VerifyPeerCertificate(certs, roots, spiffe.ExpectAnyPeer())
	if err != nil {
		log.Fatalf("%s", err)
	}
	log.Println(verifiedChains)
}

var pp = func(a interface{}) {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	log.Println(string(b))
}
