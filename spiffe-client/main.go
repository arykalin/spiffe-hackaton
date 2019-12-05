package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/spiffe/go-spiffe/workload"
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
	svid, err := pemCollectionTOCVID(*pcc)
	if err != nil {
		log.Fatalf("%s", err)
	}
	log.Println(svid.SPIFFEID)
}

var pp = func(a interface{}) {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	log.Println(string(b))
}

func pemCollectionTOCVID(collection certificate.PEMCollection) (svid workload.X509SVID, err error) {
	p, _ := pem.Decode([]byte(collection.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return
	}
	svid.SPIFFEID = cert.URIs[0].String()
	svid.Certificates = []*x509.Certificate{cert}
	for _, c := range collection.Chain {
		p, _ = pem.Decode([]byte(c))
		cert, err = x509.ParseCertificate(p.Bytes)
		if err != nil {
			return
		}
		svid.Certificates = append(svid.Certificates, cert)
	}
	p, _ = pem.Decode([]byte(collection.PrivateKey))
	key, _ := x509.ParsePKCS8PrivateKey(p.Bytes)
	switch key.(type) {
	case *rsa.PrivateKey:
		svid.PrivateKey = key.(*rsa.PrivateKey)
	case *ecdsa.PrivateKey:
		svid.PrivateKey = key.(*ecdsa.PrivateKey)
	}
	p, _ = pem.Decode([]byte(CACertPem))
	cert, _ = x509.ParseCertificate(p.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	svid.TrustBundle = []*x509.Certificate{cert}
	svid.TrustBundlePool = pool
	return
}
