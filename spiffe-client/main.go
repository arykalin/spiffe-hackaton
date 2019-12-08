package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/spiffe/go-spiffe/spiffe"
	"github.com/spiffe/go-spiffe/workload"
	"io/ioutil"
	"log"
	"net/url"
	"time"

	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
)

const (
	trustFile          = "./faketpp/trust.pem"
	trustDomain1CAFile = "./cert_db/trust1.domain.crt"
	trustDomain2CAFile = "./cert_db/trust2.domain.crt"
)

var serverURL string

func main() {
	//TODO: make a code to generate intermediate signing SVID from root CA

	var (
		co                string
		uri               string
		path              string
		zone              string
		trustDomainCAPath string
	)
	flag.StringVar(&co, "command", "", "")
	flag.StringVar(&uri, "uri", "", "")
	flag.StringVar(&path, "path", "", "Path to cert file")
	flag.StringVar(&zone, "zone", "default", "")
	flag.StringVar(&trustDomainCAPath, "trustDomainCAPath", "", "Path trust domain to cert file")
	flag.StringVar(&serverURL, "url", "https://localhost:8080/", "")
	flag.Parse()

	switch co {
	case "enroll":
		log.Println("Enroll cert with SVID", uri)
		s, err := url.Parse(uri)
		if err != nil {
			log.Fatalf("%s", err)
		}
		u := url.URL{Scheme: s.Scheme, Host: s.Host, Path: s.Path}
		enroll(u, zone)
	case "validate":
		log.Println("Validating cert file", path)
		b, err := ioutil.ReadFile(path)
		if err != nil {
			panic(err)
		}
		var pcc certificate.PEMCollection
		err = json.Unmarshal(b, &pcc)
		if err != nil {
			panic(err)
		}
		verifyWorkloadCert(pcc, trustDomainCAPath)
		//verifyWorkloadCert(*pcc, trustDomain2CAFile)
	default:
		panic("you forgot command")
	}
}

func enroll(u url.URL, zone string) {

	buf, err := ioutil.ReadFile(trustFile)
	if err != nil {
		panic(err)
	}

	config := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
		BaseUrl:       serverURL,
		Credentials: &endpoint.Authentication{
			AccessToken: "88870cb8-a5f9-44a7-a63e-85a3e5706d32"},
		Zone:            zone,
		ConnectionTrust: string(buf),
	}

	c, err := vcert.NewClient(config)
	if err != nil {
		log.Fatalf("could not connect to endpoint: %s", err)
	}

	enrollReq := &certificate.Request{
		Subject: pkix.Name{
			CommonName: "",
		},
		URIs:      []*url.URL{&u},
		KeyLength: 2048,
	}

	policy, err := c.ReadPolicyConfiguration()
	if err != nil {
		log.Fatalf("%s", err)
	}

	err = policy.ValidateCertificateRequest(enrollReq)
	if err != nil {
		log.Fatalf("%s", err)
	}
	//TODO: policy should be checked on generate request, but it don't
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

	fmt.Printf("\nCertificate:\n%s\nPkey:\n%s\nChain:\n%s\n", pcc.Certificate, pcc.PrivateKey, pcc.Chain)
	f := fmt.Sprintf("%s.bundle.json", u.Host)
	log.Println("Writing PCC to ", f)
	err = ioutil.WriteFile(f, []byte(dumpPCC(pcc)), 0644)
	if err != nil {
		log.Fatalf("%s", err)
	}
}

func verifyWorkloadCert(pcc certificate.PEMCollection, trustDomainCAPath string) {
	svid, err := pemCollectionTOCVID(pcc, trustDomainCAPath)
	if err != nil {
		log.Fatalf("%s", err)
	}
	log.Printf("Verifying workload %s signed by %s", svid.SPIFFEID, svid.Certificates[0].Issuer)

	s, err := url.Parse(svid.SPIFFEID)
	if err != nil {
		log.Fatalf("%s", err)
	}

	root := s.Scheme + "://" + s.Host
	log.Println("Verifying for root", root)
	roots := map[string]*x509.CertPool{
		root: svid.TrustBundlePool,
	}

	//We think that writing SPIFFE ID to CA's URI is a good practice, because with it
	//we can verify SPIFFEID with ExpctedPeer
	var verifiedChains [][]*x509.Certificate

	if len(svid.TrustBundle[0].URIs) > 0 {
		expectedPeer := fmt.Sprintf("%s%s", svid.TrustBundle[0].URIs[0], s.Path)
		log.Println("Expecting workload have peer ID", expectedPeer)
		verifiedChains, err = spiffe.VerifyPeerCertificate(svid.Certificates, roots, spiffe.ExpectPeer(expectedPeer))
		if err != nil {
			log.Fatalf("%s", err)
		}
	} else {
		log.Println("WARNING: No SPIFFE URI found in CA")
		verifiedChains, err = spiffe.VerifyPeerCertificate(svid.Certificates, roots, spiffe.ExpectAnyPeer())
		if err != nil {
			log.Fatalf("%s", err)
		}
	}

	log.Println("Workload certificate verified", verifiedChains[0][0].URIs)
}

func pemCollectionTOCVID(collection certificate.PEMCollection, trustDomainFile string) (svid workload.X509SVID, err error) {
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
	log.Printf("Loading CA from file %s", trustDomainFile)
	CACertPem, err := ioutil.ReadFile(trustDomainFile)
	if err != nil {
		return
	}
	p, _ = pem.Decode([]byte(CACertPem))
	cert, _ = x509.ParseCertificate(p.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	svid.TrustBundle = []*x509.Certificate{cert}
	svid.TrustBundlePool = pool
	return
}

var dumpPCC = func(a interface{}) string {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		log.Fatalf("%s", err)
	}
	return string(b)
}
