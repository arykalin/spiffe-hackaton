# spiffe-hackaton
We want to understand how SPIFFE works and what problems and possible integrations 
have applications like Consul Connect or Istio Citadel.

Stack: Go language, go-spiffe library, vCert.

## General thoughts
1. SPIFFE is a set of standards for multi platform workload authentication.
1. SPIFFE have many implementations: SPIRE, Istio security, Consul-connect, ghostunnel etc.
1. Main thing used for workload authentication is an x.509 certificate with SAN URI extension set to workload identifier. 
    Example: `spiffe://example.com/worload/id`  
1. Also JWT token can be used for the same goal.
1. To validate certificate SPIFFE use workload API which should provide root trust bundle by client request
1. Workload API is a server which have a registry of records like `spiffe://example.com/worload/pay` with selector conditionals
    which should be met in workload to give a certificate to it (node attestation).
1. Usually you have a SPIFFE agent running on workload which executes a set of accestors to properly identify the node.
1. SPIFFE is not for authorization and transport level security. Fundamentally SPIFFE is about identity.
1. Certificate expiration date should be similar to workload living time. I.E. if workload is docker worker it should not be more than a day.
    And if it is a database it may be a month.
1. TPP and Cloud can be used as high level policy system to check x509 SVIDs. We can use vCert to validate SVID against
    policy and import them if necessary. Also we can use TPP\Cloud for enrolling intermediate SVID CAs.
    
##Project description
1. We tried to emulate TPP server to add URI support to TPP policy
1. We used vCert SDK and added URI to the request and policy validation
1. We used go-spiffe library to validate x509 SVID certificates

###Fake TPP
1. Fake TPP is server which emulates TPP. It support following API endpoints:
    ```
    /vedsdk/certificates/request
    /vedsdk/certificates/retrieve
    /vedsdk/certificates/checkpolicy
    ```
1. Policy can be configured using faketpp/policies/policy-example.json file.
    `SubjAltNameUriRegex` field used for URI regex.

1. You can run server using following command:
    `./bin/faketpp -policy=faketpp/policies/policy-example.json`
    
###Command line client
1. spiffe-client used to enroll, sign and validate SVIDs

##Usage:

1. To build application run `make build`
1. To start fake TPP server `./bin/faketpp -policy=faketpp/policies/policy-example.json`
1. enroll SVID:
    `./bin/spiffe-client -command enroll -uri spiffe://trust1.domain/workload1 -zone trust1`
1. validate SVID:
    `./bin/spiffe-client -command validate -path trust1.domain.bundle.json -trustDomainCAPath cert_db/trust1.domain.crt`
1. sign intermediate CA using pregenerated CSR:
    `./bin/spiffe-client -command sign -zone ca-trust -path cert_db/trust4.domain_csr.pem`    
 
1. copy signed CA pem to the path defined in zone configuration (faketpp/zones/ca-trust.json file):
    `jq .Certificate cert_db/trust4.domain_csr.pem.bundle.json |xargs echo -e > cert_db/trust4.domain.crt`
    
1. Sign SVID with intermediate CA:
    `./bin/spiffe-client -command enroll -uri spiffe://trust4.domain/workload2 -zone trust4`   

##Usage scenarios:
1. Show cert_db/trust1.domain.crt certificate in openssl
    ```
    openssl x509 -in cert_db/trust1.domain.crt -noout -text
    ```
    Look into X509v3 Subject Alternative Name field
    
1. Sign certificate for workload1 in trust domain trust1.domain:
    ```
    cat faketpp/zones/trust1.json
    {
      "CACertPemFile": "cert_db/trust1.domain.crt",
      "CAKeyPemFile": "cert_db/trust1.domain_key.pem",
      "PolicyFile": "faketpp/policies/policy-example.json"
    }
    
    ./bin/spiffe-client -command enroll -uri spiffe://trust1.domain/workload1 -zone trust1
    ./bin/spiffe-client -command validate -path trust1.domain.bundle.json -trustDomainCAPath cert_db/trust1.domain.crt
    ```

1. Sign certificate for workload2 in trust domain trust2.domain. 
    ```
    cat faketpp/zones/trust2.json
    {
      "CACertPemFile": "cert_db/trust2.domain.crt",
      "CAKeyPemFile": "cert_db/trust2.domain_key.pem",
      "PolicyFile": "faketpp/policies/policy-example.json"
    }

	./bin/spiffe-client -command enroll -uri spiffe://trust2.domain/workload2 -zone trust2
	./bin/spiffe-client -command validate -path trust2.domain.bundle.json -trustDomainCAPath cert_db/trust2.domain.crt    
    ```

1. cert_bad_policy:
	./bin/spiffe-client -command enroll -uri spiffe://wrong-trust.domain/workload2 -zone trust2

1. cert_bad_root:
	./bin/spiffe-client -command enroll -uri spiffe://trust-wrong.domain/workload2 -zone trust1
	./bin/spiffe-client -command validate -path trust-wrong.domain.bundle.json -trustDomainCAPath cert_db/trust2.domain.crt

1. cert_bad_root_id:
	./bin/spiffe-client -command enroll -uri spiffe://trust-wrong.domain/workload2 -zone trust2
	./bin/spiffe-client -command validate -path trust-wrong.domain.bundle.json -trustDomainCAPath cert_db/trust2.domain.crt

1. Show cert_db/trust3.domain.crt certificate in openssl
    ```
    openssl x509 -in cert_db/trust3.domain.crt -noout -text
    ```
    Look into X509v3 Subject Alternative Name field
    
1. Sign certificate for workload3 in trust domain trust3.domain. This trust domain CA don't have SAN URI extension.
 It is not necessary but recommended. So we will show warning about. Also you will see that I can sign certificate with
 different trust domain in URI.
	./bin/spiffe-client -command enroll -uri spiffe://trust123.domain/workload2 -zone trust3
	./bin/spiffe-client -command validate -path trust123.domain.bundle.json -trustDomainCAPath cert_db/trust3.domain.crt


1. sign_intermediate_ca:
	./bin/spiffe-client -command sign -zone ca-trust -path cert_db/trust4.domain_csr.pem
	jq .Certificate cert_db/trust4.domain_csr.pem.bundle.json |xargs echo -e > cert_db/trust4.domain.crt

1. cert_intermediate_ca:
	./bin/spiffe-client -command enroll -uri spiffe://trust4.domain/workload2 -zone trust4
	./bin/spiffe-client -command validate -path trust4.domain.bundle.json -trustDomainCAPath cert_db/trust4.domain.crt
	    
### More examples in asciinema video
 
[![asciicast](https://asciinema.org/a/nyk8QGYzftnytSK88rxtKsMIK.svg)](https://asciinema.org/a/nyk8QGYzftnytSK88rxtKsMIK)

[1]: https://tools.ietf.org/html/rfc5280#section-4.2.1.
[2]: https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md#4-constraints-and-usage

     

## How we can integrate
1. Add support of URI type in the Subject Alternative Name extension (SAN extension, see [RFC 5280 section 4.2.16][1]) to\
    our products policies.
    1. Add same support to vCert SDK
    1. TODO: describe exactly how this support should look like.
    1. Policy example:
    ```
     SubjAltNameUriRegex: 'spiffe://example.com/*'
    ```    
1. Provide ability to request and manage SPIFFE signing certificates (basically intermediate CAs) via API. Since most of the systems
    which implement SPIFFE have support of exporting external CA we can manage this certificates on TPP\Cloud.
    TODO: test if we can create a valid SPIFFE signing certificate using TPP.
1. Provide same ability for leaf (client) certificates
1. Check external SPIFFE CA for constraints:
    1. Basic Constraints: pathLenConstraint, and CA field
    1. Name Constraints: URI SAN constraint may be checked by our policies. For examples: 
        ```
        nameConstraints=critical,permitted;
          URIs: spiffe://trust1.domain
          URIs: spiffe://trust2.domain
        nameConstraints=critical,excluded;
          ExcludedURIDomains: spiffe://example.com
          ExcludedURIDomains: spiffe://local
        ```
    1. Also you can look into [X509-SVID constraints-and-usage][2]

## Possible integration scenarios:
1. Workload API is requesting intermediate CA from TPP\Cloud via vcert
1. Vcert is runnning on Workload API part and monitor certificates against TPP\Cloud policies
1. Workload request leaf (client) SVID certificates from TPP\Cloud via vcert

