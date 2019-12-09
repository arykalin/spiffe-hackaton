# spiffe-hackaton
We want to understand how SPIFFE works and what problems and possible integrations 
have applications like Consul Connect or Istio Citadel.

Stack: Go language, Kubernetes, Istio/Consul/Spire sources to understand how it works.

## Goals:
1. CA which can sign X.509 SVID.
1. Kubernetes sidecar container (resource) which will request X.509 SVID certificate from CA.
1. Validate call  from resoure using it's x.509 SVID on another service (authentication).
1. Check that authenticated resource can perform read\write\delete action (authorization)

## Detailed tasks
### CA which can sign X.509 SVID.
1. Emulate TPP API to request x.509 SVID
1. Make Go code to sign x.509 SVID
    1. Create a signing certificate with proper SVID : A signing certificate SHOULD itself be an SVID. 
    If present, the SPIFFE ID of a signing certificate MUST NOT have a path component, and MAY reside in the 
    trust domain of any leaf SVIDs it issues. A signing certificate MAY be used to issue further signing 
    certificates in the same or different trust domains.

### Kubernetes sidecar container (resource) which will request X.509 SVID certificate from CA.
1. Use vcert as basic signing tool. Make a method for requesting x.509 SVID
1. Determine POD environment.
1. Write and example POD with sidecar for testing requests.

### Validate call  from resoure using it's x.509 SVID on another service (authentication).
1. Write a simple web server which can recieve POST\GET\DELETE.
1. Recieve request from resource and validate it's SVID
1. Make secure MTLS connection.

### Check that authenticated resource can perform read\write\delete action (authorization)
1. Decide how we will perform policy check. Policy inside x509 or external resource?
1. Check recieved request x.509 SVID and allow\reject action based on policy. 

## General thoughts
1. SPIFFE is a set of standards for multi platform workload authentication.
1. SPIFFE have many implementations: SPIRE, Istio security, Consul-connect, ghostunnel etc.
1. Main thing used for workload authentication is an x.509 certificate with SAN URI extension set to workload identifier. 
    Example: `spiffe://example.com/worload/id`  
1. To validate certificate SPIFFE use workload API which should provide root trust bundle by client request
1. Workload API is a server which have a registry of records like `spiffe://example.com/worload/pay` with selector conditionals
    which should be met in workload to give a certificate to it (node attestation).
1. Usually you have a SPIFFE agent running on workload which executes a set of accestors to properly identify the node.
1. SPIFFE is not for authorization and transport level security. Fundamentally SPIFFE is about identity.
1. Certificate expiration date should be similar to workload living time. I.E. if workload is docker worker it should not more than a day.
    And if it is a database it may be a month.

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

## Integration scenarios:
1. Workload API is requesting intermediate CA from TPP\Cloud via vcert
1. Vcert is runnning on Workload API part and monitor certificates against TPP\Cloud policies
1. Workload request leaf (client) certificates from TPP\Cloud via vcert

##Usage examples:

1. build application run `make build`
1. start fake TPP server `./bin/faketpp -policy=faketpp/policies/policy-example.json`
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
    
### More examples in asciinema video
 
[![asciicast](https://asciinema.org/a/nyk8QGYzftnytSK88rxtKsMIK.svg)](https://asciinema.org/a/vmo1iE4fj3bDQFOByCSVH5h4D)

[1]: https://tools.ietf.org/html/rfc5280#section-4.2.1.
[2]: https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md#4-constraints-and-usage