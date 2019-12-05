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
1. SPIFFE is not for authorization and transport level security. Fundamentally SPIFFE is about identity.

## How we can integrate
1. Add support of URI type in the Subject Alternative Name extension (SAN extension, see [RFC 5280 section 4.2.16][2]) to\
    our products policies.
    1. Add same support to vCert SDK
    1. TODO: describe exactly how this support should look like.
    1. Policy example:
    ```json
    SubjAltNameUriRegex: 'spiffe://example.com/*'
    ```    
1. Provide ability to request and manage SPIFFE signing certificates (basically intermediate CAs) via API. Since most of the systems
    which implement SPIFFE have support of exporting external CA we can manage this certificates on TPP\Cloud
1. Provide same ability for leaf (client) certificates


[2]: https://tools.ietf.org/html/rfc5280#section-4.2.1.