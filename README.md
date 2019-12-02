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
