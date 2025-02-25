build:
	cd ./spiffe-client; env GOOS=linux GOARCH=amd64 go build -o ../bin/spiffe-client ./
	cd ./faketpp; env GOOS=linux GOARCH=amd64 go build -o ../bin/faketpp ./

runtpp:
	./bin/faketpp -policy=faketpp/policies/policy-example.json

cert1:
	./bin/spiffe-client -command enroll -uri spiffe://trust1.domain/workload1 -zone trust1
	./bin/spiffe-client -command validate -path trust1.domain.bundle.json -trustDomainCAPath cert_db/trust1.domain.crt

cert2:
	./bin/spiffe-client -command enroll -uri spiffe://trust2.domain/workload2 -zone trust2
	./bin/spiffe-client -command validate -path trust2.domain.bundle.json -trustDomainCAPath cert_db/trust2.domain.crt

cert3:
	./bin/spiffe-client -command enroll -uri spiffe://trust3.domain/workload2 -zone trust3
	./bin/spiffe-client -command validate -path trust3.domain.bundle.json -trustDomainCAPath cert_db/trust3.domain.crt

cert_bad_policy:
	./bin/spiffe-client -command enroll -uri spiffe://wrong-trust.domain/workload2 -zone trust2

cert_bad_root:
	./bin/spiffe-client -command enroll -uri spiffe://trust-wrong.domain/workload2 -zone trust1
	./bin/spiffe-client -command validate -path trust-wrong.domain.bundle.json -trustDomainCAPath cert_db/trust2.domain.crt

cert_bad_root_id:
	./bin/spiffe-client -command enroll -uri spiffe://trust-wrong.domain/workload2 -zone trust2
	./bin/spiffe-client -command validate -path trust-wrong.domain.bundle.json -trustDomainCAPath cert_db/trust2.domain.crt

sign_intermediate_ca:
	./bin/spiffe-client -command sign -zone ca-trust -path cert_db/trust4.domain_csr.pem
	jq .Certificate cert_db/trust4.domain_csr.pem.bundle.json |xargs echo -e > cert_db/trust4.domain.crt

cert_intermediate_ca:
	./bin/spiffe-client -command enroll -uri spiffe://trust4.domain/workload2 -zone trust4
	./bin/spiffe-client -command validate -path trust4.domain.bundle.json -trustDomainCAPath cert_db/trust4.domain.crt