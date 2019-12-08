build:
	cd ./spiffe-client; env GOOS=linux GOARCH=amd64 go build -o ../bin/spiffe-client ./
	cd ./faketpp; env GOOS=linux GOARCH=amd64 go build -o ../bin/faketpp ./

runtpp:
	./bin/faketpp -policy=faketpp/policy-example.json

cert1:
	./bin/spiffe-client -command enroll -uri spiffe://trust1.domain/workload1 -zone trust1
	./bin/spiffe-client -command validate -path trust1.domain.bundle.json -trustDomainCAPath cert_db/trust1.domain.crt

cert2:
	./bin/spiffe-client -command enroll -uri spiffe://trust2.domain/workload2 -zone trust2
	./bin/spiffe-client -command validate -path trust1.domain.bundle.json -trustDomainCAPath cert_db/trust2.domain.crt

cert_wrong_domain:
	./bin/spiffe-client -command enroll -uri spiffe://trust1.domain/workload2 -zone trust2