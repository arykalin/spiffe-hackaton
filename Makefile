build:
	cd ./spiffe-client; env GOOS=linux GOARCH=amd64 go build -o ../bin/spiffe-client ./
	cd ./faketpp; env GOOS=linux GOARCH=amd64 go build -o ../bin/faketpp ./
runtpp:
	./bin/faketpp -policy=faketpp/policy-example.json