test:
	go test $(go list ./... | grep -v "/protos/" ) -v -cover -coverprofile=c.out

generate-protos:
	bash generate-protos.sh