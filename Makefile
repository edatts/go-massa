test:
	go test $(go list ./... | grep -v "/protos/" ) -v -cover -coverprofile=c.out

generate-protos:
	bash generate-protos.sh

run-examples:
	go run examples/generate-wallet/main.go
	go run examples/send-coins/main.go

cleanup-storage:
	rm ./testStorage/keys/*
	rm ./exampleStorage/keys/*