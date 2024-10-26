package payloadpb

// pure-protobuf: go:generate protoc --proto_path=../../java/src/main/proto/ --go_out=. --go_opt=paths=source_relative jscp-protocol.proto

// vtproto: go install github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto@latest
//go:generate protoc --proto_path=../../java/src/main/proto/ --go_out=. --go_opt=paths=source_relative --go-vtproto_out=. --go-vtproto_opt=paths=source_relative,features=marshal+unmarshal+size jscp-protocol.proto
