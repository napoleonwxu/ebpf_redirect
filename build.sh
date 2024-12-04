BPF_CLANG=clang BPF_CFLAGS="-g -Wall" go generate
CGO_ENABLED=0 go build .
# instead of "CGO_ENABLED=0 go build main.go"