// A separate module, so that comparing against five other Merkle tree libraries does
// not put a single dependency into merkletree itself. A nested module is excluded from
// the parent's package list, so `go build ./...` and `go test ./...` at the root neither
// see this directory nor acquire anything it requires.
module github.com/cbergoon/merkletree/benchmarks

go 1.25.0

require (
	github.com/cbergoon/merkletree v0.0.0
	github.com/jvsteiner/merkle v0.0.0-20180127204300-2864125ed95b
	github.com/onrik/gomerkle v1.0.0
	github.com/txaty/go-merkletree v0.2.2
	github.com/wealdtech/go-merkletree v1.0.0
	github.com/xsleonard/go-merkle v1.1.0
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sync v0.5.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

// The comparison always runs against the working tree it sits in, never a published
// version.
replace github.com/cbergoon/merkletree => ../
