// This is a separate module on purpose. The oracle tests need a third party RFC 6962
// implementation to check against, and merkletree itself has no dependencies and is
// meant to keep it that way. A nested module is excluded from the parent's package
// list, so `go build ./...` and `go test ./...` at the root neither see this directory
// nor acquire anything it requires.
module github.com/cbergoon/merkletree/oracle

go 1.21

// The oracle always tests the working tree it sits in, never a published version.
replace github.com/cbergoon/merkletree => ../

require (
	github.com/cbergoon/merkletree v0.0.0-00010101000000-000000000000
	github.com/transparency-dev/merkle v0.0.2
)
