module github.com/sagarc03/stowry-go

go 1.25.5

// v1.0.0 and v1.1.0 were published in error: this module is pre-1.0. Their tags
// have since been deleted from the repository, but proxy.golang.org caches
// module versions permanently, so they stay resolvable through the proxy and
// fail for anyone building with GOPROXY=direct. Retracting them is the only way
// to tell the go command not to select them.
//
// v1.1.1 exists solely to carry these directives - a retraction has to be
// published in a version higher than the versions it retracts - and retracts
// itself, so it is never selected either.
retract (
	[v1.0.0, v1.1.1]
)
