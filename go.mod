module github.com/JonasBorgesLM/security-scanner

go 1.25.0

// The `go` directive above is the minimum LANGUAGE version; this is the
// toolchain CI and contributors actually build with. Without it setup-go
// installs exactly 1.25.0, whose standard library carries 31 advisories
// this code reaches — every one already fixed in a later 1.25.x patch.
//
// Pinned exactly, like the govulncheck version in the CI workflow, so the
// gate stays reproducible. When it goes stale the govulncheck step fails
// and says so, which is the bump reminder.
toolchain go1.25.14

require (
	github.com/getkin/kin-openapi v0.146.0
	golang.org/x/time v0.15.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/go-openapi/jsonpointer v0.22.5 // indirect
	github.com/go-openapi/swag/jsonname v0.25.5 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/oasdiff/yaml v0.1.1 // indirect
	github.com/oasdiff/yaml3 v0.0.14 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	golang.org/x/text v0.14.0 // indirect
)
