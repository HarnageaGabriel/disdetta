# Third-party licenses

disdetta is distributed under Apache-2.0 (see [LICENSE](../LICENSE)). Some of
the code it depends on is under other licenses, and several of those licenses
require the license text to be reproduced in the distribution. This directory
holds those texts, copied verbatim.

Only the direct dependencies listed in [go.mod](../go.mod) are covered here.
Indirect dependencies are listed in go.mod and pinned in go.sum; their texts
are not reproduced here. This directory complements the
[NOTICE](../NOTICE) file at the root of the repository.

## Direct dependencies

| Module | Version | SPDX license | File |
| --- | --- | --- | --- |
| github.com/hashicorp/hcl/v2 | v2.25.0 | MPL-2.0 | [github.com-hashicorp-hcl-v2-MPL-2.0.txt](github.com-hashicorp-hcl-v2-MPL-2.0.txt) |
| github.com/santhosh-tekuri/jsonschema/v6 | v6.0.2 | Apache-2.0 | [github.com-santhosh-tekuri-jsonschema-v6-Apache-2.0.txt](github.com-santhosh-tekuri-jsonschema-v6-Apache-2.0.txt) |
| github.com/spf13/cobra | v1.10.2 | Apache-2.0 | [github.com-spf13-cobra-Apache-2.0.txt](github.com-spf13-cobra-Apache-2.0.txt) |
| github.com/zclconf/go-cty | v1.19.0 | MIT | [github.com-zclconf-go-cty-MIT.txt](github.com-zclconf-go-cty-MIT.txt) |
| gopkg.in/yaml.v3 | v3.0.1 | MIT OR Apache-2.0 | [gopkg.in-yaml.v3-MIT-OR-Apache-2.0.txt](gopkg.in-yaml.v3-MIT-OR-Apache-2.0.txt) |
| k8s.io/api | v0.37.1 | Apache-2.0 | [k8s.io-api-Apache-2.0.txt](k8s.io-api-Apache-2.0.txt) |
| k8s.io/apimachinery | v0.37.1 | Apache-2.0 | [k8s.io-apimachinery-Apache-2.0.txt](k8s.io-apimachinery-Apache-2.0.txt) |
| k8s.io/client-go | v0.37.1 | Apache-2.0 | [k8s.io-client-go-Apache-2.0.txt](k8s.io-client-go-Apache-2.0.txt) |

gopkg.in/yaml.v3 is dual licensed, and its LICENSE file contains the text of
both licenses. Its NOTICE file is reproduced in
[gopkg.in-yaml.v3-NOTICE.txt](gopkg.in-yaml.v3-NOTICE.txt).

## How the texts were collected

Each file is a byte-for-byte copy of the license file shipped inside the
module, taken from the local module cache:

```sh
go env GOMODCACHE
go list -m all
```

The cache directory of a dependency is printed by:

```sh
go list -m -f '{{.Path}} {{.Version}} {{.Dir}}' github.com/spf13/cobra
```

File names follow the pattern
`<module-path-with-slashes-replaced-by-dashes>-<SPDX-license>.txt`.

## Updating

When a dependency version changes, check the license of the new version in the
module cache, copy the new license text into this directory, and update the
table above.
