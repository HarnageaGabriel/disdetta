// Package catalogdata embeds the migration route catalog shipped with disdetta.
package catalogdata

import "embed"

// Routes contains catalog/routes/*.yaml.
//
//go:embed routes/*.yaml
var Routes embed.FS
