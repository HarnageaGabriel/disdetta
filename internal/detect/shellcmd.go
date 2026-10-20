package detect

import (
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/catalog"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/imageref"
	"gopkg.in/yaml.v3"
)

// shellOrigin is where a script string starts in the file: the one-based line
// and column of its first character, and the indentation its later lines keep
// in the file. A YAML block scalar keeps its content indentation, so every
// token of the block is shifted by it (spec 9.2).
type shellOrigin struct {
	line, column, indent int
}

// shellScriptValue is one script string with the one-based location from which
// tokenizer offsets are resolved.
type shellScriptValue struct {
	value  string
	origin shellOrigin
	// node is the YAML scalar the script came from, when it came from one.
	node *yaml.Node
}

type shellTokenKind uint8

const (
	shellWord shellTokenKind = iota
	shellSeparator
)

type shellToken struct {
	value        string
	kind         shellTokenKind
	line, column int
}

// shellHeredoc is a pending heredoc body. Bodies are input data, never command
// text, so the tokenizer skips them before command classification.
type shellHeredoc struct {
	name string
	dash bool
}

// scanShellScripts visits only the CI script keys named by spec section 9.2.
func (s *walkState) scanShellScripts(root *yaml.Node) {
	keys := shellScriptKeys(s.path)
	if len(keys) == 0 {
		return
	}
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	scan := &shellScriptScan{data: s.data, allowed: allowed, seen: map[*yaml.Node]bool{}}
	scan.collect(root, "", 0)
	if len(scan.scripts) == 0 {
		return
	}
	if s.shellScriptNodes == nil {
		s.shellScriptNodes = map[*yaml.Node]bool{}
	}
	// Only the script scalars the shell detector handled are marked: any other
	// scalar of the same CI file still falls back to the whole-scalar rule
	// (spec section 9).
	for _, script := range scan.scripts {
		if script.node != nil {
			s.shellScriptNodes[script.node] = true
		}
	}
	s.scanShellValues(scan.scripts)
}

// shellScriptScan collects the script scalars of one CI file.
type shellScriptScan struct {
	data    []byte
	allowed map[string]bool
	seen    map[*yaml.Node]bool
	scripts []shellScriptValue
}

// collect walks the document and keeps the scalars whose key is a CI script
// key. The walk never evaluates the document: only the key names decide.
func (c *shellScriptScan) collect(n *yaml.Node, key string, depth int) {
	if n == nil || depth > maxYAMLDepth || c.seen[n] {
		return
	}
	c.seen[n] = true
	if n.Kind == yaml.AliasNode {
		c.collect(n.Alias, key, depth+1)
		return
	}
	if c.allowed[key] {
		switch n.Kind {
		case yaml.ScalarNode:
			c.add(n)
			return
		case yaml.SequenceNode:
			for _, child := range n.Content {
				if child.Kind == yaml.ScalarNode && !c.seen[child] {
					c.seen[child] = true
					c.add(child)
				}
			}
			return
		}
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			c.collect(n.Content[i+1], n.Content[i].Value, depth+1)
		}
	case yaml.SequenceNode:
		for _, child := range n.Content {
			c.collect(child, key, depth+1)
		}
	}
}

// add keeps one script scalar and the node it came from.
func (c *shellScriptScan) add(n *yaml.Node) {
	c.scripts = append(c.scripts, shellScriptValue{value: n.Value, origin: c.origin(n), node: n})
}

// origin resolves where a script scalar starts in the file. A block scalar
// starts on its first content line, at the column where that content begins,
// not at the column of its | or > indicator (spec 9.2). A quoted scalar
// starts at its opening quote.
func (c *shellScriptScan) origin(n *yaml.Node) shellOrigin {
	switch n.Style {
	case yaml.LiteralStyle, yaml.FoldedStyle:
		indent := blockContentIndent(c.data, n.Line)
		return shellOrigin{line: n.Line + 1, column: indent + 1, indent: indent}
	case yaml.SingleQuotedStyle, yaml.DoubleQuotedStyle:
		return shellOrigin{line: n.Line, column: n.Column + 1}
	default:
		return shellOrigin{line: n.Line, column: n.Column}
	}
}

// blockContentIndent returns the zero-based indentation of the content lines
// of the block scalar whose indicator is on the given line. It is the column
// where the block text starts in the file, not the indicator column.
func blockContentIndent(data []byte, indicatorLine int) int {
	line := 1
	start := 0
	for i := 0; i <= len(data); i++ {
		if i < len(data) && data[i] != '\n' {
			continue
		}
		if line > indicatorLine {
			end := i
			for end > start && data[end-1] == '\r' {
				end--
			}
			j := start
			for j < end && data[j] == ' ' {
				j++
			}
			if j < end {
				return j - start
			}
		}
		line++
		start = i + 1
	}
	return 0
}

// scanShellValues performs a file-wide alias prepass and then reports findings.
// Helm aliases are proof from the same file, independent of script order.
func (s *walkState) scanShellValues(scripts []shellScriptValue) {
	if len(scripts) == 0 {
		return
	}
	aliases := map[string]bool{}
	for _, script := range scripts {
		_, declared := shellCommandFindings(s.path, script.value, script.origin, aliases)
		for alias := range declared {
			aliases[alias] = true
		}
	}
	for _, script := range scripts {
		findings, _ := shellCommandFindings(s.path, script.value, script.origin, aliases)
		s.out.Findings = appendShellFindings(s.out.Findings, findings)
	}
}

func shellScriptKeys(path string) []string {
	switch {
	case isActions(path):
		return []string{"run"}
	case isGitLab(strings.ToLower(filepathBase(path))):
		return []string{"script", "before_script"}
	case isAzure(strings.ToLower(filepathBase(path))):
		return []string{"script", "bash", "pwsh"}
	default:
		return nil
	}
}

func filepathBase(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// shellCommandFindings is the pure spec-9.2 analyzer over one script string.
// It neither expands variables nor evaluates substitutions, and it returns only
// redacted references or URLs. The returned aliases are Bitnami repositories
// declared by helm repo add in this script.
func shellCommandFindings(path, script string, origin shellOrigin, aliases map[string]bool) ([]diag.Finding, map[string]bool) {
	tokens := tokenizeShell(script)
	groups := shellCommandGroups(tokens)
	declared := map[string]bool{}
	for _, group := range groups {
		if alias, _, ok := helmRepoAdd(group); ok {
			declared[alias] = true
		}
	}
	effective := make(map[string]bool, len(aliases)+len(declared))
	for alias := range aliases {
		effective[alias] = true
	}
	for alias := range declared {
		effective[alias] = true
	}

	var findings []diag.Finding
	seen := map[string]bool{}
	add := func(f diag.Finding) {
		key := shellFindingKey(f)
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, f)
	}
	for _, group := range groups {
		for _, f := range shellGroupFindings(path, group, origin, effective) {
			add(f)
		}
	}
	return findings, declared
}

func shellFindingKey(f diag.Finding) string {
	return f.Location.Path + "\x00" + itoa(f.Location.Line) + "\x00" + f.RuleID + "\x00" + f.Reference
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	negative := v < 0
	if negative {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func appendShellFindings(dst, incoming []diag.Finding) []diag.Finding {
	seen := make(map[string]bool, len(dst)+len(incoming))
	for _, f := range dst {
		seen[shellFindingKey(f)] = true
	}
	for _, f := range incoming {
		key := shellFindingKey(f)
		if seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, f)
	}
	return dst
}

func shellCommandGroups(tokens []shellToken) [][]shellToken {
	var groups [][]shellToken
	var current []shellToken
	for _, token := range tokens {
		if token.kind == shellSeparator {
			if len(current) > 0 {
				groups = append(groups, current)
				current = nil
			}
			continue
		}
		current = append(current, token)
	}
	if len(current) > 0 {
		groups = append(groups, current)
	}
	return groups
}

func shellGroupFindings(path string, group []shellToken, origin shellOrigin, aliases map[string]bool) []diag.Finding {
	if len(group) == 0 {
		return nil
	}
	command := strings.ToLower(group[0].value)
	switch command {
	case "echo", "printf":
		return nil
	case "docker", "podman", "nerdctl", "buildx", "kubectl":
		return shellDockerFindings(path, group, origin)
	case "helm":
		return shellHelmFindings(path, group, origin, aliases)
	default:
		return nil
	}
}

func shellDockerFindings(path string, group []shellToken, origin shellOrigin) []diag.Finding {
	args := group[1:]
	if len(args) == 0 {
		return nil
	}
	index := 0
	command := strings.ToLower(group[0].value)
	if command == "docker" && strings.EqualFold(args[0].value, "buildx") {
		index = 1
		if len(args) <= index {
			return nil
		}
	}
	operation := strings.ToLower(args[index].value)
	args = args[index+1:]
	if command == "buildx" || command == "kubectl" {
		if operation != "run" && operation != "build" {
			return nil
		}
	} else {
		switch operation {
		case "run", "create", "pull", "exec", "build":
		default:
			return nil
		}
	}

	if operation == "build" {
		for i := 0; i < len(args); i++ {
			if args[i].value == "--from" && i+1 < len(args) {
				if f := shellImageFinding(path, args[i+1], origin); f != nil {
					return []diag.Finding{*f}
				}
				return nil
			}
			if strings.HasPrefix(args[i].value, "--from=") {
				token := args[i]
				token.value = strings.TrimPrefix(token.value, "--from=")
				if f := shellImageFinding(path, token, origin); f != nil {
					return []diag.Finding{*f}
				}
				return nil
			}
		}
	}

	for i := 0; i < len(args); i++ {
		if args[i].value == "--image" && i+1 < len(args) {
			if f := shellImageFinding(path, args[i+1], origin); f != nil {
				return []diag.Finding{*f}
			}
			return nil
		}
		if strings.HasPrefix(args[i].value, "--image=") {
			token := args[i]
			token.value = strings.TrimPrefix(token.value, "--image=")
			if f := shellImageFinding(path, token, origin); f != nil {
				return []diag.Finding{*f}
			}
			return nil
		}
	}
	if command == "buildx" || command == "kubectl" || operation == "build" {
		return nil
	}

	for i := 0; i < len(args); {
		token := args[i]
		if strings.HasPrefix(token.value, "-") && token.value != "-" {
			if shellDockerTakesValue(operation, token.value) {
				i += 2
			} else {
				// An unknown option is skipped by itself; its following token
				// remains eligible, and is never consumed speculatively.
				i++
			}
			continue
		}
		if f := shellImageFinding(path, token, origin); f != nil {
			return []diag.Finding{*f}
		}
		return nil
	}
	return nil
}

// shellDockerTakesValue reports whether an option consumes the next token as
// its value. The arity depends on the subcommand: -t is a tag for build and a
// boolean for run, so an option is never consumed speculatively (spec 9.2).
func shellDockerTakesValue(operation, option string) bool {
	switch operation {
	case "exec":
		switch option {
		case "-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir":
			return true
		}
		return false
	case "pull":
		return option == "--platform"
	default:
		switch option {
		case "-v", "--volume", "-e", "--env", "--env-file", "-p", "--publish",
			"--name", "-w", "--workdir", "-u", "--user", "--network",
			"--network-alias", "--entrypoint", "--label", "-l", "--mount",
			"--restart", "--platform", "--pull", "--add-host", "--cpus",
			"--cpuset-cpus", "--cpuset-mems", "--cpu-shares", "--cpu-period",
			"--cpu-quota", "--device", "--device-cgroup-rule", "--dns",
			"--dns-option", "--dns-search", "--gpus", "--group-add",
			"--health-cmd", "--health-interval", "--health-retries",
			"--health-timeout", "--ipc", "--kernel-memory", "--log-driver",
			"--log-opt", "--memory", "--memory-reservation", "--memory-swap",
			"--pid", "--runtime", "--shm-size", "--storage-opt", "--sysctl",
			"--tmpfs", "--ulimit", "--userns", "--uts", "--annotation",
			"--attach", "--blkio-weight", "--cap-add", "--cap-drop",
			"--cgroup-parent", "--cidfile", "--expose", "--hostname", "-h",
			"--link", "--link-local-ip", "--mac-address", "--oom-score-adj",
			"--pids-limit", "--security-opt", "--stop-signal",
			"--stop-timeout", "--volumes-from":
			return true
		}
		return false
	}
}

func shellImageFinding(path string, token shellToken, origin shellOrigin) *diag.Finding {
	r := imageref.Parse(token.value)
	class, ok, _ := ClassifyReference(r, false, true)
	if !ok {
		return nil
	}
	return &diag.Finding{
		RuleID:     class.Rule,
		Severity:   class.Severity,
		Confidence: class.Confidence,
		Impact:     class.Impact,
		Component:  class.Component,
		Location:   shellTokenLocation(path, token, origin),
		Reference:  class.Reference,
		Original:   class.Original,
		Attributes: class.Attributes,
	}
}

func shellHelmFindings(path string, group []shellToken, origin shellOrigin, aliases map[string]bool) []diag.Finding {
	args := group[1:]
	subcommand, rest, ok := helmSubcommand(args)
	if !ok {
		return nil
	}
	switch subcommand {
	case "repo", "install", "upgrade", "template", "pull":
	default:
		return nil
	}

	if subcommand == "repo" && len(rest) > 0 && strings.EqualFold(rest[0].value, "add") {
		positionals := shellHelmPositionals(rest[1:])
		if len(positionals) < 2 || !isBitnamiChartSource(positionals[1].value) {
			return nil
		}
		f := shellChartFinding(path, positionals[1], origin, "")
		return []diag.Finding{f}
	}

	findings := shellHelmSetFindings(path, rest, origin)
	switch subcommand {
	case "install", "upgrade", "template", "pull":
	default:
		return findings
	}

	positionals := shellHelmPositionals(rest)
	var chart shellToken
	switch subcommand {
	case "pull":
		// A pull takes the chart as its first positional; there is no release
		// name in front of it (spec 9.2).
		if len(positionals) == 0 {
			return findings
		}
		chart = positionals[0]
	default:
		if len(positionals) < 2 {
			return findings
		}
		chart = positionals[1]
	}
	if f, ok := shellChartTokenFinding(path, chart, origin, aliases); ok {
		findings = append(findings, f)
	}
	return findings
}

// helmRepoAdd returns the alias and the chart source of a `helm repo add`
// command line, when the source is a Bitnami chart source. Global flags
// before the subcommand are skipped (spec 9.2).
func helmRepoAdd(group []shellToken) (string, string, bool) {
	if len(group) == 0 || !strings.EqualFold(group[0].value, "helm") {
		return "", "", false
	}
	subcommand, rest, ok := helmSubcommand(group[1:])
	if !ok || subcommand != "repo" {
		return "", "", false
	}
	if len(rest) == 0 || !strings.EqualFold(rest[0].value, "add") {
		return "", "", false
	}
	positionals := shellHelmPositionals(rest[1:])
	if len(positionals) < 2 || !isBitnamiChartSource(positionals[1].value) {
		return "", "", false
	}
	return positionals[0].value, positionals[1].value, true
}

// helmSubcommand returns the helm subcommand and the tokens after it. The
// global flags that may precede a subcommand are skipped, so
// `helm --namespace x repo add` is still a repo command (spec 9.2).
func helmSubcommand(args []shellToken) (string, []shellToken, bool) {
	for i := 0; i < len(args); i++ {
		token := args[i]
		if strings.HasPrefix(token.value, "-") && token.value != "-" {
			if helmGlobalTakesValue(token.value) {
				i++
			}
			continue
		}
		return strings.ToLower(token.value), args[i+1:], true
	}
	return "", nil, false
}

func shellHelmPositionals(tokens []shellToken) []shellToken {
	var out []shellToken
	for i := 0; i < len(tokens); {
		token := tokens[i]
		if strings.HasPrefix(token.value, "-") && token.value != "-" {
			if helmValueTakesValue(token.value) {
				i += 2
			} else {
				i++
			}
			continue
		}
		out = append(out, token)
		i++
	}
	return out
}

// helmGlobalTakesValue reports whether a helm global flag consumes the next
// token as its value (https://helm.sh/docs/helm/).
func helmGlobalTakesValue(option string) bool {
	switch option {
	case "-n", "--namespace", "--kube-context", "--kubeconfig",
		"--registry-config", "--repository-config", "--burst-limit", "--qps":
		return true
	default:
		return false
	}
}

// helmValueTakesValue reports whether a helm option consumes the next token
// as its value. A value-taking flag is never skipped by itself, so the chart
// behind it is still found (spec 9.2).
func helmValueTakesValue(option string) bool {
	switch option {
	case "-f", "--values", "--set", "--set-string", "--set-file", "--set-json",
		"--set-literal", "--version", "--repo", "--certificate-file",
		"--key-file", "--ca-file", "--username", "--password", "--timeout",
		"--description", "--destination", "--output", "--show-only",
		"--labels", "--post-renderer", "--post-renderer-args", "--take-ownership":
		return true
	default:
		return helmGlobalTakesValue(option)
	}
}

func shellHelmSetFindings(path string, tokens []shellToken, origin shellOrigin) []diag.Finding {
	var findings []diag.Finding
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		var assignments string
		locationToken := token
		switch {
		case token.value == "--set":
			if i+1 >= len(tokens) {
				continue
			}
			i++
			assignments = tokens[i].value
			locationToken = tokens[i]
		case strings.HasPrefix(token.value, "--set="):
			assignments = strings.TrimPrefix(token.value, "--set=")
		default:
			continue
		}
		for _, assignment := range strings.Split(assignments, ",") {
			name, value, ok := strings.Cut(assignment, "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(name) {
			case "image.repository":
				r := imageref.Parse(strings.TrimSpace(value))
				class, reportable, _ := ClassifyReference(r, false, true)
				if reportable && class.Rule == "DSD-IMG-001" {
					findings = append(findings, diag.Finding{
						RuleID: class.Rule, Severity: class.Severity,
						Confidence: diag.ConfidenceInferred, Impact: class.Impact,
						Component: class.Component,
						Location:  shellTokenLocation(path, locationToken, origin),
						Reference: class.Reference, Original: class.Original,
						Attributes: class.Attributes,
					})
				}
			case "global.security.allowInsecureImages":
				if strings.EqualFold(strings.TrimSpace(value), "true") {
					findings = append(findings, diag.Finding{
						RuleID: "DSD-CFG-001", Severity: diag.SeverityHigh,
						Confidence: diag.ConfidenceInferred, Impact: diag.ImpactUnknown,
						Location:  shellTokenLocation(path, locationToken, origin),
						Reference: "true", Original: "true", Attributes: []string{},
					})
				}
			}
		}
	}
	return findings
}

func shellChartTokenFinding(path string, token shellToken, origin shellOrigin, aliases map[string]bool) (diag.Finding, bool) {
	reference := strings.TrimSpace(token.value)
	if shellIsBitnamiOCIChart(reference) {
		return shellChartFinding(path, token, origin, shellChartComponent(reference)), true
	}
	alias, chart, ok := strings.Cut(reference, "/")
	if !ok || alias == "" || chart == "" || !aliases[alias] {
		return diag.Finding{}, false
	}
	return shellChartFinding(path, token, origin, shellChartComponent(reference)), true
}

func shellIsBitnamiOCIChart(reference string) bool {
	lower := strings.ToLower(reference)
	for _, base := range bitnamiChartURLs {
		if strings.HasPrefix(lower, strings.ToLower(base)+"/") && len(reference) > len(base)+1 {
			return true
		}
	}
	return false
}

func shellChartComponent(reference string) string {
	if i := strings.IndexByte(reference, '@'); i >= 0 {
		reference = reference[:i]
	}
	if i := strings.LastIndexByte(reference, '/'); i >= 0 {
		reference = reference[i+1:]
	}
	return strings.ToLower(strings.Trim(reference, ":@/"))
}

func shellChartFinding(path string, token shellToken, origin shellOrigin, component string) diag.Finding {
	reference := strings.TrimSpace(token.value)
	impact := diag.ImpactUnknown
	if component != "" {
		impact = catalog.Impact(component)
	}
	return diag.Finding{
		RuleID: "DSD-CHT-001", Severity: diag.SeverityMedium,
		Confidence: diag.ConfidenceInferred, Impact: impact,
		Component: component,
		Location:  shellTokenLocation(path, token, origin),
		Reference: reference, Original: reference,
		Attributes: []string{"chart"},
	}
}

// shellTokenLocation resolves a token position in the file. The first line of
// a script string starts at its origin column; the later lines keep the
// indentation the origin declares.
func shellTokenLocation(path string, token shellToken, origin shellOrigin) diag.Location {
	line := origin.line + token.line - 1
	column := token.column + origin.indent
	if token.line == 1 {
		column = origin.column + token.column - 1
	}
	return loc(path, line, column)
}

// tokenizeShell is a bounded, non-evaluating POSIX-like tokenizer. It handles
// quotes, escapes, continuations, command separators, substitutions, comments,
// and heredocs while preserving one-based token positions.
func tokenizeShell(script string) []shellToken {
	if script == "" {
		return nil
	}
	tokens := make([]shellToken, 0, min(len(script)/4+1, 4096))
	var current []byte
	hasCurrent := false
	currentLine, currentColumn := 1, 1
	line, column := 1, 1
	var heredoc *shellHeredoc

	emit := func() {
		if !hasCurrent {
			return
		}
		tokens = append(tokens, shellToken{value: string(current), kind: shellWord, line: currentLine, column: currentColumn})
		current = current[:0]
		hasCurrent = false
	}
	startWord := func() {
		if !hasCurrent {
			hasCurrent = true
			currentLine, currentColumn = line, column
		}
	}
	separator := func(atLine, atColumn int, value string) {
		tokens = append(tokens, shellToken{value: value, kind: shellSeparator, line: atLine, column: atColumn})
	}

	for i := 0; i < len(script); {
		if heredoc != nil {
			i, line = skipShellHeredoc(script, i, line, heredoc)
			column = 1
			continue
		}

		c := script[i]
		switch {
		case c == '\\' && i+1 < len(script) && script[i+1] == '\n':
			i += 2
			line++
			column = 1
		case c == '\\' && i+2 < len(script) && script[i+1] == '\r' && script[i+2] == '\n':
			i += 3
			line++
			column = 1
		case c == '\n':
			emit()
			separator(line, column, "\n")
			i++
			line++
			column = 1
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			emit()
			i++
			column++
		case c == '#' && !hasCurrent:
			for i < len(script) && script[i] != '\n' {
				i++
				column++
			}
		case c == '\'' || c == '"':
			quote := c
			startWord()
			i++
			column++
			for i < len(script) && script[i] != quote {
				if quote == '"' && script[i] == '\\' && i+1 < len(script) {
					if script[i+1] == '\n' {
						i += 2
						line++
						column = 1
						continue
					}
					current = append(current, script[i+1])
					i += 2
					column += 2
					continue
				}
				current = append(current, script[i])
				i++
				column++
			}
			if i < len(script) {
				i++
				column++
			}
		case c == '$' && i+1 < len(script) && script[i+1] == '(':
			emit()
			separator(line, column, "$(")
			openLine, openColumn := line, column
			i, line, column = skipShellSubstitution(script, i+2, line, column)
			separator(openLine, openColumn, ")")
		case c == '`':
			emit()
			separator(line, column, "`")
			openLine, openColumn := line, column
			i, line, column = skipShellBackticks(script, i+1, line, column)
			separator(openLine, openColumn, "`")
		case c == '<' && i+1 < len(script) && script[i+1] == '<' && (i+2 >= len(script) || script[i+2] != '<'):
			emit()
			separator(line, column, "<<")
			name, dash, next := parseShellHeredoc(script, i+2)
			if name != "" {
				heredoc = &shellHeredoc{name: name, dash: dash}
				i = next
				for i < len(script) && script[i] != '\n' {
					i++
					column++
				}
				if i < len(script) {
					separator(line, column, "\n")
					i++
					line++
					column = 1
				}
				continue
			}
			i += 2
			column += 2
		case c == '&' && i+1 < len(script) && script[i+1] == '&':
			emit()
			separator(line, column, "&&")
			i += 2
			column += 2
		case c == '|' && i+1 < len(script) && script[i+1] == '|':
			emit()
			separator(line, column, "||")
			i += 2
			column += 2
		case c == ';' || c == '|':
			emit()
			separator(line, column, string(c))
			i++
			column++
		default:
			startWord()
			current = append(current, c)
			i++
			column++
		}
	}
	emit()
	return tokens
}

func parseShellHeredoc(script string, start int) (string, bool, int) {
	i := start
	dash := false
	if i < len(script) && script[i] == '-' {
		dash = true
		i++
	}
	var quote byte
	if i < len(script) && (script[i] == '\'' || script[i] == '"') {
		quote = script[i]
		i++
	}
	begin := i
	for i < len(script) && script[i] != '\n' && script[i] != ' ' && script[i] != '\t' && script[i] != '\r' {
		if quote != 0 && script[i] == quote {
			i++
			return script[begin : i-1], dash, i
		}
		i++
	}
	if quote != 0 {
		return "", false, start
	}
	return script[begin:i], dash, i
}

func skipShellHeredoc(script string, start, line int, heredoc *shellHeredoc) (int, int) {
	i := start
	for i < len(script) {
		end := strings.IndexByte(script[i:], '\n')
		if end < 0 {
			end = len(script)
		} else {
			end += i
		}
		body := script[i:end]
		if shellHeredocTerminates(body, heredoc) {
			if end < len(script) {
				return end + 1, line + 1
			}
			return len(script), line
		}
		if end >= len(script) {
			return len(script), line
		}
		line++
		i = end + 1
	}
	return i, line
}

func shellHeredocTerminates(line string, heredoc *shellHeredoc) bool {
	line = strings.TrimRight(line, "\r")
	if heredoc.dash {
		line = strings.TrimLeft(line, "\t")
	}
	return line == heredoc.name
}

func skipShellSubstitution(script string, start, line, column int) (int, int, int) {
	depth := 1
	var quote byte
	for i := start; i < len(script); {
		c := script[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(script) {
				i += 2
				column += 2
				continue
			}
			if c == quote {
				quote = 0
			}
			i++
			column++
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			i++
			column++
		case '\n':
			i++
			line++
			column = 1
		case '(':
			depth++
			i++
			column++
		case ')':
			depth--
			i++
			column++
			if depth == 0 {
				return i, line, column
			}
		default:
			i++
			column++
		}
	}
	return len(script), line, column
}

func skipShellBackticks(script string, start, line, column int) (int, int, int) {
	for i := start; i < len(script); {
		if script[i] == '\\' && i+1 < len(script) {
			if script[i+1] == '\n' {
				line++
				column = 1
			} else {
				column += 2
			}
			i += 2
			continue
		}
		if script[i] == '`' {
			return i + 1, line, column
		}
		if script[i] == '\n' {
			line++
			column = 1
		} else {
			column++
		}
		i++
	}
	return len(script), line, column
}
