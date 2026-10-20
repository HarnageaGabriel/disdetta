package detect

import (
	"strings"
	"unicode/utf8"

	"github.com/HarnageaGabriel/disdetta/internal/catalog"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/imageref"
	"gopkg.in/yaml.v3"
)

// shellPos is a one-based position in the source file.
type shellPos struct {
	line, column int
}

// shellOrigin is where a script string starts in the file: the one-based line
// and column of its first character, and the indentation its later lines keep
// in the file. A YAML block scalar keeps its content indentation, so every
// token of the block is shifted by it (spec 9.2).
type shellOrigin struct {
	line, column, indent int
	// flat marks a scalar whose text keeps no line structure of the source:
	// a plain, single-quoted or double-quoted scalar has no position table,
	// so every one of its tokens is reported on the line of the scalar
	// (spec 9.2).
	flat bool
	// positions maps the offset of every character of the script to its
	// position in the file. A folded block scalar replaces the line breaks of
	// the source by spaces, so the text alone does not tell where a token
	// is: the position table does (spec 9.2). It is empty for the scripts
	// whose text keeps the line structure of the source.
	positions []shellPos
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
	// offset is the offset of the token in the script string, so a position
	// table can resolve it (spec 9.2).
	offset int
}

// shellHeredoc is a pending heredoc body. Bodies are input data, never command
// text, so the tokenizer skips them before command classification.
type shellHeredoc struct {
	name string
	dash bool
}

// shellCIKind names the CI system a file belongs to. The script keys and the
// positions they are read from depend on it (spec 9.2).
type shellCIKind uint8

const (
	shellCIUnknown shellCIKind = iota
	shellCIActions
	shellCIGitLab
	shellCIAzure
)

// gitLabScriptKeys are the keys of a GitLab CI job that hold scripts.
var gitLabScriptKeys = []string{"script", "before_script", "after_script"}

// gitLabReserved are the top-level keys of a GitLab CI file that are not
// jobs.
var gitLabReserved = map[string]bool{
	"image": true, "services": true, "default": true, "stages": true,
	"variables": true, "include": true, "workflow": true, "script": true,
	"before_script": true, "after_script": true,
}

// azureScriptKeys are the keys of an Azure Pipelines step that hold a script.
var azureScriptKeys = []string{"script", "bash", "powershell", "pwsh"}

// scanShellScripts visits only the CI script keys named by spec section 9.2.
func (s *walkState) scanShellScripts(root *yaml.Node) {
	kind := shellCIKindOf(s.path)
	if kind == shellCIUnknown {
		return
	}
	scan := &shellScriptScan{data: s.data, kind: kind, seen: map[*yaml.Node]bool{}, visited: map[*yaml.Node]bool{}}
	scan.collect(root)
	if len(scan.scripts) == 0 {
		return
	}
	if s.shellScriptNodes == nil {
		s.shellScriptNodes = map[*yaml.Node]bool{}
	}
	// Every script scalar is marked, so the whole-scalar fallback never
	// reports a script, not even one the tokenizer found nothing in: any
	// other scalar of the same CI file still falls back to the whole-scalar
	// rule (spec sections 9, 9.2).
	for _, script := range scan.scripts {
		if script.node != nil {
			s.shellScriptNodes[script.node] = true
		}
	}
	s.scanShellValues(scan.scripts)
}

// shellCIKindOf returns the CI system a path belongs to, or shellCIUnknown
// when the file carries no CI script.
func shellCIKindOf(path string) shellCIKind {
	base := strings.ToLower(filepathBase(path))
	switch {
	case isActions(path):
		return shellCIActions
	case isGitLab(base):
		return shellCIGitLab
	case isAzure(base):
		return shellCIAzure
	default:
		return shellCIUnknown
	}
}

// shellScriptScan collects the script scalars of one CI file.
type shellScriptScan struct {
	data []byte
	kind shellCIKind
	seen map[*yaml.Node]bool
	// visited holds the nodes the traversal already entered. A node is
	// identified by its address, so an anchor that references itself ends
	// the traversal instead of overflowing the stack (spec section 3).
	visited map[*yaml.Node]bool
	scripts []shellScriptValue
}

// enter marks a node as traversed and reports whether the traversal may go
// on inside it. A node that was already entered is skipped, so a cycle in
// the YAML ends the branch that holds it.
func (c *shellScriptScan) enter(n *yaml.Node) bool {
	if n == nil || c.visited[n] {
		return false
	}
	c.visited[n] = true
	return true
}

// collect keeps the script scalars of the positions the CI system defines
// (spec 9.2): the `run` key of a GitHub Actions step, the `script`,
// `before_script` and `after_script` lists of a GitLab CI job, and the
// `script`, `bash`, `powershell` and `pwsh` keys of an Azure Pipelines step.
// A key with the same name anywhere else, such as a `with` input, is never a
// script.
func (c *shellScriptScan) collect(root *yaml.Node) {
	switch c.kind {
	case shellCIActions:
		c.collectActions(root)
	case shellCIGitLab:
		c.collectGitLab(root)
	case shellCIAzure:
		c.collectAzure(root)
	}
}

// collectActions collects the `run` key of the steps of every job of a
// GitHub Actions workflow.
func (c *shellScriptScan) collectActions(root *yaml.Node) {
	for _, job := range mappingEntries(shellNodeAt(root, "jobs")) {
		c.collectSteps(shellNodeAt(job.value, "steps"), "run")
	}
}

// collectGitLab collects the script lists of the jobs of a GitLab CI file.
func (c *shellScriptScan) collectGitLab(root *yaml.Node) {
	for _, key := range gitLabScriptKeys {
		c.collectScript(shellNodeAt(root, key))
	}
	if def := shellNodeAt(root, "default"); def != nil {
		for _, key := range gitLabScriptKeys {
			c.collectScript(shellNodeAt(def, key))
		}
	}
	for _, job := range mappingEntries(root) {
		if gitLabReserved[job.key] {
			continue
		}
		value := shellResolvedNode(job.value)
		if value == nil || value.Kind != yaml.MappingNode {
			continue
		}
		for _, key := range gitLabScriptKeys {
			c.collectScript(shellNodeAt(value, key))
		}
	}
}

// shellNodeAt returns the node at the given path of a mapping. A merge key
// (`<<`) is resolved: the value of the merged mapping is returned as it is,
// so its position stays the position of its anchor and the same node is
// always the same node (spec section 5).
func shellNodeAt(n *yaml.Node, path ...string) *yaml.Node {
	for _, p := range path {
		if n == nil {
			return nil
		}
		n = shellMappingLookup(n, p, map[*yaml.Node]bool{}, 0)
	}
	return n
}

// shellMappingLookup returns the value node of a key of a mapping. An alias
// is resolved, and a merge key (`<<`) is looked up in the merged mapping. The
// node is returned as it is: it keeps the address and the position of its
// anchor, so an alias and its anchor are one reference (spec section 5). The
// seen set and the depth bound end a cycle in the YAML (spec section 3).
func shellMappingLookup(n *yaml.Node, key string, seen map[*yaml.Node]bool, depth int) *yaml.Node {
	if n == nil || depth > maxYAMLDepth || seen[n] {
		return nil
	}
	seen[n] = true
	defer delete(seen, n)
	if n.Kind == yaml.AliasNode {
		return shellMappingLookup(n.Alias, key, seen, depth+1)
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value != "<<" {
			continue
		}
		merge := n.Content[i+1]
		candidates := []*yaml.Node{merge}
		if merge.Kind == yaml.SequenceNode {
			candidates = merge.Content
		}
		for _, candidate := range candidates {
			if found := shellMappingLookup(candidate, key, seen, depth+1); found != nil {
				return found
			}
		}
	}
	return nil
}

// shellResolvedNode resolves an alias node to the node it points at.
func shellResolvedNode(n *yaml.Node) *yaml.Node {
	for depth := 0; n != nil && n.Kind == yaml.AliasNode && depth < maxYAMLDepth; depth++ {
		n = n.Alias
	}
	return n
}

// collectAzure collects the scripts of the steps of an Azure Pipelines file.
// A standard pipeline nests its steps in stages and jobs, so every level is
// traversed (spec 9.2).
func (c *shellScriptScan) collectAzure(root *yaml.Node) {
	c.collectSteps(shellNodeAt(root, "steps"), azureScriptKeys...)
	c.collectAzureJobs(root, 0)
	for _, stage := range shellSequenceAt(root, "stages") {
		if !c.enter(stage) {
			continue
		}
		c.collectAzureJobs(stage, 0)
	}
}

// collectAzureJobs collects the steps of the jobs of one level of a pipeline.
// A job that references itself is entered once, so a cycle in the YAML ends
// the traversal instead of overflowing the stack (spec section 3).
func (c *shellScriptScan) collectAzureJobs(node *yaml.Node, depth int) {
	if depth > maxYAMLDepth {
		return
	}
	for _, job := range shellSequenceAt(node, "jobs") {
		if !c.enter(job) {
			continue
		}
		c.collectSteps(shellNodeAt(job, "steps"), azureScriptKeys...)
		c.collectAzureJobs(job, depth+1)
	}
}

// collectSteps collects the given script keys of the items of a steps list.
// Only a key of the step itself is a script, never a key of an input. An
// alias to a steps list or to a step is resolved (spec 9.2).
func (c *shellScriptScan) collectSteps(steps *yaml.Node, keys ...string) {
	steps = shellResolvedNode(steps)
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return
	}
	if !c.enter(steps) {
		return
	}
	for _, item := range steps.Content {
		item = shellResolvedNode(item)
		if item == nil || item.Kind != yaml.MappingNode {
			continue
		}
		for _, key := range keys {
			c.collectScript(shellNodeAt(item, key))
		}
	}
}

// collectScript keeps the script scalars of a script key: the items of a
// list, or the scalar itself. An alias to a script is resolved (spec 9.2).
func (c *shellScriptScan) collectScript(n *yaml.Node) {
	n = shellResolvedNode(n)
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.ScalarNode:
		c.add(n)
	case yaml.SequenceNode:
		for _, item := range n.Content {
			item = shellResolvedNode(item)
			if item != nil && item.Kind == yaml.ScalarNode {
				c.add(item)
			}
		}
	}
}

// shellSequenceAt returns the items of the sequence at the given path. An
// alias to a sequence is resolved (spec 9.2).
func shellSequenceAt(n *yaml.Node, path ...string) []*yaml.Node {
	resolved := shellResolvedNode(shellNodeAt(n, path...))
	if resolved != nil && resolved.Kind == yaml.SequenceNode {
		return resolved.Content
	}
	return nil
}

// mappingEntry is one key and value of a mapping.
type mappingEntry struct {
	key   string
	value *yaml.Node
}

// mappingEntries returns the entries of a mapping in document order, so the
// scripts are collected in the order of the file.
func mappingEntries(n *yaml.Node) []mappingEntry {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	out := make([]mappingEntry, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, mappingEntry{key: n.Content[i].Value, value: n.Content[i+1]})
	}
	return out
}

// add keeps one script scalar and the node it came from.
func (c *shellScriptScan) add(n *yaml.Node) {
	if c.seen[n] {
		return
	}
	c.seen[n] = true
	value, positions := n.Value, []shellPos(nil)
	if n.Style == yaml.LiteralStyle || n.Style == yaml.FoldedStyle {
		if text, table, ok := c.blockContent(n); ok && text == n.Value {
			value, positions = text, table
		}
	}
	c.scripts = append(c.scripts, shellScriptValue{value: value, origin: c.origin(n, positions), node: n})
}

// origin resolves where a script scalar starts in the file. A block scalar
// starts on its first content line, at the column where that content begins,
// not at the column of its | or > indicator (spec 9.2). A quoted scalar
// starts at its opening quote.
func (c *shellScriptScan) origin(n *yaml.Node, positions []shellPos) shellOrigin {
	switch n.Style {
	case yaml.LiteralStyle, yaml.FoldedStyle:
		indent := blockContentIndent(c.data, n.Line)
		return shellOrigin{line: n.Line + 1, column: indent + 1, indent: indent, positions: positions}
	case yaml.SingleQuotedStyle, yaml.DoubleQuotedStyle:
		return shellOrigin{line: n.Line, column: n.Column + 1, flat: true}
	default:
		return shellOrigin{line: n.Line, column: n.Column, flat: true}
	}
}

// blockContentIndent returns the zero-based indentation of the content lines
// of the block scalar whose indicator is on the given line. It is the column
// where the block text starts in the file, not the indicator column. An
// explicit indentation indicator fixes that indentation to the indentation of
// the parent node plus the indicator, so a first line that is more indented
// than the block does not shift it (spec 9.2).
func blockContentIndent(data []byte, indicatorLine int) int {
	_, indicator, ok := blockHeader(data, indicatorLine)
	if ok && indicator > 0 {
		return blockParentIndent(sourceLineText(data, indicatorLine)) + indicator
	}
	return blockAutoIndent(data, indicatorLine)
}

// blockAutoIndent returns the zero-based indentation of the content lines of
// a block scalar without an explicit indentation indicator: the indentation
// of its first non-blank line.
func blockAutoIndent(data []byte, indicatorLine int) int {
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

// blockParentIndent returns the zero-based indentation of the node that holds
// the block scalar whose header is the given line. A block scalar that is the
// content of a sequence entry hangs from the sequence; a block scalar that is
// the value of a key hangs from its mapping, whose indentation is the column
// of its key.
func blockParentIndent(header string) int {
	i := 0
	for i < len(header) && header[i] == ' ' {
		i++
	}
	if i < len(header) && header[i] == '-' && (i+1 == len(header) || header[i+1] == ' ') {
		j := i + 1
		for j < len(header) && header[j] == ' ' {
			j++
		}
		if j >= len(header) || header[j] == '|' || header[j] == '>' {
			return i
		}
		return j
	}
	return i
}

// shellBlockLine is one source line of a YAML block scalar.
type shellBlockLine struct {
	num   int    // one-based line in the file
	text  string // the content of the line, without the block indentation
	blank bool   // the line holds no content
	more  bool   // the content starts with a space: a more-indented line
	ended bool   // the line ends with a line break
}

// blockContent rebuilds the text of a block scalar and the source position of
// every character. A folded scalar replaces the line breaks of the source by
// spaces, so the text alone does not tell where a token is: the position
// table does (spec 9.2). ok is false when the block cannot be rebuilt, and
// the caller keeps the plain value of the scalar.
func (c *shellScriptScan) blockContent(n *yaml.Node) (string, []shellPos, bool) {
	chomp, _, ok := blockHeader(c.data, n.Line)
	if !ok {
		return "", nil, false
	}
	indent := blockContentIndent(c.data, n.Line)
	lines := c.blockLines(n.Line, indent)
	literal := n.Style == yaml.LiteralStyle

	var text []byte
	var positions []shellPos
	leadingBreak := ""
	leadingBlank := false
	trailingBreaks := 0
	lastLine := 0

	index := 0
	for index < len(lines) && lines[index].blank {
		trailingBreaks++
		index++
	}
	for index < len(lines) {
		line := lines[index]
		index++
		// A line break between two plain lines is folded into a space; a
		// more-indented line and an empty line keep their line breaks.
		if !literal && !leadingBlank && !line.more && leadingBreak == "\n" {
			if trailingBreaks == 0 {
				text = append(text, ' ')
				positions = append(positions, shellPos{line: line.num, column: indent + 1})
			}
		} else if leadingBreak != "" {
			text = append(text, '\n')
			positions = append(positions, shellPos{line: lastLine, column: indent + 1})
		}
		for i := 0; i < trailingBreaks; i++ {
			text = append(text, '\n')
			positions = append(positions, shellPos{line: line.num, column: 1})
		}
		trailingBreaks = 0
		leadingBlank = line.more
		// The table is indexed by the offset of a byte in the text, but the
		// column of a character is the count of the characters before it on
		// the line, not the count of the bytes: a multibyte character does
		// not shift the column of the rest of the line (spec 9.2).
		column := indent + 1
		for i := 0; i < len(line.text); {
			_, size := utf8.DecodeRuneInString(line.text[i:])
			text = append(text, line.text[i:i+size]...)
			for j := 0; j < size; j++ {
				positions = append(positions, shellPos{line: line.num, column: column})
			}
			i += size
			column++
		}
		lastLine = line.num
		leadingBreak = ""
		if line.ended {
			leadingBreak = "\n"
		}
		for index < len(lines) && lines[index].blank {
			trailingBreaks++
			index++
		}
	}
	// The chomping decides the trailing line breaks: '-' strips them, '+'
	// keeps them and the default keeps one.
	if chomp != '-' && leadingBreak != "" {
		text = append(text, '\n')
		positions = append(positions, shellPos{line: lastLine, column: indent + 1})
	}
	if chomp == '+' {
		for i := 0; i < trailingBreaks; i++ {
			text = append(text, '\n')
			positions = append(positions, shellPos{line: lastLine, column: indent + 1})
		}
	}
	return string(text), positions, true
}

// blockLines returns the source lines of the block scalar whose indicator is
// on the given line, with the block indentation removed. The block ends at the
// first non-empty line that is less indented than the block.
func (c *shellScriptScan) blockLines(indicatorLine, indent int) []shellBlockLine {
	var out []shellBlockLine
	eachSourceLine(c.data, indicatorLine+1, func(num int, text string, ended bool) bool {
		spaces := 0
		for spaces < len(text) && text[spaces] == ' ' {
			spaces++
		}
		if spaces == len(text) {
			out = append(out, shellBlockLine{num: num, blank: true, ended: ended})
			return true
		}
		if spaces < indent {
			return false
		}
		content := text[indent:]
		out = append(out, shellBlockLine{num: num, text: content, more: content[0] == ' ', ended: ended})
		return true
	})
	return out
}

// blockHeader returns the chomping method and the explicit indentation
// indicator of the block scalar whose indicator is on the given line: '-' for
// the chomping strips the trailing line breaks, '+' keeps them and the
// default keeps one; the indicator is 0 when the block has none.
func blockHeader(data []byte, line int) (byte, int, bool) {
	header := sourceLineText(data, line)
	if header == "" {
		return 0, 0, false
	}
	// A comment ends the header.
	if i := strings.Index(header, "#"); i > 0 && (header[i-1] == ' ' || header[i-1] == '\t') {
		header = header[:i]
	}
	index := strings.LastIndexAny(header, "|>")
	if index < 0 {
		return 0, 0, false
	}
	chomp := byte(0)
	indicator := 0
	for _, c := range []byte(strings.TrimSpace(header[index+1:])) {
		switch {
		case c == '+' || c == '-':
			chomp = c
		case c >= '0' && c <= '9':
			indicator = int(c - '0')
		default:
			return 0, 0, false
		}
	}
	return chomp, indicator, true
}

// sourceLineText returns the text of the given one-based source line, without
// its terminator.
func sourceLineText(data []byte, line int) string {
	text := ""
	eachSourceLine(data, line, func(num int, value string, ended bool) bool {
		text = value
		return false
	})
	return text
}

// eachSourceLine calls fn for every line of the file from the given one-based
// line number, with the line terminator removed. It stops when fn returns
// false.
func eachSourceLine(data []byte, from int, fn func(num int, text string, ended bool) bool) {
	line := 1
	start := 0
	for i := 0; i <= len(data); i++ {
		if i < len(data) && data[i] != '\n' {
			continue
		}
		if i == len(data) {
			if start == len(data) {
				return
			}
			if line >= from {
				fn(line, string(data[start:i]), false)
			}
			return
		}
		if line >= from {
			end := i
			if end > start && data[end-1] == '\r' {
				end--
			}
			if !fn(line, string(data[start:end]), true) {
				return
			}
		}
		line++
		start = i + 1
	}
}

// scanShellValues performs a file-wide alias prepass and then reports findings.
// Helm aliases are proof from the same file, independent of script order.
func (s *walkState) scanShellValues(scripts []shellScriptValue) {
	if len(scripts) == 0 {
		return
	}
	// Every script is tokenized once: the alias prepass and the reporting
	// pass work on the same command groups, so the tokens are kept instead of
	// being computed twice.
	groups := make([][][]shellToken, len(scripts))
	aliases := map[string]bool{}
	for i, script := range scripts {
		groups[i] = shellCommandGroups(tokenizeShell(script.value))
		for _, group := range groups[i] {
			if alias, _, ok := helmRepoAdd(group); ok {
				aliases[alias] = true
			}
		}
	}
	// The aliases the file proves are proof for every script of the file, so
	// the effective set is built once and shared.
	//
	// The seen set of the findings is built once too and grows with them: the
	// work of a file stays linear in the number of its findings.
	seen := make(map[string]bool, len(s.out.Findings))
	for _, f := range s.out.Findings {
		seen[shellFindingKey(f)] = true
	}
	for i, script := range scripts {
		findings := shellFindingsFromGroups(s.path, script.origin, groups[i], aliases)
		s.out.Findings = appendShellFindings(s.out.Findings, seen, findings)
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
// It neither evaluates substitutions nor resolves functions, aliases and
// variables: only the references that are literally present are reported, and
// it returns only redacted references or URLs. The returned aliases are
// Bitnami repositories declared by helm repo add in this script.
func shellCommandFindings(path, script string, origin shellOrigin, aliases map[string]bool) ([]diag.Finding, map[string]bool) {
	groups := shellCommandGroups(tokenizeShell(script))
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
	return shellFindingsFromGroups(path, origin, groups, effective), declared
}

// shellFindingsFromGroups reports the findings of one script from the command
// groups its tokens form, with the aliases that are proven for the file. A
// finding that repeats another one of the same script is reported once.
func shellFindingsFromGroups(path string, origin shellOrigin, groups [][]shellToken, aliases map[string]bool) []diag.Finding {
	var findings []diag.Finding
	seen := map[string]bool{}
	for _, group := range groups {
		for _, f := range shellGroupFindings(path, group, origin, aliases) {
			key := shellFindingKey(f)
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, f)
		}
	}
	return findings
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

// appendShellFindings appends the findings that are not reported yet. The seen
// set holds the findings that are already reported: it is built once per file
// and grows with them, so the work stays linear in their number.
func appendShellFindings(dst []diag.Finding, seen map[string]bool, incoming []diag.Finding) []diag.Finding {
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
			switch {
			case shellDockerTakesValue(operation, token.value):
				i += 2
			case shellDockerUnknownTakesValue(operation, token.value, args, i):
				// An option that is in neither table and is followed by a
				// number consumes it, so an option the tables do not know
				// yet does not hide the image behind it.
				i += 2
			default:
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

// dockerValueFlags are the options of `docker run` and `docker create` that
// consume the next token as their value
// (https://docs.docker.com/reference/cli/docker/container/run/).
var dockerValueFlags = map[string]bool{
	"--add-host": true,
	"-a":         true, "--attach": true,
	"--blkio-weight": true, "--blkio-weight-device": true,
	"--cap-add": true, "--cap-drop": true,
	"--cgroup-parent": true, "--cgroupns": true,
	"--cidfile":    true,
	"--cpu-period": true, "--cpu-quota": true,
	"--cpu-rt-period": true, "--cpu-rt-runtime": true,
	"-c": true, "--cpu-shares": true,
	"--cpus": true, "--cpuset-cpus": true, "--cpuset-mems": true,
	"--detach-keys": true,
	"--device":      true, "--device-cgroup-rule": true,
	"--device-read-bps": true, "--device-read-iops": true,
	"--device-write-bps": true, "--device-write-iops": true,
	"--dns": true, "--dns-option": true, "--dns-search": true,
	"--domainname": true,
	"--entrypoint": true,
	"-e":           true, "--env": true, "--env-file": true,
	"--expose": true,
	"--gpus":   true, "--group-add": true,
	"--health-cmd": true, "--health-interval": true,
	"--health-retries": true, "--health-start-interval": true,
	"--health-start-period": true, "--health-timeout": true,
	"-h": true, "--hostname": true,
	"--io-maxbandwidth": true, "--io-maxiops": true,
	"--ip": true, "--ip6": true, "--ipc": true, "--isolation": true,
	"-l": true, "--label": true, "--label-file": true,
	"--link": true, "--link-local-ip": true,
	"--log-driver": true, "--log-opt": true,
	"--mac-address": true,
	"-m":            true, "--memory": true, "--memory-reservation": true,
	"--memory-swap": true, "--memory-swappiness": true,
	"--mount": true, "--name": true,
	"--network": true, "--net": true, "--network-alias": true,
	"--oom-score-adj": true,
	"--pid":           true, "--pids-limit": true, "--platform": true,
	"-p": true, "--publish": true, "--pull": true,
	"--restart": true, "--runtime": true,
	"--security-opt": true, "--shm-size": true,
	"--stop-signal": true, "--stop-timeout": true,
	"--storage-opt": true, "--sysctl": true,
	"--tmpfs": true, "--ulimit": true,
	"-u": true, "--user": true, "--userns": true, "--uts": true,
	"-v": true, "--volume": true, "--volume-driver": true,
	"--volumes-from": true,
	"-w":             true, "--workdir": true, "--umask": true,
	// Deprecated options that still take a value.
	"--annotation": true, "--kernel-memory": true,
}

// dockerBooleanFlags are the options of `docker run` and `docker create` that
// never take a value: they are listed so that they are never read as a
// value-taking one (spec 9.2).
var dockerBooleanFlags = map[string]bool{
	"--rm": true,
	"-d":   true, "--detach": true,
	"-i": true, "--interactive": true,
	"-t": true, "--tty": true,
	"--init": true, "--privileged": true, "--read-only": true,
	"--oom-kill-disable": true, "--no-healthcheck": true,
	"-P": true, "--publish-all": true,
	"--sig-proxy": true, "--disable-content-trust": true,
	"-q": true,
}

// shellDockerTakesValue reports whether an option consumes the next token as
// its value. The arity depends on the subcommand: -t is a tag for build and a
// boolean for run, so an option is never consumed speculatively (spec 9.2).
// The table holds the value-taking options of `docker run` and
// `docker create` (https://docs.docker.com/reference/cli/docker/container/run/).
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
	case "run", "create":
		return dockerValueFlags[option]
	default:
		return false
	}
}

// shellDockerUnknownTakesValue reports whether an option that is in neither
// table consumes the next token as its value. Only a long option followed by
// a number qualifies: the value of an option the tables do not know yet is
// usually a limit, and the image behind it must still be found (spec 9.2).
func shellDockerUnknownTakesValue(operation, option string, args []shellToken, index int) bool {
	if operation != "run" && operation != "create" {
		return false
	}
	if !strings.HasPrefix(option, "--") || dockerValueFlags[option] || dockerBooleanFlags[option] {
		return false
	}
	if index+1 >= len(args) {
		return false
	}
	return shellNumericValue(args[index+1].value)
}

// shellNumericValue reports whether a token is a number with an optional unit
// suffix, like the value of a resource limit.
func shellNumericValue(token string) bool {
	digits := 0
	for digits < len(token) && token[digits] >= '0' && token[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return false
	}
	if digits == len(token) {
		return true
	}
	switch token[digits:] {
	case "k", "m", "g", "b", "s", "ms":
		return true
	}
	return false
}

// shellImageFinding reports an image reference of a command line. Only a
// reference that is literally present is reported: a variable is never
// resolved (spec 9.2).
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
		if len(positionals) < 2 {
			return nil
		}
		source := positionals[1].value
		if !isBitnamiChartSource(source) {
			return nil
		}
		f := shellChartFinding(path, positionals[1], origin, "", source)
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
	if len(positionals) < 2 {
		return "", "", false
	}
	source := positionals[1].value
	if !isBitnamiChartSource(source) {
		return "", "", false
	}
	return positionals[0].value, source, true
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
			switch {
			case helmValueTakesValue(token.value):
				i += 2
			case helmOptionalValueTakesValue(token.value, tokens, i):
				i += 2
			default:
				i++
			}
			continue
		}
		out = append(out, token)
		i++
	}
	return out
}

// helmGlobalValueFlags are the helm global flags that consume the next token
// as their value (https://helm.sh/docs/helm/).
var helmGlobalValueFlags = map[string]bool{
	"-n": true, "--namespace": true,
	"--burst-limit":          true,
	"--kube-apiserver":       true,
	"--kube-as-group":        true,
	"--kube-as-user":         true,
	"--kube-ca-file":         true,
	"--kube-context":         true,
	"--kube-tls-server-name": true,
	"--kube-token":           true,
	"--kubeconfig":           true,
	"--qps":                  true,
	"--registry-config":      true,
	"--repository-cache":     true,
	"--repository-config":    true,
}

// helmGlobalBooleanFlags are the helm global flags that never take a value
// (https://helm.sh/docs/helm/).
var helmGlobalBooleanFlags = map[string]bool{
	"--debug":                         true,
	"--kube-insecure-skip-tls-verify": true,
}

// helmGlobalTakesValue reports whether a helm global flag consumes the next
// token as its value (https://helm.sh/docs/helm/).
func helmGlobalTakesValue(option string) bool {
	return helmGlobalValueFlags[option]
}

// helmBooleanFlags are the helm options of the install, upgrade, template and
// pull commands that never take a value. They are listed so that a flag is
// never read as a value-taking one (spec 9.2).
var helmBooleanFlags = map[string]bool{
	"--allow-deprecated-repos": true, "--atomic": true,
	"--cleanup-on-fail":  true,
	"--create-namespace": true, "--devel": true, "--dependency-update": true,
	"--disable-openapi-validation": true, "--enable-dns": true,
	"--force": true, "--force-update": true,
	"--generate-name": true, "--hide-notes": true, "--include-crds": true,
	"--install": true, "-i": true,
	"--insecure-skip-tls-verify": true, "--is-upgrade": true,
	"--no-hooks": true, "--no-update": true, "--pass-credentials": true,
	"--plain-http": true, "--prov": true, "--render-subchart-notes": true,
	"--release-name": true, "--replace": true,
	"--reset-values": true, "--reset-then-reuse-values": true,
	"--reuse-values": true,
	"--skip-crds":    true, "--skip-schema-validation": true,
	"--skip-tests": true, "--subnotes": true, "--take-ownership": true,
	"--validate": true, "--verify": true, "--wait": true,
	"--wait-for-jobs": true,
}

// helmValueFlags are the helm options of the install, upgrade, template and
// pull commands that consume the next token as their value
// (https://helm.sh/docs/helm/).
var helmValueFlags = map[string]bool{
	"-f": true, "--values": true,
	"--set": true, "--set-string": true, "--set-file": true,
	"--set-json": true, "--set-literal": true,
	"--version": true, "--repo": true, "--description": true,
	"--timeout": true, "--username": true, "--password": true,
	"--ca-file": true, "--cert-file": true, "--key-file": true,
	"--keyring": true, "--post-renderer": true, "--post-renderer-args": true,
	"--destination": true, "--untar-dir": true, "--untardir": true,
	"--output": true, "-o": true, "--output-dir": true,
	"--show-only": true, "-s": true,
	"--kube-version": true,
	"--api-versions": true, "-a": true,
	"--labels": true, "-l": true,
	"--name-template": true,
	"--history-max":   true,
}

// helmOptionalValueFlags are the helm options whose value is optional: they
// take a value only when the next token names one (spec 9.2).
var helmOptionalValueFlags = map[string]bool{
	"--dry-run": true,
}

// helmOptionalValueTakesValue reports whether an option with an optional value
// consumes the next token. The dry-run flag names the client or the server
// mode, and only those words are values (spec 9.2).
func helmOptionalValueTakesValue(option string, tokens []shellToken, index int) bool {
	if !helmOptionalValueFlags[option] || index+1 >= len(tokens) {
		return false
	}
	switch strings.ToLower(tokens[index+1].value) {
	case "client", "server", "true", "false":
		return true
	}
	return false
}

// helmValueTakesValue reports whether a helm option consumes the next token
// as its value. A value-taking flag is never skipped by itself, so the chart
// behind it is still found (spec 9.2).
func helmValueTakesValue(option string) bool {
	if helmBooleanFlags[option] || helmGlobalBooleanFlags[option] {
		return false
	}
	if helmValueFlags[option] {
		return true
	}
	return helmGlobalTakesValue(option)
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
			value = strings.TrimSpace(value)
			switch strings.TrimSpace(name) {
			case "image.repository":
				r := imageref.Parse(value)
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
				if strings.EqualFold(value, "true") {
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

// shellChartTokenFinding reports the chart of a command line. Only a chart
// that is literally present is reported: a variable is never resolved
// (spec 9.2).
func shellChartTokenFinding(path string, token shellToken, origin shellOrigin, aliases map[string]bool) (diag.Finding, bool) {
	reference := strings.TrimSpace(token.value)
	if shellIsBitnamiOCIChart(reference) {
		return shellChartFinding(path, token, origin, shellChartComponent(reference), reference), true
	}
	alias, chart, ok := strings.Cut(reference, "/")
	if !ok || alias == "" || chart == "" || !aliases[alias] {
		return diag.Finding{}, false
	}
	return shellChartFinding(path, token, origin, shellChartComponent(reference), reference), true
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

// shellChartFinding reports a chart reference of a command line. The
// reference is the text of the token.
func shellChartFinding(path string, token shellToken, origin shellOrigin, component, reference string) diag.Finding {
	reference = strings.TrimSpace(reference)
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

// shellTokenLocation resolves a token position in the file. A block scalar
// keeps a position table, so the finding lands on the line and column of the
// token in the source, not on the first line of the folded text. The first
// line of a script string starts at its origin column; the later lines keep
// the indentation the origin declares. A plain or quoted scalar has no
// position table: all its tokens are reported on the line of the scalar
// (spec 9.2).
func shellTokenLocation(path string, token shellToken, origin shellOrigin) diag.Location {
	if token.offset < len(origin.positions) {
		position := origin.positions[token.offset]
		return loc(path, position.line, position.column)
	}
	if origin.flat {
		return loc(path, origin.line, origin.column+token.column-1)
	}
	line := origin.line + token.line - 1
	column := token.column + origin.indent
	if token.line == 1 {
		column = origin.column + token.column - 1
	}
	return loc(path, line, column)
}

// tokenizeShell is a bounded, non-evaluating POSIX-like tokenizer. It handles
// quotes, escapes, continuations, command separators, substitutions, comments,
// and heredocs while preserving one-based token positions. A column counts the
// characters of the line, not its bytes, like the rest of the scanner
// (spec 9.2).
func tokenizeShell(script string) []shellToken {
	if script == "" {
		return nil
	}
	tokens := make([]shellToken, 0, min(len(script)/4+1, 4096))
	var current []byte
	hasCurrent := false
	currentLine, currentColumn, currentOffset := 1, 1, 0
	line, column := 1, 1
	var heredoc *shellHeredoc

	emit := func() {
		if !hasCurrent {
			return
		}
		tokens = append(tokens, shellToken{value: string(current), kind: shellWord, line: currentLine, column: currentColumn, offset: currentOffset})
		current = current[:0]
		hasCurrent = false
	}
	startWord := func(at int) {
		if !hasCurrent {
			hasCurrent = true
			currentLine, currentColumn = line, column
			currentOffset = at
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
			startWord(i)
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
					_, size := utf8.DecodeRuneInString(script[i+1:])
					current = append(current, script[i+1:i+1+size]...)
					i += 1 + size
					column += 2
					continue
				}
				_, size := utf8.DecodeRuneInString(script[i:])
				current = append(current, script[i:i+size]...)
				i += size
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
			startWord(i)
			_, size := utf8.DecodeRuneInString(script[i:])
			current = append(current, script[i:i+size]...)
			i += size
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
