package plan

import (
	"fmt"
	"strconv"
	"strings"
)

type transformResult struct {
	Value     any
	Dropped   []Unmapped
	Checklist []ChecklistItem
	Mapped    bool
}
type transformFunc func(path string, value any, all map[string]any) (transformResult, error)

var transforms = map[string]transformFunc{
	"instances-from-architecture": instancesFromArchitecture,
	"parse-postgresql-conf":       parsePostgresqlConf,
	"split-lines":                 splitLines,
	"split-comma":                 splitComma,
}

func RegisteredTransform(name string) bool { _, ok := transforms[name]; return ok }

func instancesFromArchitecture(path string, value any, all map[string]any) (transformResult, error) {
	arch, ok := value.(string)
	if !ok {
		return transformResult{Dropped: []Unmapped{{Path: path, Kind: "manual", Note: "unsupported value"}}}, nil
	}
	switch arch {
	case "standalone":
		return transformResult{Value: 1, Mapped: true}, nil
	case "replication":
		v, ok := lookup(all, "readReplicas.replicaCount")
		if !ok {
			return transformResult{Value: 2, Mapped: true}, nil
		}
		n, ok := integer(v)
		if !ok || n < 0 {
			return transformResult{Dropped: []Unmapped{{Path: "readReplicas.replicaCount", Kind: "manual", Note: "value not in the expected shape; not copied"}}}, nil
		}
		return transformResult{Value: n + 1, Mapped: true}, nil
	default:
		return transformResult{Dropped: []Unmapped{{Path: path, Kind: "manual", Note: "unsupported value"}}}, nil
	}
}

var fixedParameters = map[string]bool{}

func init() {
	for _, k := range strings.Fields("allow_alter_system allow_system_table_mods archive_cleanup_command archive_command archive_mode bonjour bonjour_name cluster_name config_file data_directory data_sync_retry event_source external_pid_file hba_file hot_standby ident_file jit_provider listen_addresses log_destination log_directory log_file_mode log_filename log_rotation_age log_rotation_size log_truncate_on_rotation logging_collector port primary_conninfo primary_slot_name promote_trigger_file recovery_end_command recovery_min_apply_delay restart_after_crash restore_command shared_preload_libraries ssl ssl_ca_file ssl_cert_file ssl_crl_file ssl_dh_params_file ssl_key_file ssl_passphrase_command ssl_passphrase_command_supports_reload ssl_prefer_server_ciphers stats_temp_directory synchronous_standby_names unix_socket_directories unix_socket_group unix_socket_permissions") {
		fixedParameters[k] = true
	}
}
func isFixed(k string) bool {
	k = strings.ToLower(k)
	return fixedParameters[k] || strings.HasPrefix(k, "recovery_target") || strings.HasPrefix(k, "syslog_")
}

func parsePostgresqlConf(path string, value any, _ map[string]any) (transformResult, error) {
	s, ok := value.(string)
	if !ok {
		return transformResult{Dropped: []Unmapped{{Path: path, Kind: "manual", Note: "value not in the expected shape; not copied"}}}, nil
	}
	out := map[string]any{}
	var dropped []Unmapped
	for i, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		key, val, ok := parsePostgresqlConfLine(line)
		if !ok {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				dropped = append(dropped, Unmapped{Path: fmt.Sprintf("%s:line%d", path, i+1), Kind: "unmapped", Note: "unrecognized postgresql.conf line"})
			}
			continue
		}
		lowerKey := strings.ToLower(key)
		switch lowerKey {
		case "include", "include_dir", "include_if_exists":
			dropped = append(dropped, Unmapped{Path: fmt.Sprintf("%s:line%d", path, i+1), Kind: "manual", Note: "include directives require manual migration"})
			continue
		}
		if deniedKey(lowerKey) {
			dropped = append(dropped, Unmapped{Path: fmt.Sprintf("%s:line%d", path, i+1), Kind: "manual", Note: "credential-bearing parameter not copied"})
			continue
		}
		if isFixed(lowerKey) {
			dropped = append(dropped, Unmapped{Path: safePath(path + ":" + lowerKey), Kind: "unmapped", Note: "fixed parameter managed by CloudNativePG; cannot be set"})
			continue
		}
		out[lowerKey] = val
	}
	return transformResult{Value: out, Dropped: dropped, Mapped: true}, nil
}

func parsePostgresqlConfLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	i := 0
	for i < len(line) && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	key := line[:i]
	rest := strings.TrimSpace(line[i:])
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimSpace(rest[1:])
	}
	if rest == "" {
		return "", "", false
	}
	value, ok := postgresqlValue(rest)
	if !ok {
		return "", "", false
	}
	return key, value, true
}

func postgresqlValue(raw string) (string, bool) {
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote == '\'' && c == '\'' && i+1 < len(raw) && raw[i+1] == '\'' {
			b.WriteByte('\'')
			i++
			continue
		}
		if c == '\'' || c == '"' {
			if quote == 0 {
				quote = c
				continue
			}
			if quote == c {
				quote = 0
				continue
			}
		}
		if c == '#' && quote == 0 {
			break
		}
		b.WriteByte(c)
	}
	if quote != 0 {
		return "", false
	}
	return strings.TrimSpace(b.String()), true
}

func splitLines(path string, value any, all map[string]any) (transformResult, error) {
	s, ok := value.(string)
	if !ok {
		return transformResult{Dropped: []Unmapped{{Path: path, Kind: "manual", Note: "value not in the expected shape; not copied"}}}, nil
	}
	var out []string
	var dropped []Unmapped
	var checklist []ChecklistItem
	md5Found := false
	for i, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if credentialBearingHBA(fields) {
			dropped = append(dropped, Unmapped{Path: fmt.Sprintf("%s:line%d", path, i+1), Kind: "manual", Note: "credential-bearing pg_hba rule not copied"})
			continue
		}
		if fixedHBARule(fields) {
			dropped = append(dropped, Unmapped{Path: fmt.Sprintf("%s:line%d", path, i+1), Kind: "manual", Note: "duplicates a fixed CloudNativePG pg_hba rule"})
			continue
		}
		for _, field := range fields {
			if strings.EqualFold(field, "md5") {
				md5Found = true
			}
		}
		out = append(out, line)
	}
	if md5Found && sourceMajorAtLeast14OrUnknown(all) {
		checklist = append(checklist, ChecklistItem{Text: "On PostgreSQL 14+, review md5 pg_hba rules before the default scram-sha-256 catch-all.", Source: "https://cloudnative-pg.io/docs/1.30/postgresql_conf"})
	}
	return transformResult{Value: out, Dropped: dropped, Checklist: checklist, Mapped: true}, nil
}

func credentialBearingHBA(fields []string) bool {
	for _, field := range fields {
		name, _, _ := strings.Cut(strings.ToLower(field), "=")
		switch name {
		case "ldapbindpasswd", "radiussecrets", "password", "secret":
			return true
		}
	}
	return false
}

func fixedHBARule(fields []string) bool {
	if len(fields) >= 4 && strings.EqualFold(fields[0], "local") && strings.EqualFold(fields[1], "all") && strings.EqualFold(fields[2], "all") && strings.EqualFold(fields[3], "peer") {
		return true
	}
	if len(fields) < 5 || !strings.EqualFold(fields[0], "hostssl") || !strings.EqualFold(fields[3], "all") || !strings.EqualFold(fields[4], "cert") {
		return false
	}
	streaming := (strings.EqualFold(fields[1], "postgres") || strings.EqualFold(fields[1], "replication")) && strings.EqualFold(fields[2], "streaming_replica")
	pooler := strings.EqualFold(fields[1], "all") && strings.EqualFold(fields[2], "cnpg_pooler_pgbouncer")
	return streaming || pooler
}

func sourceMajorAtLeast14OrUnknown(all map[string]any) bool {
	v, ok := lookup(all, "image.tag")
	if !ok {
		return true
	}
	tag, ok := v.(string)
	if !ok {
		return true
	}
	i := 0
	for i < len(tag) && tag[i] >= '0' && tag[i] <= '9' {
		i++
	}
	if i == 0 {
		return true
	}
	major, err := strconv.Atoi(tag[:i])
	return err != nil || major >= 14
}

func splitComma(path string, value any, all map[string]any) (transformResult, error) {
	s, ok := value.(string)
	if !ok {
		return transformResult{Dropped: []Unmapped{{Path: path, Kind: "manual", Note: "value not in the expected shape; not copied"}}}, nil
	}
	managed := map[string]bool{"pgaudit": true, "pg_stat_statements": true, "auto_explain": true, "pg_failover_slots": true}
	parameters := configuredParameters(all)
	var out []string
	var dropped []Unmapped
	var checks []ChecklistItem
	for i, item := range strings.Split(s, ",") {
		lib := strings.TrimSpace(item)
		if lib == "" {
			continue
		}
		itemPath := fmt.Sprintf("%s:item%d", path, i+1)
		if managed[lib] {
			if parameters[lib] {
				dropped = append(dropped, Unmapped{Path: path + "." + lib, Kind: "handled", Note: "loaded automatically by CloudNativePG"})
				if lib == "pgaudit" {
					checks = append(checks, ChecklistItem{Text: "pgaudit requires a standard CloudNativePG operand image.", Source: "https://cloudnative-pg.io/docs/1.30/postgresql_conf"})
				}
			} else {
				dropped = append(dropped, Unmapped{Path: path + "." + lib, Kind: "manual", Note: "loaded automatically by CloudNativePG only when " + lib + ".* parameters are set; set one to keep the library loaded"})
			}
			continue
		}
		if !acceptsValue("pg-identifier", lib) {
			dropped = append(dropped, Unmapped{Path: itemPath, Kind: "manual", Note: "value not in the expected shape; not copied"})
			continue
		}
		out = append(out, lib)
	}
	return transformResult{Value: out, Dropped: dropped, Checklist: checks, Mapped: true}, nil
}

func configuredParameters(all map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, path := range []string{"primary.configuration", "primary.extendedConfiguration"} {
		value, ok := lookup(all, path)
		if !ok {
			continue
		}
		parsed, err := parsePostgresqlConf(path, value, nil)
		if err != nil {
			continue
		}
		parameters, _ := parsed.Value.(map[string]any)
		for key := range parameters {
			if dot := strings.IndexByte(key, '.'); dot > 0 {
				out[key[:dot]] = true
			}
		}
	}
	return out
}

func integer(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	}
	return 0, false
}
