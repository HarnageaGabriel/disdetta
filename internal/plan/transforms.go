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
		return transformResult{}, fmt.Errorf("%s must be a string", path)
	}
	switch arch {
	case "standalone":
		return transformResult{Value: 1}, nil
	case "replication":
		v, ok := lookup(all, "readReplicas.replicaCount")
		if !ok {
			return transformResult{}, fmt.Errorf("replication requires readReplicas.replicaCount")
		}
		n, ok := integer(v)
		if !ok || n < 0 {
			return transformResult{}, fmt.Errorf("readReplicas.replicaCount must be a non-negative integer")
		}
		return transformResult{Value: n + 1}, nil
	default:
		return transformResult{}, fmt.Errorf("unsupported architecture %q", arch)
	}
}

var fixedParameters = map[string]bool{}

func init() {
	for _, k := range strings.Fields("allow_alter_system allow_system_table_mods archive_cleanup_command archive_command archive_mode bonjour bonjour_name cluster_name config_file data_directory data_sync_retry event_source external_pid_file hba_file hot_standby ident_file jit_provider listen_addresses log_destination log_directory log_file_mode log_filename log_rotation_age log_rotation_size log_truncate_on_rotation logging_collector port primary_conninfo primary_slot_name promote_trigger_file recovery_end_command recovery_min_apply_delay restart_after_crash restore_command shared_preload_libraries ssl ssl_ca_file ssl_cert_file ssl_crl_file ssl_dh_params_file ssl_key_file ssl_passphrase_command ssl_passphrase_command_supports_reload ssl_prefer_server_ciphers stats_temp_directory synchronous_standby_names unix_socket_directories unix_socket_group unix_socket_permissions") {
		fixedParameters[k] = true
	}
}
func isFixed(k string) bool {
	return fixedParameters[k] || strings.HasPrefix(k, "recovery_target") || strings.HasPrefix(k, "syslog_")
}

func parsePostgresqlConf(path string, value any, _ map[string]any) (transformResult, error) {
	s, ok := value.(string)
	if !ok {
		return transformResult{}, fmt.Errorf("%s must be a string", path)
	}
	out := map[string]any{}
	var dropped []Unmapped
	for i, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "include") {
			dropped = append(dropped, Unmapped{Path: fmt.Sprintf("%s:line%d", path, i+1), Kind: "unmapped", Note: "include directives require manual migration"})
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			dropped = append(dropped, Unmapped{Path: fmt.Sprintf("%s:line%d", path, i+1), Kind: "unmapped", Note: "unrecognized postgresql.conf line"})
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := unquote(stripComment(strings.TrimSpace(parts[1])))
		if key == "" {
			continue
		}
		if isFixed(key) {
			dropped = append(dropped, Unmapped{Path: path + ":" + key, Kind: "unmapped", Note: "fixed parameter managed by CloudNativePG; cannot be set"})
			continue
		}
		out[key] = val
	}
	return transformResult{Value: out, Dropped: dropped}, nil
}

func unquote(s string) string {
	if len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"')) {
		return s[1 : len(s)-1]
	}
	return s
}
func stripComment(s string) string {
	quote := rune(0)
	for i, r := range s {
		if r == '\'' || r == '"' {
			if quote == 0 {
				quote = r
			} else if quote == r {
				quote = 0
			}
		}
		if r == '#' && quote == 0 {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func splitLines(path string, value any, _ map[string]any) (transformResult, error) {
	s, ok := value.(string)
	if !ok {
		return transformResult{}, fmt.Errorf("%s must be a string", path)
	}
	var out []string
	for _, v := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		v = strings.TrimSpace(v)
		if v != "" && !strings.HasPrefix(v, "#") {
			out = append(out, v)
		}
	}
	return transformResult{Value: out}, nil
}

func splitComma(path string, value any, _ map[string]any) (transformResult, error) {
	s, ok := value.(string)
	if !ok {
		return transformResult{}, fmt.Errorf("%s must be a string", path)
	}
	managed := map[string]bool{"pgaudit": true, "pg_stat_statements": true, "auto_explain": true, "pg_failover_slots": true}
	var out []string
	var dropped []Unmapped
	var checks []ChecklistItem
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if managed[v] {
			dropped = append(dropped, Unmapped{Path: path + "." + v, Kind: "unmapped", Note: "loaded automatically by CloudNativePG only when " + v + ".* parameters are set; set one to keep the library loaded"})
			if v == "pgaudit" {
				checks = append(checks, ChecklistItem{Text: "pgaudit requires a standard CloudNativePG operand image.", Source: "https://github.com/cloudnative-pg/postgres-containers"})
			}
			continue
		}
		out = append(out, v)
	}
	return transformResult{Value: out, Dropped: dropped, Checklist: checks}, nil
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
	case string:
		i, e := strconv.Atoi(n)
		return i, e == nil
	}
	return 0, false
}
