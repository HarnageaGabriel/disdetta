package plan

import (
	"reflect"
	"testing"
)

func TestInstancesFromArchitecture(t *testing.T) {
	tests := []struct {
		name    string
		arch    any
		values  map[string]any
		want    any
		wantErr bool
	}{
		{"standalone", "standalone", map[string]any{}, 1, false},
		{"replication", "replication", map[string]any{"readReplicas": map[string]any{"replicaCount": 2}}, 3, false},
		{"missing replicas", "replication", map[string]any{}, 2, false},
		{"invalid architecture", "other", map[string]any{}, nil, false},
		{"negative replicas", "replication", map[string]any{"readReplicas": map[string]any{"replicaCount": -1}}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := instancesFromArchitecture("architecture", tt.arch, tt.values)
			if (err != nil) != tt.wantErr || !reflect.DeepEqual(got.Value, tt.want) {
				t.Fatalf("value=%#v err=%v", got.Value, err)
			}
		})
	}
}

func TestParsePostgresqlConf(t *testing.T) {
	in := "# ignored\nlisten_addresses = '*'\nport=5433\npgaudit.log = 'write, ddl' # comment\nauto_explain.log_min_duration = \"1s#kept\"\ninclude = 'other.conf'\ninvalid line\n"
	got, err := parsePostgresqlConf("primary.configuration", in, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"pgaudit.log": "write, ddl", "auto_explain.log_min_duration": "1s#kept", "invalid": "line"}
	if !reflect.DeepEqual(got.Value, want) {
		t.Fatalf("parameters=%#v", got.Value)
	}
	if len(got.Dropped) != 3 || got.Dropped[0].Path != "primary.configuration:listen_addresses" || got.Dropped[1].Note != "fixed parameter managed by CloudNativePG; cannot be set" {
		t.Fatalf("dropped=%#v", got.Dropped)
	}
	if invalid, err := parsePostgresqlConf("primary.configuration", 42, nil); err != nil || len(invalid.Dropped) != 1 {
		t.Fatalf("non-string result=%#v err=%v", invalid, err)
	}
}

func TestSplitLines(t *testing.T) {
	got, err := splitLines("hba", "# comment\n\nhost all all 0.0.0.0/0 md5\r\n", nil)
	if err != nil || !reflect.DeepEqual(got.Value, []string{"host all all 0.0.0.0/0 md5"}) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	if invalid, err := splitLines("hba", 1, nil); err != nil || len(invalid.Dropped) != 1 {
		t.Fatalf("non-string result=%#v err=%v", invalid, err)
	}
}

func TestSplitComma(t *testing.T) {
	got, err := splitComma("postgresqlSharedPreloadLibraries", " pgaudit, vector, pg_stat_statements, ,timescaledb ", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Value, []string{"vector", "timescaledb"}) || len(got.Dropped) != 2 || len(got.Checklist) != 0 {
		t.Fatalf("got=%#v", got)
	}
	if invalid, err := splitComma("libs", true, nil); err != nil || len(invalid.Dropped) != 1 {
		t.Fatalf("non-string result=%#v err=%v", invalid, err)
	}
}
