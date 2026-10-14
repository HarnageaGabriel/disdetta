package plan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/scan/cluster"
)

func postgresqlCatalog(t *testing.T) (Catalog, Route) {
	t.Helper()
	catalogs, err := EmbeddedCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	c, route, err := SelectCatalog(catalogs, "postgresql", "16.7.4", "")
	if err != nil {
		t.Fatal(err)
	}
	return c, route
}

// review 04 #1 and review 04 #2: planted credentials never reach any plan
// representation, including values shaped like YAML aliases or cluster config.
func TestReview04PlantedSecretCorpus(t *testing.T) {
	c, route := postgresqlCatalog(t)
	secret := "PLANTED-secret-token-123"
	values := map[string]any{
		"architecture": secret,
		"auth":         map[string]any{"password": secret},
		"primary": map[string]any{
			"resources":          map[string]any{"password": secret, "requests": map[string]any{"cpu": "1"}},
			"configuration":      "app.password = '" + secret + "'\nnormal = 'ok'",
			"pgHbaConfiguration": "host all all 0.0.0.0/0 ldap ldapbindpasswd=" + secret,
		},
		"postgresqlSharedPreloadLibraries": secret,
		"tls":                              map[string]any{secret: true},
	}
	payload, err := json.Marshal(map[string]any{"name": "pg", "chart": map[string]any{"metadata": map[string]any{"name": "postgresql", "version": "16.7.4"}}, "config": values})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cluster.DecodePlanRelease("pg", payload)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Build(Input{decoded.Name, decoded.Chart, decoded.Version, decoded.Config}, c, route)
	if err != nil {
		t.Fatal(err)
	}
	jsonPlan, _ := JSON(p)
	table, _ := Table(p)
	target, _ := TargetYAML(p)
	unmapped, _ := UnmappedYAML(p)
	outputs := map[string][]byte{
		"stdout": table, "stderr": []byte(fmt.Sprint(err)), "JSON": jsonPlan,
		"target": target, "unmapped": unmapped, "checklist": ChecklistMarkdown(p),
	}
	for name, output := range outputs {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatalf("secret leaked in %s", name)
		}
	}
}

// review 04 #4: Flux valuesFrom is explicit and inline values win after the
// supplied stand-in files.
func TestReview04FluxValuesFrom(t *testing.T) {
	release := []byte("kind: HelmRelease\nmetadata: {name: pg}\nspec:\n  chart:\n    spec: {chart: postgresql, version: 16.7.4}\n  valuesFrom:\n    - {kind: Secret, name: values}\n  values:\n    architecture: standalone\n    primary: {persistence: {size: 20Gi}}\n")
	if _, err := FindRepoRelease("pg", map[string][]byte{"release.yaml": release}, nil); err == nil || !strings.Contains(err.Error(), "valuesFrom is not resolved") {
		t.Fatalf("missing valuesFrom error: %v", err)
	}
	in, err := FindRepoRelease("pg", map[string][]byte{"release.yaml": release}, [][]byte{[]byte("architecture: replication\nprimary:\n  persistence:\n    storageClass: slow\n")})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := lookup(in.Values, "architecture"); got != "standalone" {
		t.Fatalf("inline precedence lost: %#v", in.Values)
	}
	if got, _ := lookup(in.Values, "primary.persistence.storageClass"); got != "slow" {
		t.Fatalf("valuesFrom stand-in missing: %#v", in.Values)
	}
}

// review 04 #5: Helm layers deep-merge maps, replace lists, and null deletes.
func TestReview04HelmMergeSemantics(t *testing.T) {
	dst := map[string]any{"map": map[string]any{"keep": 1, "drop": 2}, "list": []any{1, 2}}
	MergeValues(dst, map[string]any{"map": map[string]any{"drop": nil, "add": 3}, "list": []any{9}})
	want := map[string]any{"map": map[string]any{"keep": 1, "add": 3}, "list": []any{9}}
	if !reflect.DeepEqual(dst, want) {
		t.Fatalf("merge=%#v", dst)
	}
}

// review 04 #6: the shipped route is pinned and unsupported replica keys stay
// unknown rather than inheriting the replicaCount claim.
func TestReview04CatalogPinsAndReplicaScope(t *testing.T) {
	c, route := postgresqlCatalog(t)
	if c.AppliesTo != ">=16.0.0 <18.0.0" || route.Target.Version != "1.30" {
		t.Fatalf("catalog not pinned: %#v %#v", c.AppliesTo, route.Target.Version)
	}
	for _, m := range c.Mappings {
		if strings.Contains(m.Source.URL, "/devel/") || m.From == "readReplicas.*" {
			t.Fatalf("unsupported catalog claim: %#v", m)
		}
	}
	p, err := Build(Input{"pg", "postgresql", "16.7.4", map[string]any{"readReplicas": map[string]any{"other": true}}}, c, route)
	if err != nil || len(p.Unmapped) != 1 || p.Unmapped[0].Kind != "unknown" {
		t.Fatalf("plan=%#v err=%v", p, err)
	}
}

// review 04 #7: PostgreSQL optional '=', quoting, exact include directives,
// duplicate last-wins behavior, units, and case-insensitive fixed keys.
func TestReview04PostgresqlConfGrammar(t *testing.T) {
	text := "shared_buffers '1GB'\ninclude.foo = 'on'\nname = 'it''s # kept' # removed\nname final\nLISTEN_ADDRESSES '*'\ninclude_dir 'conf.d'\n"
	got, err := parsePostgresqlConf("primary.configuration", text, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"shared_buffers": "1GB", "include.foo": "on", "name": "final"}
	if !reflect.DeepEqual(got.Value, want) || len(got.Dropped) != 2 || got.Dropped[1].Kind != "manual" {
		t.Fatalf("parsed=%#v dropped=%#v", got.Value, got.Dropped)
	}
}

// review 04 #8: replication uses the pinned default and unsupported
// architecture values become manual work without echoing the value.
func TestReview04ArchitectureDefaultsAndUnsupported(t *testing.T) {
	got, err := instancesFromArchitecture("architecture", "replication", map[string]any{})
	if err != nil || got.Value != 2 || !got.Mapped {
		t.Fatalf("default replication=%#v err=%v", got, err)
	}
	bad, err := instancesFromArchitecture("architecture", "do-not-echo", map[string]any{})
	if err != nil || len(bad.Dropped) != 1 || bad.Dropped[0].Note != "unsupported value" || strings.Contains(fmt.Sprint(bad), "do-not-echo") {
		t.Fatalf("unsupported=%#v err=%v", bad, err)
	}
}

// review 04 #9: a managed preload library with a matching parameter is
// handled, while a request without one remains manual.
func TestReview04ManagedPreloadLibraries(t *testing.T) {
	withParameter := map[string]any{"primary": map[string]any{"configuration": "pgaudit.log = 'write'"}}
	got, err := splitComma("postgresqlSharedPreloadLibraries", "pgaudit", withParameter)
	if err != nil || len(got.Dropped) != 1 || got.Dropped[0].Kind != "handled" || got.Dropped[0].Note != "loaded automatically by CloudNativePG" {
		t.Fatalf("handled=%#v err=%v", got, err)
	}
	without, _ := splitComma("postgresqlSharedPreloadLibraries", "pgaudit", nil)
	if len(without.Dropped) != 1 || without.Dropped[0].Kind != "manual" {
		t.Fatalf("manual=%#v", without)
	}
}

// review 04 #10: empty values are explicitly incomplete and produce the
// required chart-default checklist item.
func TestReview04EmptyValuesIncomplete(t *testing.T) {
	c, route := postgresqlCatalog(t)
	p, err := Build(Input{"pg", "postgresql", "16.7.4", map[string]any{}}, c, route)
	if err != nil || len(p.Unmapped) != 1 || !strings.Contains(string(ChecklistMarkdown(p)), "no user values found; review the chart defaults") {
		t.Fatalf("plan=%#v err=%v", p, err)
	}
}

// review 04 #11: coverage counts only original user-set leaves; transform
// parser outcomes are counted separately as derived items.
func TestReview04CoverageUsesInputLeaves(t *testing.T) {
	c, route := postgresqlCatalog(t)
	values := map[string]any{"architecture": "standalone", "primary": map[string]any{"configuration": "listen_addresses='*'\npgaudit.log='write'"}}
	p, err := Build(Input{"pg", "postgresql", "16.7.4", values}, c, route)
	if err != nil || p.Coverage.Total != 2 || p.Coverage.Mapped != 2 || p.Coverage.Derived != 1 {
		t.Fatalf("coverage=%#v err=%v", p.Coverage, err)
	}
}

// review 04 #12: every human checklist string escapes controls and Unicode Cf.
func TestReview04ChecklistEscapesUnsafeText(t *testing.T) {
	c, route := postgresqlCatalog(t)
	p, err := Build(Input{"pg\x1b\u202ename", "postgresql", "16.7.4\u200f", map[string]any{"tls": map[string]any{"bad\x07\u200f": true}, "primary": map[string]any{"configuration": "name='bad\u202e'"}}}, c, route)
	if err != nil {
		t.Fatal(err)
	}
	jsonPlan, _ := JSON(p)
	table, _ := Table(p)
	target, _ := TargetYAML(p)
	unmapped, _ := UnmappedYAML(p)
	p.Checklist = append(p.Checklist, ChecklistItem{Text: "review\x07\u200fitem", Source: "https://example.test/\x1b"})
	out := bytes.Join([][]byte{jsonPlan, table, target, unmapped, ChecklistMarkdown(p)}, nil)
	for _, unsafe := range [][]byte{{0x1b}, {0x07}, []byte("\u202e"), []byte("\u200f")} {
		if bytes.Contains(out, unsafe) {
			t.Fatalf("unsafe bytes remain in %q", out)
		}
	}
}

// review 04 #13: md5 advice is conditional on an md5 rule and source major.
func TestReview04ConditionalMD5Checklist(t *testing.T) {
	for _, tc := range []struct {
		name string
		hba  string
		tag  any
		want int
	}{{"no md5", "host all all all scram-sha-256", nil, 0}, {"old", "host all all all md5", "13.9.0", 0}, {"new", "host all all all md5", "14.1.0", 1}, {"unknown", "host all all all md5", nil, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			all := map[string]any{}
			if tc.tag != nil {
				all["image"] = map[string]any{"tag": tc.tag}
			}
			got, err := splitLines("primary.pgHbaConfiguration", tc.hba, all)
			if err != nil || len(got.Checklist) != tc.want {
				t.Fatalf("checklist=%#v err=%v", got.Checklist, err)
			}
		})
	}
}

// review 04 #15: repository parse errors always select the first sorted path.
func TestReview04DeterministicRepoParseError(t *testing.T) {
	files := map[string][]byte{"z.yaml": []byte("["), "a.yaml": []byte("{")}
	for i := 0; i < 20; i++ {
		_, err := FindRepoRelease("pg", files, nil)
		if err == nil || !strings.Contains(err.Error(), "a.yaml") {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}
