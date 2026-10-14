package catalog

import "testing"

func TestCatalogContainsSpecifiedComponents(t *testing.T) { // Source: docs/spec/v0.1.md section 2.3.
	want := []string{"postgresql", "postgresql-repmgr", "redis", "redis-cluster", "redis-sentinel", "valkey", "valkey-cluster", "kafka", "mongodb", "mongodb-sharded", "keycloak", "mariadb", "mariadb-galera", "mysql", "rabbitmq", "elasticsearch", "opensearch", "cassandra", "zookeeper", "etcd", "minio", "clickhouse", "influxdb", "os-shell", "bitnami-shell", "kubectl", "git", "nginx"}
	got := map[string]bool{}
	for _, n := range Names() {
		got[n] = true
	}
	for _, n := range want {
		if !got[n] {
			t.Errorf("missing %s", n)
		}
	}
}
