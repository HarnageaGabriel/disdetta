package cluster

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

// listOptions returns the Limit, LabelSelector, FieldSelector and Continue of a
// list action, whichever concrete action type client-go uses.
func listOptions(action k8stesting.Action) (int64, string, string, string, bool) {
	switch a := action.(type) {
	case k8stesting.ListActionImpl:
		return a.ListOptions.Limit, a.ListOptions.LabelSelector, a.ListOptions.FieldSelector, a.ListOptions.Continue, true
	case *k8stesting.ListActionImpl:
		return a.ListOptions.Limit, a.ListOptions.LabelSelector, a.ListOptions.FieldSelector, a.ListOptions.Continue, true
	}
	return 0, "", "", "", false
}

// TestClientSourceReadOnly asserts the source issues only get and list verbs
// (spec v0.2 section 4, threat model T8).
func TestClientSourceReadOnly(t *testing.T) {
	source, client := newSource(t, recordedObjects(t)...)
	verbs := map[string]bool{}
	client.PrependReactor("*", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		verbs[action.GetVerb()] = true
		if action.GetVerb() != "get" && action.GetVerb() != "list" {
			t.Errorf("source docs/spec/v0.2-cluster.md section 4 (threat model T8): verb %q on %s", action.GetVerb(), action.GetResource().Resource)
			return true, nil, errors.New("unexpected verb")
		}
		return false, nil, nil
	})
	ctx := context.Background()
	if _, failures := source.ListWorkloads(ctx, nil); len(failures) != 0 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: failures %#v", failures)
	}
	if _, failures := source.ListReleases(ctx, nil); len(failures) != 0 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: failures %#v", failures)
	}
	if !verbs["list"] {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: no list verb observed")
	}
	if verbs["get"] {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: tier reads must be lists, not gets")
	}
}

// TestClientSourceListOptions asserts every list uses the page size of spec
// v0.2 section 4, and that release Secrets use the smaller tier 3 page with both
// server-side selectors (review 03 M1).
func TestClientSourceListOptions(t *testing.T) {
	source, client := newSource(t, recordedObjects(t)...)
	lists := 0
	secretSelector, secretFieldSelector := "", ""
	client.PrependReactor("list", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		limit, selector, fieldSelector, _, ok := listOptions(action)
		if !ok {
			t.Errorf("source docs/spec/v0.2-cluster.md section 4: no list options on %T", action)
			return false, nil, nil
		}
		lists++
		if action.GetResource().Resource == "secrets" {
			secretSelector, secretFieldSelector = selector, fieldSelector
			if limit != releaseListLimit {
				t.Errorf("review 03 M1: secret list limit %d want %d", limit, releaseListLimit)
			}
			return false, nil, nil
		}
		if limit != ListLimit {
			t.Errorf("source docs/spec/v0.2-cluster.md section 4: list limit %d want %d", limit, ListLimit)
		}
		return false, nil, nil
	})
	ctx := context.Background()
	source.ListWorkloads(ctx, nil)
	source.ListReleases(ctx, nil)
	if lists == 0 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: no lists issued")
	}
	if secretSelector != helmReleaseLabelSelector || secretFieldSelector != helmReleaseFieldSelector {
		t.Fatalf("review 03 M1: secret selectors %q %q", secretSelector, secretFieldSelector)
	}
}

// TestClientSourcePagination asserts a list continues across pages with the
// continuation token (spec v0.2 section 4).
func TestClientSourcePagination(t *testing.T) {
	source, client := newSource(t)
	calls := 0
	var limits []int64
	var continues []string
	client.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		limit, _, _, cont, _ := listOptions(action)
		limits = append(limits, limit)
		continues = append(continues, cont)
		list := &corev1.PodList{}
		if calls == 1 {
			list.Continue = "page-2"
			list.Items = []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "db"}}}
		} else {
			list.Items = []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "db"}}}
		}
		return true, list, nil
	})
	workloads, failures := source.ListWorkloads(context.Background(), []string{"db"})
	if len(failures) != 0 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: failures %#v", failures)
	}
	if calls != 2 || len(workloads.Pods) != 2 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: calls %d pods %d", calls, len(workloads.Pods))
	}
	if len(continues) != 2 || continues[0] != "" || continues[1] != "page-2" {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: continue tokens %v", continues)
	}
	for _, limit := range limits {
		if limit != ListLimit {
			t.Fatalf("source docs/spec/v0.2-cluster.md section 4: list limit %d", limit)
		}
	}
}

// TestClientSourceOwnerFiltering asserts the tier 1 template sources: every
// workload kind, the CronJob jobTemplate, ephemeral containers, and the
// owner-based skips that avoid double counting (spec v0.2 section 2).
func TestClientSourceOwnerFiltering(t *testing.T) {
	source, _ := newSource(t, recordedObjects(t)...)
	workloads, failures := source.ListWorkloads(context.Background(), nil)
	if len(failures) != 0 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 2: failures %#v", failures)
	}
	templates := map[string]Workload{}
	for _, w := range workloads.Templates {
		templates[w.Kind+"/"+w.Namespace+"/"+w.Name] = w
	}
	for _, skipped := range []string{"ReplicaSet/shop/web-7d9c", "Job/db/nightly-28917420"} {
		if _, ok := templates[skipped]; ok {
			t.Errorf("source docs/spec/v0.2-cluster.md section 2 (owner filtering): %s must be skipped", skipped)
		}
	}
	for _, want := range []string{"Deployment/shop/web", "StatefulSet/db/pg", "DaemonSet/kube-system/agent", "ReplicaSet/db/standalone-rs", "Job/db/migrate", "CronJob/db/nightly"} {
		if _, ok := templates[want]; !ok {
			t.Errorf("source docs/spec/v0.2-cluster.md section 2 tier 1: missing %s", want)
		}
	}
	cronJob := templates["CronJob/db/nightly"]
	if len(cronJob.Containers) != 1 || cronJob.Containers[0].Image != "bitnami/kubectl:latest" {
		t.Errorf("source docs/spec/v0.2-cluster.md section 2 tier 1: CronJob jobTemplate containers %#v", cronJob.Containers)
	}
	web := templates["Deployment/shop/web"]
	images := map[string]string{}
	for _, c := range web.Containers {
		images[c.Name] = c.Image
	}
	for name, image := range map[string]string{"web": "bitnami/nginx:1.25.3", "sidecar": "bitnamilegacy/os-shell:1", "debug": "bitnamilegacy/kubectl:1.29"} {
		if images[name] != image {
			t.Errorf("source docs/spec/v0.2-cluster.md section 2 tier 1 (ephemeral containers): %s=%q", name, images[name])
		}
	}
	pods := map[string]Pod{}
	for _, p := range workloads.Pods {
		pods[p.Namespace+"/"+p.Name] = p
	}
	if len(workloads.Pods) != 3 {
		t.Errorf("source docs/spec/v0.2-cluster.md section 2 tier 1: %d pods, want 3", len(workloads.Pods))
	}
	if !pods["shop/web-abc123"].Owned {
		t.Errorf("source docs/spec/v0.2-cluster.md section 2 tier 1: controller-owned pod must be flagged Owned")
	}
	if pods["db/pg-0"].Owned || pods["db/cache-0"].Owned {
		t.Errorf("source docs/spec/v0.2-cluster.md section 2 tier 1: standalone pods must not be Owned")
	}
}

// TestClientSourceReleaseLatestRevision asserts tier 3 keeps the latest deployed
// revision per release (spec v0.2 section 2).
func TestClientSourceReleaseLatestRevision(t *testing.T) {
	source, _ := newSource(t, recordedObjects(t)...)
	releases, failures := source.ListReleases(context.Background(), nil)
	if len(failures) != 0 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 2 tier 3: failures %#v", failures)
	}
	if len(releases) != 1 || releases[0].Namespace != "db" || releases[0].Name != "pg" {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 2 tier 3: %#v", releases)
	}
	decoded, err := DecodeReleasePayload(releases[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(decoded, []byte(`"version":2`)) {
		t.Errorf("source docs/spec/v0.2-cluster.md section 2 tier 3: kept the wrong revision: %s", decoded)
	}
}

// TestClientSourceForbidden asserts an RBAC denial is a ListFailure flagged
// Forbidden and the read of other kinds continues (spec v0.2 section 4).
func TestClientSourceForbidden(t *testing.T) {
	source, client := newSource(t, recordedObjects(t)...)
	client.PrependReactor("list", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "deployments"}, "web", errors.New("denied"))
	})
	workloads, failures := source.ListWorkloads(context.Background(), nil)
	if len(failures) != 1 || !failures[0].Forbidden || failures[0].Tier != 1 || failures[0].Resource != "deployments" {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: failures %#v", failures)
	}
	if len(workloads.Templates) == 0 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: scan did not continue after a forbidden list")
	}
}

// TestClientSourceOwnerChain checks review 03 m2: a Pod's controller owner chain
// is resolved through the listed ReplicaSet to the Deployment that owns it, so
// the mirror attribute can be scoped to the owning workload.
func TestClientSourceOwnerChain(t *testing.T) {
	source, _ := newSource(t, recordedObjects(t)...)
	workloads, failures := source.ListWorkloads(context.Background(), nil)
	if len(failures) != 0 {
		t.Fatalf("review 03 m2: failures %#v", failures)
	}
	want := []Owner{{Kind: "Deployment", Name: "web"}, {Kind: "ReplicaSet", Name: "web-7d9c"}}
	for _, p := range workloads.Pods {
		if p.Namespace != "shop" || p.Name != "web-abc123" {
			continue
		}
		if len(p.OwnerChain) != len(want) {
			t.Fatalf("review 03 m2: owner chain %#v want %#v", p.OwnerChain, want)
		}
		for i := range want {
			if p.OwnerChain[i] != want[i] {
				t.Fatalf("review 03 m2: owner chain %#v want %#v", p.OwnerChain, want)
			}
		}
		return
	}
	t.Fatalf("review 03 m2: pod shop/web-abc123 not found")
}

// TestClientSourceReleaseSecretFilters checks review 03 M1 and m6: the tier 3
// list sends the deployed-Helm label selector and the release-type field
// selector, keeps the highest numeric deployed revision, and never decodes a
// non-Helm Secret that carries owner=helm.
func TestClientSourceReleaseSecretFilters(t *testing.T) {
	helmRelease := func(name, version string, payload []byte) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "db", Labels: map[string]string{
				"owner": "helm", "name": "pg", "version": version, "status": "deployed",
			}},
			Type: corev1.SecretType(helmReleaseSecretType),
			Data: map[string][]byte{"release": payload},
		}
	}
	v9 := releasePayload(t, `{"chart":{"metadata":{"name":"pg","version":"9.0.0"}}}`)
	v10 := releasePayload(t, `{"chart":{"metadata":{"name":"pg","version":"10.0.0"}}}`)
	opaque := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "sh.helm.release.v1.pg.v99", Namespace: "db", Labels: map[string]string{
			"owner": "helm", "name": "pg", "version": "99", "status": "deployed",
		}},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"release": []byte("!!!not-base64!!!")},
	}
	source, client := newSource(t,
		helmRelease("sh.helm.release.v1.pg.v9", "9", v9),
		helmRelease("sh.helm.release.v1.pg.v10", "10", v10),
		opaque,
	)
	var label, field string
	client.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		_, label, field, _, _ = listOptions(action)
		return false, nil, nil
	})
	releases, failures := source.ListReleases(context.Background(), nil)
	if len(failures) != 0 {
		t.Fatalf("review 03 M1: failures %#v", failures)
	}
	if label != helmReleaseLabelSelector || field != helmReleaseFieldSelector {
		t.Fatalf("review 03 M1: selectors %q %q", label, field)
	}
	if len(releases) != 1 || releases[0].Name != "pg" || !bytes.Equal(releases[0].Payload, v10) {
		t.Fatalf("review 03 M1: highest deployed revision not selected: %#v", releases)
	}
	// The Opaque Secret carries an undecodable payload: decoding it would report
	// DSD-SCN-009, so its absence proves it is never decoded (review 03 m6).
	got, err := Scan(context.Background(), source, Options{ReadHelmSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range got.Diagnostics {
		if d.Code == "DSD-SCN-009" {
			t.Fatalf("review 03 m6: a non-Helm Secret was decoded: %#v", d)
		}
	}
}

// TestClientSourceListTimeoutBoundsWholeList checks review 03 m8: the timeout
// bounds the whole paginated list, so a server that keeps returning a
// continuation token cannot extend the read page after page.
func TestClientSourceListTimeoutBoundsWholeList(t *testing.T) {
	source, client := newSource(t)
	source.timeout = 150 * time.Millisecond
	calls := 0
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		time.Sleep(30 * time.Millisecond)
		return true, &corev1.PodList{ListMeta: metav1.ListMeta{Continue: "next"}}, nil
	})
	start := time.Now()
	_, failures := source.ListWorkloads(context.Background(), []string{"db"})
	elapsed := time.Since(start)
	if calls == 0 || calls > 20 || elapsed > 5*time.Second {
		t.Fatalf("review 03 m8: paging did not stop on the whole-list timeout: calls=%d elapsed=%s", calls, elapsed)
	}
	if len(failures) != 1 || failures[0].Forbidden || failures[0].Resource != "pods" || failures[0].Tier != 1 {
		t.Fatalf("review 03 m8: failures %#v", failures)
	}
}

// TestClientSourceListStopsOnCancellation checks review 03 m8: paging stops as
// soon as the parent context is done instead of issuing another page.
func TestClientSourceListStopsOnCancellation(t *testing.T) {
	source, client := newSource(t)
	source.timeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	client.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		cancel()
		return true, &corev1.PodList{ListMeta: metav1.ListMeta{Continue: "next"}}, nil
	})
	_, failures := source.ListWorkloads(ctx, []string{"db"})
	if calls != 1 {
		t.Fatalf("review 03 m8: paging continued after cancellation: calls=%d", calls)
	}
	if len(failures) != 1 || failures[0].Resource != "pods" {
		t.Fatalf("review 03 m8: failures %#v", failures)
	}
}
