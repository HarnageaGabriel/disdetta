package cluster

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/fake"
)

// recordedObjects reads the recorded cluster fixture and decodes every document
// into a typed Kubernetes object, so the tests drive the scan with real API
// objects through the fake clientset (spec v0.2 section 6).
func recordedObjects(t *testing.T) []runtime.Object {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "cluster", "basic", "objects.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []runtime.Object
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("source docs/spec/v0.2-cluster.md section 6: decode %s: %v", path, err)
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var meta metav1.TypeMeta
		if err := json.Unmarshal(raw, &meta); err != nil {
			t.Fatal(err)
		}
		out = append(out, decodeObject(t, meta.Kind, raw))
	}
	if len(out) == 0 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 6: %s has no objects", path)
	}
	return out
}

// decodeObject decodes one recorded document by kind, the objects tier 1-3 read
// (spec v0.2 section 2).
func decodeObject(t *testing.T, kind string, raw json.RawMessage) runtime.Object {
	t.Helper()
	switch kind {
	case "Deployment":
		var object appsv1.Deployment
		mustUnmarshal(t, raw, &object)
		return &object
	case "StatefulSet":
		var object appsv1.StatefulSet
		mustUnmarshal(t, raw, &object)
		return &object
	case "DaemonSet":
		var object appsv1.DaemonSet
		mustUnmarshal(t, raw, &object)
		return &object
	case "ReplicaSet":
		var object appsv1.ReplicaSet
		mustUnmarshal(t, raw, &object)
		return &object
	case "Job":
		var object batchv1.Job
		mustUnmarshal(t, raw, &object)
		return &object
	case "CronJob":
		var object batchv1.CronJob
		mustUnmarshal(t, raw, &object)
		return &object
	case "Pod":
		var object corev1.Pod
		mustUnmarshal(t, raw, &object)
		return &object
	case "Secret":
		var object corev1.Secret
		mustUnmarshal(t, raw, &object)
		return &object
	default:
		t.Fatalf("recorded fixture has unexpected kind %q", kind)
		return nil
	}
}

func mustUnmarshal(t *testing.T, raw json.RawMessage, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode recorded object: %v", err)
	}
}

// newSource builds a ClientSource over a fake clientset holding objects, the way
// the CLI builds one over client-go but without a cluster (ADR 0007). It returns
// both the Source and the concrete fake so tests can add reactors.
func newSource(t *testing.T, objects ...runtime.Object) (*ClientSource, *fake.Clientset) {
	t.Helper()
	client := fake.NewSimpleClientset(objects...)
	return &ClientSource{client: client, timeout: 5 * time.Second}, client
}
