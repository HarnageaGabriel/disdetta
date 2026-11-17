// Package cluster scans a Kubernetes cluster for Bitnami dependencies
// (spec v0.2). It reads through the consumer-defined Source interface so the
// collection logic stays pure and a fake clientset can drive the tests
// (ADR 0007).
package cluster

import "context"

// Container is one container image of a pod template (spec v0.2 section 2,
// tier 1). Containers, initContainers and ephemeralContainers all appear here.
type Container struct {
	Name  string
	Image string
}

// Owner is one ownerReference used to filter objects a controller already
// covers (spec v0.2 section 2, tier 1). Controller mirrors
// ownerReference.controller.
type Owner struct {
	Kind       string
	Name       string
	Controller bool
}

// Workload is one pod-template-bearing object (spec v0.2 section 2, tier 1):
// Deployment, StatefulSet, DaemonSet, ReplicaSet, Job or CronJob. Labels are the
// object labels merged with the pod template labels, where Helm sets the tier 2
// labels.
type Workload struct {
	Namespace  string
	Kind       string
	Name       string
	Labels     map[string]string
	Containers []Container
	Owners     []Owner
}

// Pod is one Pod object (spec v0.2 section 2, tier 1). Owned is true when the
// pod has a controller owner, in which case it is not a template source but its
// running imageIDs still feed the mirror attribute. OwnerChain is the pod's
// controller owner chain, outermost first, resolved from the objects of the same
// read so the mirror attribute is scoped to the owning workload (review 03 m2).
type Pod struct {
	Namespace  string
	Name       string
	Labels     map[string]string
	Containers []Container
	Status     []ContainerStatus
	Owned      bool
	OwnerChain []Owner
}

// ContainerStatus is one running status.containerStatuses entry of a Pod
// (spec v0.2 section 2, tier 1).
type ContainerStatus struct {
	Name    string
	Image   string
	ImageID string
}

// Workloads is the tier 1 and 2 object set of one cluster read.
type Workloads struct {
	Templates []Workload
	Pods      []Pod
}

// Release is one Helm release read from a Secret (spec v0.2 section 2, tier 3).
// Payload is the raw data.release value, which the scan decodes with bounded
// decoding; it is never printed.
type Release struct {
	Namespace string
	Name      string
	Payload   []byte
}

// ListFailure is one list call that could not be completed (spec v0.2 section
// 4). Forbidden reports an RBAC denial, which is a warning; any other failure is
// an error. It never carries object content.
type ListFailure struct {
	Tier      int
	Resource  string
	Namespace string
	Forbidden bool
	// Code is the diagnostic code of the failure. An empty code is
	// DSD-SCN-010, the code of a list that failed.
	Code string
	// Detail names the limit or the status that stopped the list. It never
	// carries server content.
	Detail string
	// Deadline marks a list that the total time budget of the scan cut short.
	// The scan reports one budget diagnostic instead of one diagnostic per
	// list (spec v0.2 section 4).
	Deadline bool
}

// Source lists the objects the cluster scan reads (ADR 0007). Implementations
// must issue only get and list verbs; the scan never writes. A Source returns
// the objects it could read together with one ListFailure per list that could
// not complete, so a partial read still produces a report.
type Source interface {
	ListWorkloads(ctx context.Context, namespaces []string) (Workloads, []ListFailure)
	ListReleases(ctx context.Context, namespaces []string) ([]Release, []ListFailure)
}
