package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// helmReleaseSecretType is the Secret type Helm uses for release storage
// (research notes section 9).
const helmReleaseSecretType = "helm.sh/release.v1"

// defaultRequestTimeout bounds one request when the scan budget leaves more time
// (spec v0.2 section 4).
const defaultRequestTimeout = 30 * time.Second

// releaseListLimit is the page size for the tier 3 Secret list. It is smaller
// than ListLimit so one page of Secret payloads stays bounded (review 03 M1).
const releaseListLimit = 50

// The bounds a hostile API server cannot pass (adversarial audit F1). Every
// bound is reported, never a silent truncation.
//
// MaxListResponseBytes is the hard limit on the bytes one list response may
// deliver. The response is never transparently decompressed, so a compressed
// body is read as it arrives and cannot expand.
const MaxListResponseBytes = 64 << 20

// MaxItemsPerList is the largest number of items one list accumulates. A list
// that reaches it stops with a DSD-SCN-005 diagnostic.
const MaxItemsPerList = 100000

// MaxPagesPerList is the largest number of pages one list fetches. A server
// that always answers with a continuation token stops at this cap with a
// DSD-SCN-005 diagnostic.
const MaxPagesPerList = 1000

// Tier 3 Secret selectors: the server filters to deployed Helm release Secrets
// by label and to the release type by field (Secrets support the type field
// selector), and the client re-checks the type as defense in depth (review 03
// M1, spec v0.2 section 2).
const (
	helmReleaseLabelSelector = "owner=helm,status=deployed"
	helmReleaseFieldSelector = "type=" + helmReleaseSecretType
)

// ClientSource is the client-go implementation of Source (ADR 0007). It issues
// list calls only, paginated with ListLimit (releaseListLimit for tier 3
// Secrets) and bounded by a per-request timeout.
type ClientSource struct {
	client  kubernetes.Interface
	timeout time.Duration
}

// NewClientSource builds a read-only Source using the kubectl kubeconfig
// resolution rules (--kubeconfig, KUBECONFIG, ~/.kube/config) and the optional
// context (spec v0.2 section 1). It never contacts the cluster.
func NewClientSource(opts Options) (Source, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.Kubeconfig != "" {
		rules.ExplicitPath = opts.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if opts.Context != "" {
		overrides.CurrentContext = opts.Context
	}
	deferred := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	config, err := deferred.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	if opts.DenyExecPlugins {
		if err := refuseExecPlugins(deferred, overrides, config); err != nil {
			return nil, err
		}
	}
	// The API server is untrusted for content (threat model T2, audit F1):
	// no transparent decompression and a hard limit on every response body.
	config.DisableCompression = true
	config.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		return &hardeningTransport{base: rt}
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	return &ClientSource{client: client, timeout: defaultRequestTimeout}, nil
}

// refuseExecPlugins refuses a kubeconfig whose selected user runs a credential
// plugin: client-go executes the command of an exec provider and the binary of
// an auth provider, so a hostile kubeconfig runs a program on the machine of
// the scan (threat model T13, audit F3). The check runs before the client is
// built, so no plugin ever runs.
func refuseExecPlugins(deferred clientcmd.ClientConfig, overrides *clientcmd.ConfigOverrides, config *rest.Config) error {
	name := selectedUserName(deferred, overrides)
	switch {
	case config.ExecProvider != nil:
		return fmt.Errorf("kubeconfig user %q uses an exec credential plugin, which runs a program; --deny-exec-plugins refuses it", name)
	case config.AuthProvider != nil:
		return fmt.Errorf("kubeconfig user %q uses an auth provider plugin, which runs a program; --deny-exec-plugins refuses it", name)
	}
	return nil
}

// selectedUserName returns the name of the user the selected context uses, or
// an empty name when the kubeconfig names none.
func selectedUserName(deferred clientcmd.ClientConfig, overrides *clientcmd.ConfigOverrides) string {
	raw, err := deferred.RawConfig()
	if err != nil {
		return ""
	}
	contextName := overrides.CurrentContext
	if contextName == "" {
		contextName = raw.CurrentContext
	}
	if contextName == "" {
		return ""
	}
	kubeContext, ok := raw.Contexts[contextName]
	if !ok {
		return ""
	}
	return kubeContext.AuthInfo
}

// hardeningTransport wraps the client-go transport so a hostile API server
// cannot make the scan allocate unbounded memory and cannot redirect the
// bearer token to another endpoint (audit F1, F4).
type hardeningTransport struct {
	base http.RoundTripper
}

// RoundTrip refuses a redirect answer and bounds the body of every other
// answer.
func (t *hardeningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Accept-Encoding") == "" {
		// client-go falls back to http.DefaultTransport when the kubeconfig
		// needs no TLS option, and that transport ignores DisableCompression.
		// Asking for the identity encoding keeps the answer uncompressed
		// whatever transport is below, so no body is ever transparently
		// expanded (audit F1).
		req = req.Clone(req.Context())
		req.Header.Set("Accept-Encoding", "identity")
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// client-go owns the http.Client, so the redirect policy is enforced
		// here: a 3xx answer is refused, never followed, and the Location is
		// never read. The bearer token never leaves the API server.
		_ = resp.Body.Close()
		return nil, &redirectError{status: resp.StatusCode}
	}
	if resp.Body != nil {
		resp.Body = &limitedBody{body: resp.Body}
	}
	return resp, nil
}

// limitedBody reads at most MaxListResponseBytes bytes of a response body and
// fails the read when the limit is passed, so an over-limit response is an
// error and never a silent truncation (audit F1).
type limitedBody struct {
	body io.ReadCloser
	read int64
}

// Read reads one chunk and fails when the limit is passed.
func (b *limitedBody) Read(p []byte) (int, error) {
	if b.read >= MaxListResponseBytes {
		return 0, errResponseTooLarge
	}
	if remaining := MaxListResponseBytes - b.read + 1; int64(len(p)) > remaining {
		p = p[:int(remaining)]
	}
	n, err := b.body.Read(p)
	b.read += int64(n)
	if b.read > MaxListResponseBytes {
		return 0, errResponseTooLarge
	}
	return n, err
}

// Close closes the underlying body.
func (b *limitedBody) Close() error {
	return b.body.Close()
}

// errResponseTooLarge marks a response body over MaxListResponseBytes.
var errResponseTooLarge = fmt.Errorf("response body over the MaxListResponseBytes limit of %d bytes", MaxListResponseBytes)

// errItemLimit marks a list that reached MaxItemsPerList.
var errItemLimit = fmt.Errorf("list reached the MaxItemsPerList limit of %d items", MaxItemsPerList)

// errPageLimit marks a list that reached MaxPagesPerList.
var errPageLimit = fmt.Errorf("list reached the MaxPagesPerList limit of %d pages", MaxPagesPerList)

// redirectError marks a 3xx answer the client refuses to follow.
type redirectError struct {
	status int
}

// Error names the status of the refused redirect and never the Location.
func (e *redirectError) Error() string {
	return fmt.Sprintf("redirect response status %d is not followed", e.status)
}

// ListWorkloads reads the tier 1 and 2 objects (spec v0.2 section 2). A kind or
// namespace that cannot be listed yields a ListFailure and the read continues.
func (s *ClientSource) ListWorkloads(ctx context.Context, namespaces []string) (Workloads, []ListFailure) {
	var out Workloads
	var failures []ListFailure
	// owners carries every listed object's ownerReferences so a Pod's controller
	// owner chain can be resolved to its workload (review 03 m2). Pods are listed
	// last, after the intermediate owners they may point at.
	owners := ownerIndex{}
	for _, namespace := range namespaceTargets(namespaces) {
		out.Templates = append(out.Templates, s.deployments(ctx, namespace, owners, &failures)...)
		out.Templates = append(out.Templates, s.statefulSets(ctx, namespace, owners, &failures)...)
		out.Templates = append(out.Templates, s.daemonSets(ctx, namespace, owners, &failures)...)
		out.Templates = append(out.Templates, s.replicaSets(ctx, namespace, owners, &failures)...)
		out.Templates = append(out.Templates, s.jobs(ctx, namespace, owners, &failures)...)
		out.Templates = append(out.Templates, s.cronJobs(ctx, namespace, owners, &failures)...)
		out.Pods = append(out.Pods, s.pods(ctx, namespace, owners, &failures)...)
	}
	return out, failures
}

// ListReleases reads the tier 3 Helm release Secrets, keeping the latest
// deployed revision per release (spec v0.2 section 2).
func (s *ClientSource) ListReleases(ctx context.Context, namespaces []string) ([]Release, []ListFailure) {
	var out []Release
	var failures []ListFailure
	for _, namespace := range namespaceTargets(namespaces) {
		out = append(out, s.releaseSecrets(ctx, namespace, &failures)...)
	}
	return out, failures
}

func (s *ClientSource) deployments(ctx context.Context, namespace string, owners ownerIndex, failures *[]ListFailure) []Workload {
	var out []Workload
	err := s.listPages(ctx, ListLimit, func(pageCtx context.Context, opts metav1.ListOptions, budget *listBudget) (string, error) {
		list, err := s.client.AppsV1().Deployments(namespace).List(pageCtx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			item := &list.Items[i]
			indexOwners(owners, item.Namespace, "Deployment", item.Name, item.OwnerReferences)
			if !budget.add() {
				return "", errItemLimit
			}
			out = append(out, newWorkload(item, "Deployment", item.Spec.Template.Spec, item.Spec.Template.Labels))
		}
		return list.Continue, nil
	})
	if err != nil {
		*failures = append(*failures, listFailure(1, "deployments", namespace, err))
	}
	return out
}

func (s *ClientSource) statefulSets(ctx context.Context, namespace string, owners ownerIndex, failures *[]ListFailure) []Workload {
	var out []Workload
	err := s.listPages(ctx, ListLimit, func(pageCtx context.Context, opts metav1.ListOptions, budget *listBudget) (string, error) {
		list, err := s.client.AppsV1().StatefulSets(namespace).List(pageCtx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			item := &list.Items[i]
			indexOwners(owners, item.Namespace, "StatefulSet", item.Name, item.OwnerReferences)
			if !budget.add() {
				return "", errItemLimit
			}
			out = append(out, newWorkload(item, "StatefulSet", item.Spec.Template.Spec, item.Spec.Template.Labels))
		}
		return list.Continue, nil
	})
	if err != nil {
		*failures = append(*failures, listFailure(1, "statefulsets", namespace, err))
	}
	return out
}

func (s *ClientSource) daemonSets(ctx context.Context, namespace string, owners ownerIndex, failures *[]ListFailure) []Workload {
	var out []Workload
	err := s.listPages(ctx, ListLimit, func(pageCtx context.Context, opts metav1.ListOptions, budget *listBudget) (string, error) {
		list, err := s.client.AppsV1().DaemonSets(namespace).List(pageCtx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			item := &list.Items[i]
			indexOwners(owners, item.Namespace, "DaemonSet", item.Name, item.OwnerReferences)
			if !budget.add() {
				return "", errItemLimit
			}
			out = append(out, newWorkload(item, "DaemonSet", item.Spec.Template.Spec, item.Spec.Template.Labels))
		}
		return list.Continue, nil
	})
	if err != nil {
		*failures = append(*failures, listFailure(1, "daemonsets", namespace, err))
	}
	return out
}

func (s *ClientSource) replicaSets(ctx context.Context, namespace string, owners ownerIndex, failures *[]ListFailure) []Workload {
	var out []Workload
	err := s.listPages(ctx, ListLimit, func(pageCtx context.Context, opts metav1.ListOptions, budget *listBudget) (string, error) {
		list, err := s.client.AppsV1().ReplicaSets(namespace).List(pageCtx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			item := &list.Items[i]
			indexOwners(owners, item.Namespace, "ReplicaSet", item.Name, item.OwnerReferences)
			// A ReplicaSet owned by a Deployment duplicates its template
			// (spec v0.2 section 2, owner filtering).
			if ownedBy(item.OwnerReferences, "Deployment") {
				continue
			}
			if !budget.add() {
				return "", errItemLimit
			}
			out = append(out, newWorkload(item, "ReplicaSet", item.Spec.Template.Spec, item.Spec.Template.Labels))
		}
		return list.Continue, nil
	})
	if err != nil {
		*failures = append(*failures, listFailure(1, "replicasets", namespace, err))
	}
	return out
}

func (s *ClientSource) jobs(ctx context.Context, namespace string, owners ownerIndex, failures *[]ListFailure) []Workload {
	var out []Workload
	err := s.listPages(ctx, ListLimit, func(pageCtx context.Context, opts metav1.ListOptions, budget *listBudget) (string, error) {
		list, err := s.client.BatchV1().Jobs(namespace).List(pageCtx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			item := &list.Items[i]
			indexOwners(owners, item.Namespace, "Job", item.Name, item.OwnerReferences)
			// A Job owned by a CronJob duplicates its jobTemplate (spec v0.2
			// section 2, owner filtering).
			if ownedBy(item.OwnerReferences, "CronJob") {
				continue
			}
			if !budget.add() {
				return "", errItemLimit
			}
			out = append(out, newWorkload(item, "Job", item.Spec.Template.Spec, item.Spec.Template.Labels))
		}
		return list.Continue, nil
	})
	if err != nil {
		*failures = append(*failures, listFailure(1, "jobs", namespace, err))
	}
	return out
}

func (s *ClientSource) cronJobs(ctx context.Context, namespace string, owners ownerIndex, failures *[]ListFailure) []Workload {
	var out []Workload
	err := s.listPages(ctx, ListLimit, func(pageCtx context.Context, opts metav1.ListOptions, budget *listBudget) (string, error) {
		list, err := s.client.BatchV1().CronJobs(namespace).List(pageCtx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			item := &list.Items[i]
			indexOwners(owners, item.Namespace, "CronJob", item.Name, item.OwnerReferences)
			if !budget.add() {
				return "", errItemLimit
			}
			out = append(out, newWorkload(item, "CronJob", item.Spec.JobTemplate.Spec.Template.Spec, item.Spec.JobTemplate.Spec.Template.Labels))
		}
		return list.Continue, nil
	})
	if err != nil {
		*failures = append(*failures, listFailure(1, "cronjobs", namespace, err))
	}
	return out
}

func (s *ClientSource) pods(ctx context.Context, namespace string, owners ownerIndex, failures *[]ListFailure) []Pod {
	var out []Pod
	err := s.listPages(ctx, ListLimit, func(pageCtx context.Context, opts metav1.ListOptions, budget *listBudget) (string, error) {
		list, err := s.client.CoreV1().Pods(namespace).List(pageCtx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			if !budget.add() {
				return "", errItemLimit
			}
			out = append(out, newPod(owners, &list.Items[i]))
		}
		return list.Continue, nil
	})
	if err != nil {
		*failures = append(*failures, listFailure(1, "pods", namespace, err))
	}
	return out
}

// helmRevision is one stored Helm release revision (spec v0.2 section 2, tier 3).
type helmRevision struct {
	namespace string
	name      string
	payload   []byte
	version   int
	deployed  bool
}

// releaseSecrets reads Helm release Secrets and keeps the highest-version
// deployed revision per release (spec v0.2 section 2). The list is server-side
// filtered to deployed Helm releases and paginated at releaseListLimit, and only
// one candidate payload per release name is held at a time, so a long revision
// history is never retained (review 03 M1). Only the raw payload is carried;
// decoding happens in the pure layer (spec v0.2 section 4).
func (s *ClientSource) releaseSecrets(ctx context.Context, namespace string, failures *[]ListFailure) []Release {
	best := map[string]helmRevision{}
	err := s.listPages(ctx, releaseListLimit, func(pageCtx context.Context, opts metav1.ListOptions, budget *listBudget) (string, error) {
		opts.LabelSelector = helmReleaseLabelSelector
		opts.FieldSelector = helmReleaseFieldSelector
		list, err := s.client.CoreV1().Secrets(namespace).List(pageCtx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			secret := &list.Items[i]
			// Defense in depth: the field selector excludes non-Helm Secrets, but
			// a server may ignore it (spec v0.2 section 2).
			if string(secret.Type) != helmReleaseSecretType {
				continue
			}
			name := secret.Labels["name"]
			payload := secret.Data["release"]
			if name == "" || len(payload) == 0 {
				continue
			}
			if !budget.add() {
				return "", errItemLimit
			}
			version, _ := strconv.Atoi(secret.Labels["version"])
			key := secret.Namespace + "\x00" + name
			revision := helmRevision{
				namespace: secret.Namespace,
				name:      name,
				payload:   payload,
				version:   version,
				deployed:  secret.Labels["status"] == "deployed",
			}
			if current, ok := best[key]; !ok || betterRevision(revision, current) {
				best[key] = revision
			}
		}
		return list.Continue, nil
	})
	if err != nil {
		*failures = append(*failures, listFailure(3, "secrets", namespace, err))
	}
	keys := make([]string, 0, len(best))
	for key := range best {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]Release, 0, len(keys))
	for _, key := range keys {
		chosen := best[key]
		out = append(out, Release{Namespace: chosen.namespace, Name: chosen.name, Payload: chosen.payload})
	}
	return out
}

// betterRevision reports whether candidate should replace best: a deployed
// revision beats a non-deployed one, otherwise the higher version wins.
func betterRevision(candidate, best helmRevision) bool {
	if candidate.deployed != best.deployed {
		return candidate.deployed
	}
	return candidate.version > best.version
}

// listBudget counts the items and the pages one list may consume.
type listBudget struct {
	items int
	pages int
}

// add reserves one item of the list and reports false when the item cap is
// reached (audit F1).
func (b *listBudget) add() bool {
	if b.items >= MaxItemsPerList {
		return false
	}
	b.items++
	return true
}

// listPages runs fn for every page of one paginated list. Each request is
// bounded by the per-request timeout and by the remaining scan budget, and the
// list stops at the page cap (audit F1). It stops at the first error and
// returns it.
func (s *ClientSource) listPages(ctx context.Context, limit int64, fn func(ctx context.Context, opts metav1.ListOptions, budget *listBudget) (string, error)) error {
	requestCtx, cancel := context.WithTimeout(ctx, s.requestTimeout(ctx))
	defer cancel()
	budget := &listBudget{}
	cont := ""
	for {
		if err := requestCtx.Err(); err != nil {
			return err
		}
		next, err := fn(requestCtx, metav1.ListOptions{Limit: limit, Continue: cont}, budget)
		if err != nil {
			if ctxErr := requestCtx.Err(); ctxErr != nil {
				// The scan budget ended the request: report the budget, not
				// the API error.
				return ctxErr
			}
			return err
		}
		budget.pages++
		if next == "" {
			return nil
		}
		if budget.pages >= MaxPagesPerList {
			return errPageLimit
		}
		cont = next
	}
}

// requestTimeout returns the timeout of one request: the smaller of the
// remaining scan budget and the per-request cap (audit F2).
func (s *ClientSource) requestTimeout(ctx context.Context) time.Duration {
	timeout := s.timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < timeout {
			timeout = remaining
		}
	}
	if timeout <= 0 {
		timeout = time.Nanosecond
	}
	return timeout
}

// namespaceTargets returns the namespaces to list: the requested ones in sorted
// order, or a single empty string meaning all namespaces the identity can list
// (spec v0.2 section 1).
func namespaceTargets(namespaces []string) []string {
	if len(namespaces) == 0 {
		return []string{""}
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(namespaces))
	for _, namespace := range namespaces {
		if namespace == "" || seen[namespace] {
			continue
		}
		seen[namespace] = true
		out = append(out, namespace)
	}
	sort.Strings(out)
	return out
}

// listFailure records one failed list; Forbidden marks an RBAC denial. The
// detail names the limit or the status that stopped the list and never carries
// server content (audit F1, F4).
func listFailure(tier int, resource, namespace string, err error) ListFailure {
	failure := ListFailure{Tier: tier, Resource: resource, Namespace: namespace, Forbidden: apierrors.IsForbidden(err)}
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		failure.Deadline = true
	case errors.Is(err, errItemLimit):
		failure.Code = "DSD-SCN-005"
		failure.Detail = errItemLimit.Error()
	case errors.Is(err, errPageLimit):
		failure.Code = "DSD-SCN-005"
		failure.Detail = errPageLimit.Error()
	case errors.Is(err, errResponseTooLarge):
		failure.Detail = errResponseTooLarge.Error()
	default:
		var redirect *redirectError
		if errors.As(err, &redirect) {
			failure.Detail = redirect.Error()
		}
	}
	return failure
}

// newWorkload converts one pod-template-bearing object (spec v0.2 section 2).
func newWorkload(object metav1.Object, kind string, spec corev1.PodSpec, templateLabels map[string]string) Workload {
	return Workload{
		Namespace:  object.GetNamespace(),
		Kind:       kind,
		Name:       object.GetName(),
		Labels:     mergeLabels(templateLabels, object.GetLabels()),
		Containers: containerList(spec),
		Owners:     ownerList(object.GetOwnerReferences()),
	}
}

// newPod converts one Pod object (spec v0.2 section 2: only running container
// statuses feed the mirror attribute). owners resolves the controller owner
// chain that scopes the mirror attribute to the owning workload (review 03 m2).
func newPod(owners ownerIndex, pod *corev1.Pod) Pod {
	status := make([]ContainerStatus, 0, len(pod.Status.ContainerStatuses))
	for i := range pod.Status.ContainerStatuses {
		container := &pod.Status.ContainerStatuses[i]
		if container.State.Running == nil {
			continue
		}
		status = append(status, ContainerStatus{Name: container.Name, Image: container.Image, ImageID: container.ImageID})
	}
	return Pod{
		Namespace:  pod.Namespace,
		Name:       pod.Name,
		Labels:     pod.Labels,
		Containers: containerList(pod.Spec),
		Status:     status,
		Owned:      hasController(pod.OwnerReferences),
		OwnerChain: podOwnerChain(owners, pod),
	}
}

// ownerIndex records the ownerReferences of every object listed in one read.
// Pods are listed last, so a Pod's controller owner chain can be resolved to the
// workload that owns it without extra API calls (review 03 m2, spec v0.2
// section 3).
type ownerIndex map[string][]metav1.OwnerReference

// indexOwners records an object's ownerReferences in the read's owner index.
func indexOwners(index ownerIndex, namespace, kind, name string, references []metav1.OwnerReference) {
	if len(references) == 0 {
		return
	}
	index[namespace+"\x00"+kind+"\x00"+name] = references
}

// controllerOwner returns the controller ownerReference of an object, if any.
func controllerOwner(references []metav1.OwnerReference) (metav1.OwnerReference, bool) {
	for i := range references {
		if references[i].Controller != nil && *references[i].Controller {
			return references[i], true
		}
	}
	return metav1.OwnerReference{}, false
}

// podOwnerChain resolves a Pod's controller owner chain, outermost first, from
// the owner index of the same read (review 03 m2, spec v0.2 section 3). The
// depth is bounded so a hostile owner cycle cannot loop, and a standalone pod
// yields no chain.
func podOwnerChain(index ownerIndex, pod *corev1.Pod) []Owner {
	var chain []Owner
	references := pod.OwnerReferences
	for depth := 0; depth < 16; depth++ {
		owner, ok := controllerOwner(references)
		if !ok {
			break
		}
		chain = append(chain, Owner{Kind: owner.Kind, Name: owner.Name})
		references = index[pod.Namespace+"\x00"+owner.Kind+"\x00"+owner.Name]
		if len(references) == 0 {
			break
		}
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// containerList flattens containers, initContainers and ephemeralContainers in
// declaration order (spec v0.2 section 2, tier 1).
func containerList(spec corev1.PodSpec) []Container {
	out := make([]Container, 0, len(spec.Containers)+len(spec.InitContainers)+len(spec.EphemeralContainers))
	for i := range spec.Containers {
		out = append(out, Container{Name: spec.Containers[i].Name, Image: spec.Containers[i].Image})
	}
	for i := range spec.InitContainers {
		out = append(out, Container{Name: spec.InitContainers[i].Name, Image: spec.InitContainers[i].Image})
	}
	for i := range spec.EphemeralContainers {
		out = append(out, Container{Name: spec.EphemeralContainers[i].Name, Image: spec.EphemeralContainers[i].Image})
	}
	return out
}

// ownerList converts ownerReferences (spec v0.2 section 2, owner filtering).
func ownerList(references []metav1.OwnerReference) []Owner {
	if len(references) == 0 {
		return nil
	}
	out := make([]Owner, 0, len(references))
	for i := range references {
		owner := Owner{Kind: references[i].Kind, Name: references[i].Name}
		if references[i].Controller != nil {
			owner.Controller = *references[i].Controller
		}
		out = append(out, owner)
	}
	return out
}

// ownedBy reports whether any controller ownerReference names kind.
func ownedBy(references []metav1.OwnerReference, kind string) bool {
	for i := range references {
		if references[i].Kind == kind && references[i].Controller != nil && *references[i].Controller {
			return true
		}
	}
	return false
}

// hasController reports whether any ownerReference is the controller.
func hasController(references []metav1.OwnerReference) bool {
	for i := range references {
		if references[i].Controller != nil && *references[i].Controller {
			return true
		}
	}
	return false
}

// mergeLabels overlays object labels on template labels; neither map is mutated.
func mergeLabels(template, object map[string]string) map[string]string {
	out := make(map[string]string, len(template)+len(object))
	for key, value := range template {
		out[key] = value
	}
	for key, value := range object {
		out[key] = value
	}
	return out
}
