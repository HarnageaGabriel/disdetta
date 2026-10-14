// Package cluster scans a Kubernetes cluster for Bitnami dependencies (spec v0.2).
package cluster

import (
	_ "k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/kubernetes/fake"
	_ "k8s.io/client-go/tools/clientcmd"
)
