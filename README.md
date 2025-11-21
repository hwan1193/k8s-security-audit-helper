# k8s-security-audit-helper

# k8s-security-audit.sh

Simple, read-only Kubernetes security audit helper script.

## Features

- Collects cluster info (`cluster_info.txt`)
- Lists all images from Pods (`images.csv`)
- Detects `:latest` or tagless images (`images_latest_or_tagless.csv`)
- Summarizes NetworkPolicies per namespace (`networkpolicies_summary.csv`)
- Summarizes Pod Security Admission labels (`psa_namespace_labels.csv`)
- (Optional) Runs [Trivy](https://github.com/aquasecurity/trivy) image scans for a few images

## Usage

```bash
bash k8s_security_audit.sh
bash k8s_security_audit.sh -n default --out-dir ./reports
bash k8s_security_audit.sh --trivy-scan 5

---

## Prerequisites

- kubectl (configured to access the target cluster)
- jq
- (Optional) Trivy – for `--trivy-scan` option
- Read-only access is recommended, but cluster-wide list permissions are required:
  - pods
  - namespaces
  - networkpolicies
