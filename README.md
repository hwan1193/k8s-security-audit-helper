# k8s-security-audit-helper

./k8s_security_audit.sh --trivy-scan 3 <-- 실행명령어

# k8s-security-audit.sh

Simple, read-only Kubernetes security audit helper script.

## Features

- Collects cluster info (`cluster_info.txt`)
- Lists all images from Pods (`images.csv`)
- Detects `:latest` or tagless images (`images_latest_or_tagless.csv`)
- Summarizes NetworkPolicies per namespace (`networkpolicies_summary.csv`)
- Summarizes Pod Security Admission labels (`psa_namespace_labels.csv`)
- Summarizes RBAC bindings (ClusterRoleBinding / RoleBinding) into CSV
- Summarizes external exposure of Services and Ingresses
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

## Quickstart

```bash
git clone https://github.com/…/k8s-security-audit-helper.git
cd k8s-security-audit-helper

chmod +x k8s_security_audit.sh

# All namespaces
./k8s_security_audit.sh

# Specific namespace + Trivy for 3 images
./k8s_security_audit.sh -n default --trivy-scan 3

### (3) Example output 구조 한 번 보여주기

```markdown
## Example output

```text
k8s_audit_20250719_120000/
  ├─ cluster_info.txt
  ├─ images.csv
  ├─ images_latest_or_tagless.csv
  ├─ networkpolicies_summary.csv
  ├─ psa_namespace_labels.csv
  ├─ rbac_clusterrolebindings.csv
  ├─ rbac_rolebindings.csv
  ├─ services_exposure.csv
  ├─ ingress_exposure.csv
  ├─ trivy_1_nginx_1.25.txt
  └─ SUMMARY.md

