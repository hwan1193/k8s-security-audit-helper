#!/usr/bin/env bash
#
# k8s_security_audit.sh
#
# Simple, read-only Kubernetes security audit helper.
# - Collects cluster info
# - Lists images and finds :latest / tagless images
# - Summarizes NetworkPolicies per namespace
# - Summarizes Pod Security Admission labels
# - (Optional) Runs Trivy image scans for a few images
#
# Author: Your Name (Do-yoon Park)
# License: MIT
#

set -euo pipefail

#######################################
# Config / Defaults
#######################################

NAMESPACE_FILTER=""
OUT_DIR=""
TRIVY_SCAN_LIMIT=0   # 0 = do not run Trivy
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
JQ_BIN="${JQ_BIN:-jq}"

#######################################
# Helper functions
#######################################

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -n, --namespace NS     Only inspect a specific namespace (default: all)
  -o, --out-dir DIR      Output directory (default: ./k8s_audit_YYYYMMDD_HHMMSS)
      --trivy-scan N     Run Trivy image scan for up to N unique images
  -h, --help             Show this help

Environment:
  KUBECTL_BIN            kubectl binary (default: "kubectl")
  JQ_BIN                 jq binary (default: "jq")

Examples:
  $0
  $0 -n default --out-dir ./reports
  $0 --trivy-scan 5
EOF
}

log() {
  # timestamped log
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2
}

abort() {
  echo "ERROR: $*" >&2
  exit 1
}

check_dep() {
  local bin="$1"
  command -v "$bin" >/dev/null 2>&1 || abort "Required binary not found in PATH: $bin"
}

safe_mkdir() {
  local dir="$1"
  mkdir -p "$dir"
}

sanitize_filename() {
  # Replace / and : and @ with _
  echo "$1" | sed -e 's/[\/:@]/_/g'
}

#######################################
# Parse arguments
#######################################

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace)
      [[ $# -lt 2 ]] && abort "Missing value for $1"
      NAMESPACE_FILTER="$2"
      shift 2
      ;;
    -o|--out-dir)
      [[ $# -lt 2 ]] && abort "Missing value for $1"
      OUT_DIR="$2"
      shift 2
      ;;
    --trivy-scan)
      [[ $# -lt 2 ]] && abort "Missing value for $1"
      TRIVY_SCAN_LIMIT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      abort "Unknown option: $1"
      ;;
  esac
done

#######################################
# Init
#######################################

check_dep "$KUBECTL_BIN"
check_dep "$JQ_BIN"

if [[ -z "${OUT_DIR}" ]]; then
  OUT_DIR="./k8s_audit_$(date +%Y%m%d_%H%M%S)"
fi

safe_mkdir "$OUT_DIR"
SUMMARY_MD="${OUT_DIR}/SUMMARY.md"

log "Output directory: $OUT_DIR"

# kubectl namespace args
if [[ -n "$NAMESPACE_FILTER" ]]; then
  K_NS_ARGS=( -n "$NAMESPACE_FILTER" )
  log "Namespace filter: $NAMESPACE_FILTER"
else
  K_NS_ARGS=( -A )
  log "Namespace filter: ALL"
fi

#######################################
# 1. Cluster info
#######################################

collect_cluster_info() {
  log "Collecting cluster info..."
  {
    echo "# Cluster Info"
    echo
    echo "## kubectl version --short"
    "$KUBECTL_BIN" version --short || echo "kubectl version failed"
    echo
    echo "## Current context"
    "$KUBECTL_BIN" config current-context || echo "current-context unknown"
    echo
    echo "## Nodes"
    "$KUBECTL_BIN" get nodes -o wide || echo "kubectl get nodes failed"
  } > "${OUT_DIR}/cluster_info.txt"
}

#######################################
# 2. Image list & latest/tagless detection
#######################################

collect_images() {
  log "Collecting images from pods..."
  local out_csv="${OUT_DIR}/images.csv"
  local latest_csv="${OUT_DIR}/images_latest_or_tagless.csv"

  # CSV header
  echo "namespace,pod,container,image,image_tag,is_latest_or_tagless" > "$out_csv"
  echo "namespace,pod,container,image,image_tag,reason" > "$latest_csv"

  # Get pods JSON
  local tmp_json
  tmp_json="$(mktemp)"
  if ! "$KUBECTL_BIN" get pods "${K_NS_ARGS[@]}" -o json > "$tmp_json" 2>/dev/null; then
    log "No pods found or kubectl get pods failed (continuing)."
    rm -f "$tmp_json"
    return 0
  fi

  # Extract info using jq
  "$JQ_BIN" -r '
    .items[]? as $pod |
    ($pod.metadata.namespace // "default") as $ns |
    ($pod.metadata.name // "") as $podname |
    ($pod.spec.containers // [])[]? as $c |
    ($c.name // "") as $cname |
    ($c.image // "") as $image |
    # split image into name:tag
    (if ($image | contains(":")) then
       ($image | split(":") | .[1])
     else
       ""
     end) as $tag |
    [
      $ns,
      $podname,
      $cname,
      $image,
      ($tag | if . == "" then "<none>" else . end)
    ] | @csv
  ' "$tmp_json" >> "$out_csv"

  # Detect latest / tagless
  tail -n +2 "$out_csv" | while IFS=, read -r ns pod ctn image tag; do
    # remove quotes
    ns=${ns//\"/}
    pod=${pod//\"/}
    ctn=${ctn//\"/}
    image=${image//\"/}
    tag=${tag//\"/}

    # Determine reason
    reason=""
    if [[ "$image" != "" && "$image" != *":"* ]]; then
      reason="tagless_image"
    elif [[ "$tag" == "latest" ]]; then
      reason="latest_tag"
    fi

    if [[ -n "$reason" ]]; then
      echo "${ns},${pod},${ctn},${image},${tag},${reason}" >> "$latest_csv"
    fi
  done

  rm -f "$tmp_json"
}

#######################################
# 3. NetworkPolicy summary
#######################################

collect_networkpolicies() {
  log "Collecting NetworkPolicy summary..."
  local out_csv="${OUT_DIR}/networkpolicies_summary.csv"

  echo "namespace,total_policies" > "$out_csv"

  local tmp_json
  tmp_json="$(mktemp)"
  if ! "$KUBECTL_BIN" get networkpolicy -A -o json > "$tmp_json" 2>/dev/null; then
    log "No NetworkPolicy resources found (continuing)."
    rm -f "$tmp_json"
    return 0
  fi

  "$JQ_BIN" -r '
    .items[]? |
    (.metadata.namespace // "default") as $ns |
    {namespace: $ns} |
    group_by(.namespace) |
    map({namespace: .[0].namespace, count: length})[] |
    "\(.namespace),\(.count)"
  ' "$tmp_json" >> "$out_csv" || {
    # Fallback: simple per-item loop if jq group_by fails
    log "jq group_by failed, using simple fallback for NetworkPolicy summary."
    rm -f "$out_csv"
    echo "namespace,total_policies" > "$out_csv"
    "$JQ_BIN" -r '.items[]?.metadata.namespace // "default"' "$tmp_json" \
      | sort | uniq -c \
      | awk '{print $2","$1}' >> "$out_csv"
  }

  rm -f "$tmp_json"
}

#######################################
# 4. Pod Security Admission labels
#######################################

collect_psa_labels() {
  log "Collecting Pod Security Admission labels..."
  local out_csv="${OUT_DIR}/psa_namespace_labels.csv"

  echo "namespace,enforce,warn,audit" > "$out_csv"

  local tmp_json
  tmp_json="$(mktemp)"
  if ! "$KUBECTL_BIN" get ns -o json > "$tmp_json" 2>/dev/null; then
    log "kubectl get ns failed (continuing)."
    rm -f "$tmp_json"
    return 0
  fi

  "$JQ_BIN" -r '
    .items[]? as $ns |
    ($ns.metadata.name // "") as $name |
    ($ns.metadata.labels["pod-security.kubernetes.io/enforce"] // "") as $enforce |
    ($ns.metadata.labels["pod-security.kubernetes.io/warn"] // "") as $warn |
    ($ns.metadata.labels["pod-security.kubernetes.io/audit"] // "") as $audit |
    [$name,$enforce,$warn,$audit] | @csv
  ' "$tmp_json" >> "$out_csv"

  rm -f "$tmp_json"
}

#######################################
# 5. Optional: Trivy image scan
#######################################

run_trivy_scans() {
  if [[ "$TRIVY_SCAN_LIMIT" -le 0 ]]; then
    log "Trivy scan not requested (skip)."
    return 0
  fi

  if ! command -v trivy >/dev/null 2>&1; then
    log "Trivy not found in PATH; skipping image vulnerability scans."
    return 0
  fi

  log "Running Trivy scans for up to ${TRIVY_SCAN_LIMIT} images..."

  local images_file="${OUT_DIR}/images.csv"
  if [[ ! -f "$images_file" ]]; then
    log "images.csv not found; skipping Trivy scans."
    return 0
  fi

  # Extract unique image names (skip header)
  mapfile -t images < <(tail -n +2 "$images_file" | cut -d',' -f4 | tr -d '"' | sort -u)

  local count=0
  for img in "${images[@]}"; do
    if [[ -z "$img" ]]; then
      continue
    fi
    (( count++ ))
    if [[ "$count" -gt "$TRIVY_SCAN_LIMIT" ]]; then
      break
    fi

    local san
    san="$(sanitize_filename "$img")"
    local out_report="${OUT_DIR}/trivy_${count}_${san}.txt"

    log "  [${count}/${TRIVY_SCAN_LIMIT}] trivy image scan: ${img}"
    # Simple text output; user can parse further if needed
    trivy image --severity CRITICAL,HIGH --ignore-unfixed --no-progress "$img" > "$out_report" 2>&1 || {
      log "  Trivy scan failed for ${img} (see ${out_report})"
    }
  done
}

#######################################
# 6. Summary markdown
#######################################

write_summary() {
  log "Writing summary markdown..."

  {
    echo "# Kubernetes Security Audit Summary"
    echo
    echo "- Generated at: $(date +'%Y-%m-%d %H:%M:%S')"
    echo "- Namespace filter: ${NAMESPACE_FILTER:-ALL}"
    echo
    echo "## Files"
    echo
    for f in cluster_info.txt images.csv images_latest_or_tagless.csv \
             networkpolicies_summary.csv psa_namespace_labels.csv; do
      if [[ -f "${OUT_DIR}/${f}" ]]; then
        echo "- \`${f}\`"
      fi
    done

    if ls "${OUT_DIR}"/trivy_*.txt >/dev/null 2>&1; then
      echo
      echo "## Trivy Reports"
      for f in "${OUT_DIR}"/trivy_*.txt; do
        base="$(basename "$f")"
        echo "- \`${base}\`"
      done
    fi

    echo
    echo "## Notes"
    echo
    echo "- This script is read-only: it does not modify any Kubernetes resources."
    echo "- All checks are best-effort and may not cover every security requirement."
    echo "- You can extend this script with more checks (RBAC review, Ingress/Service exposure, etc.)."
  } > "$SUMMARY_MD"
}

#######################################
# Main
#######################################

collect_cluster_info
collect_images
collect_networkpolicies
collect_psa_labels
run_trivy_scans
write_summary

log "Done. See ${OUT_DIR} for results."