# k8s-security-audit-helper

Read-only Kubernetes security audit helper that exports **evidence-ready reports** (CSV/TXT/MD).  
쿠버네티스 클러스터를 **읽기 전용(read-only)**으로 점검하고 **증적용 리포트(CSV/TXT/MD)**를 자동 생성하는 스크립트입니다.

✅ Supports both:
- `k8s_security_audit.sh` (Linux / macOS / WSL)
- `k8s_security_audit.ps1` (Windows PowerShell)

> ⚠️ This tool is read-only: it does not modify Kubernetes resources.  
> ⚠️ 조회만 수행하며 쿠버네티스 리소스를 변경하지 않습니다.

---

## Features / 주요 기능
- Cluster info 수집 (context / nodes) → `cluster_info.txt`
- Pod 이미지 인벤토리 추출 → `images.csv`
- `:latest` / tag 없는 이미지 탐지 → `images_latest_or_tagless.csv`
- Namespace별 NetworkPolicy 개수 요약 → `networkpolicies_summary.csv`
- Pod Security Admission(PSA) 라벨 요약 → `psa_namespace_labels.csv`
- RBAC 바인딩 추출(ClusterRoleBinding / RoleBinding) → `rbac_*.csv`
- Service / Ingress 외부 노출 요약(LB/hosts/TLS) → `services_exposure.csv`, `ingress_exposure.csv`
- (옵션) Trivy 이미지 취약점 스캔(N개 제한) → `trivy_*.txt`
- 결과 파일 목록 자동 정리 → `SUMMARY.md`

---

## Prerequisites / 사전 준비
공통:
- `kubectl` (target cluster 접근 설정 완료)
- Kubernetes API 조회 권한(Read 권한)

Bash(.sh) 추가:
- `jq`
- (선택) `trivy` (`--trivy-scan` 사용할 때)

PowerShell(.ps1) 추가:
- 별도 `jq` 필요 없음
- (선택) `trivy` (`-TrivyScanLimit` 사용할 때)

---

## Installation / 설치
```bash
git clone https://github.com/hwan1193/k8s-security-audit-helper.git

cd k8s-security-audit-helper

## 1) Bash (Linux/macOS/WSL) → k8s_security_audit.sh

# 권한부여 :

chmod +x k8s_security_audit.sh

# 전체 네임스페이스 점검 (기본값)

./k8s_security_audit.sh

# 특정 네임스페이스만 점검 :

./k8s_security_audit.sh -n default

## 또는

./k8s_security_audit.sh --out-dir ./reports

# 결과 저장 폴더 지정 :

./k8s_security_audit.sh -o ./reports

## 또는

./k8s_security_audit.sh --out-dir ./reports

# (옵션) Trivy 스캔 (최대 N개 이미지) :

./k8s_security_audit.sh --trivy-scan 3

# 2) PowerShell (Windows) → k8s_security_audit.ps1

# 기본 실행 (전체 네임스페이스) :

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\k8s_security_audit.ps1

# 특정 네임스페이스 점검 :

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\k8s_security_audit.ps1 -Namespace default

# 결과 저장 폴더 지정 :

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\k8s_security_audit.ps1 -OutDir .\reports

# (옵션) Trivy 스캔 (최대 N개 이미지)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\k8s_security_audit.ps1 -TrivyScanLimit 3

# kubectl 경로 지정(환경에 따라)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\k8s_security_audit.ps1 -KubectlPath "C:\path\to\kubectl.exe"

### 참고: PowerShell 버전은 jq 없이 ConvertFrom-Json으로 파싱합니다.



```text (기본 출력 폴더)
Bash: ./k8s_audit_YYYYMMDD_HHMMSS/

PowerShell: .\k8s_audit_YYYYMMDD_HHMMSS\

k8s_audit_YYYYMMDD_HHMMSS/
├─ cluster_info.txt
├─ images.csv
├─ images_latest_or_tagless.csv
├─ networkpolicies_summary.csv
├─ psa_namespace_labels.csv
├─ rbac_clusterrolebindings.csv
├─ rbac_rolebindings.csv
├─ services_exposure.csv
├─ ingress_exposure.csv
├─ trivy_1_<image>.txt
└─ SUMMARY.md

Minimum RBAC / 최소 권한(권장)

Read-only 권한만 있으면 됩니다. 보통 필요한 리소스:

- pods
- namespaces
- networkpolicies
- services
- ingresses
- rolebindings
- clusterrolebindings

Notes / 참고 (운영 팁)
- --trivy-scan / -TrivyScanLimit 옵션은 레지스트리 접근/트래픽/시간 영향이 있을 수 있습니다.
- 결과물에 내부 이미지명/호스트/도메인 등이 포함될 수 있으니 공유 전 마스킹하세요.

