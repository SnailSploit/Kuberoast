import argparse
import sys

from kuberoast.enumerator import (
    enumerate_cluster,
    get_kube_client,
    enumerate_nodes,
    enumerate_secrets
)
from kuberoast import checks
from kuberoast.report import generate_report

def main():
    parser = argparse.ArgumentParser(description="Kuberoast: Kubernetes & Container Misconfiguration Scanner")
    parser.add_argument("--report-format", default="json", help="Output format (json or text)")
    parser.add_argument("--skip-secrets", action="store_true", help="Skip checking secrets (if not permitted)")
    parser.add_argument("--skip-nodes", action="store_true", help="Skip node-level checks (Kubelet, etc.)")
    parser.add_argument("--exploit-namespace", default=None, help="Namespace of the pod to attempt privilege escalation")
    parser.add_argument("--exploit-pod", default=None, help="Name of the pod to attempt privilege escalation")
    args = parser.parse_args()

    print("[*] Enumerating cluster objects...")
    cluster_data = enumerate_cluster()
    pods = cluster_data["pods"]
    deployments = cluster_data["deployments"]
    daemonsets = cluster_data["daemonsets"]
    cluster_role_bindings = cluster_data["cluster_role_bindings"]
    roles = cluster_data["roles"]
    role_bindings = cluster_data["role_bindings"]

    # Initialize API clients
    core_v1, apps_v1, rbac_v1 = get_kube_client()

    # Secrets enumeration
    secrets_list = []
    if not args.skip_secrets:
        print("[*] Enumerating secrets (if RBAC allows)...")
        secrets_list = enumerate_secrets(core_v1)

    # Node enumeration
    nodes_list = []
    if not args.skip_nodes:
        print("[*] Enumerating nodes for Kubelet checks...")
        nodes_list = enumerate_nodes(core_v1)

    # Run checks
    all_findings = {}

    print("[*] Running container/pod-level checks...")
    all_findings["privileged_containers"] = checks.check_privileged_containers(pods)
    all_findings["root_containers"] = checks.check_run_as_root(pods)
    all_findings["env_secrets"] = checks.check_env_secrets(pods)
    all_findings["host_network_ipc"] = checks.check_host_network_ipc(pods)
    all_findings["read_only_root_fs"] = checks.check_read_only_root_fs(pods)
    all_findings["capabilities"] = checks.check_capabilities(pods)
    all_findings["ephemeral_storage"] = checks.check_ephemeral_storage(pods)

    print("[*] Running RBAC checks...")
    all_findings["rbac_issues"] = checks.check_rbac(cluster_role_bindings, roles, role_bindings)

    if secrets_list:
        print("[*] Checking secrets for suspicious data...")
        all_findings["secret_data"] = checks.check_secret_data(secrets_list)

    if nodes_list:
        print("[*] Checking for Kubelet insecure ports...")
        all_findings["kubelet_insecure"] = checks.check_kubelet_insecure_port(nodes_list, port=10255)
        # Additional check (commented out by default):
        # all_findings["apiserver_anonymous"] = checks.check_apiserver_anonymous()

    # Attempt privilege escalation if specified
    if args.exploit_namespace and args.exploit_pod:
        print(f"[*] Attempting privilege escalation on pod: {args.exploit_pod} (namespace: {args.exploit_namespace})")
        esc_findings = checks.attempt_privilege_escalation(args.exploit_pod, args.exploit_namespace)
        if esc_findings:
            all_findings["priv_esc"] = esc_findings
        else:
            print("[*] No successful privilege escalation or attempt failed.")

    # Filter out empty categories
    final_report = {k: v for k, v in all_findings.items() if v}

    # Output results
    output = generate_report(final_report, output_format=args.report_format)
    print(output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Interrupted by user.")
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
