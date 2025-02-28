import base64
import socket
import subprocess

#######################
# Pod/Container Checks
#######################

def check_privileged_containers(pods):
    findings = []
    for pod in pods:
        for container in pod.spec.containers:
            sec_ctx = container.security_context
            if sec_ctx and getattr(sec_ctx, 'privileged', False):
                findings.append({
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "Privileged container"
                })
    return findings

def check_run_as_root(pods):
    findings = []
    for pod in pods:
        for container in pod.spec.containers:
            sec_ctx = container.security_context
            # runAsNonRoot is recommended
            if not sec_ctx or sec_ctx.run_as_non_root is not True:
                findings.append({
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "Container may run as root (runAsNonRoot not enforced)"
                })
    return findings

def check_env_secrets(pods):
    suspicious_keywords = ["pass", "key", "secret", "token"]
    findings = []
    for pod in pods:
        for container in pod.spec.containers:
            if container.env:
                for env in container.env:
                    if env.value and any(kw in env.value.lower() for kw in suspicious_keywords):
                        findings.append({
                            "namespace": pod.metadata.namespace,
                            "pod": pod.metadata.name,
                            "container": container.name,
                            "variable": env.name,
                            "value": env.value,
                            "issue": "Potential secret in environment variable"
                        })
    return findings

def check_host_network_ipc(pods):
    findings = []
    for pod in pods:
        if pod.spec.host_network:
            findings.append({
                "namespace": pod.metadata.namespace,
                "pod": pod.metadata.name,
                "issue": "Pod using hostNetwork=True"
            })
        if pod.spec.host_ipc:
            findings.append({
                "namespace": pod.metadata.namespace,
                "pod": pod.metadata.name,
                "issue": "Pod using hostIPC=True"
            })
    return findings

#############################
# CIS Benchmark-like Checks
#############################

def check_read_only_root_fs(pods):
    findings = []
    for pod in pods:
        for container in pod.spec.containers:
            sec_ctx = container.security_context
            if not sec_ctx or not getattr(sec_ctx, 'read_only_root_filesystem', False):
                findings.append({
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "Root filesystem is not read-only"
                })
    return findings

def check_capabilities(pods):
    dangerous_caps = {"NET_RAW", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE"}
    findings = []
    for pod in pods:
        for container in pod.spec.containers:
            sec_ctx = container.security_context
            if sec_ctx and sec_ctx.capabilities:
                drop_caps = sec_ctx.capabilities.drop or []
                drop_caps_set = set(drop_caps)
                if not drop_caps_set.intersection(dangerous_caps):
                    findings.append({
                        "namespace": pod.metadata.namespace,
                        "pod": pod.metadata.name,
                        "container": container.name,
                        "issue": "Container not dropping dangerous capabilities"
                    })
    return findings

def check_ephemeral_storage(pods):
    findings = []
    for pod in pods:
        for container in pod.spec.containers:
            resources = container.resources
            ephemeral_req = None
            if resources and resources.requests:
                ephemeral_req = resources.requests.get("ephemeral-storage", None)
            if not ephemeral_req:
                findings.append({
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "container": container.name,
                    "issue": "No ephemeral-storage request set"
                })
    return findings

####################
# RBAC Misconfigs
####################

def check_rbac(cluster_role_bindings, roles, role_bindings):
    findings = []
    for crb in cluster_role_bindings:
        if crb.role_ref.kind == "ClusterRole" and crb.role_ref.name == "cluster-admin":
            subjects = crb.subjects or []
            for sub in subjects:
                # If sub.name == "*" or a broad group (e.g. "system:authenticated"), that's risky
                if sub.name == "*" or (sub.kind == "Group" and sub.name == "system:authenticated"):
                    findings.append({
                        "binding": crb.metadata.name,
                        "issue": "ClusterRoleBinding grants cluster-admin to wildcard or broad group"
                    })
    return findings

###################
# Secret Analysis
###################

def check_secret_data(secrets_list):
    suspicious_keywords = ["pass", "key", "secret", "token", "private"]
    findings = []
    for secret in secrets_list:
        data_map = secret.data or {}
        for key, val in data_map.items():
            try:
                decoded = base64.b64decode(val).decode('utf-8', errors='ignore')
                if any(kw in decoded.lower() for kw in suspicious_keywords):
                    findings.append({
                        "namespace": secret.metadata.namespace,
                        "secret": secret.metadata.name,
                        "key": key,
                        "issue": "Potential credential found in secret",
                        "snippet": decoded[:50]  # partial snippet
                    })
            except Exception:
                pass
    return findings

########################################
# Kubelet / API Server Insecure Checks
########################################

def check_kubelet_insecure_port(nodes, port=10255):
    findings = []
    for node in nodes:
        addresses = node.status.addresses or []
        for addr in addresses:
            if addr.type in ["InternalIP", "ExternalIP"]:
                ip = addr.address
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        findings.append({
                            "node": node.metadata.name,
                            "ip": ip,
                            "port": port,
                            "issue": "Kubelet read-only/insecure port is open"
                        })
                except Exception:
                    pass
    return findings

def check_apiserver_anonymous():
    import requests
    findings = []
    url = "https://127.0.0.1:6443/api"
    try:
        resp = requests.get(url, verify=False, timeout=2)
        if resp.status_code == 200:
            findings.append({"issue": "API server allows anonymous access"})
    except:
        pass
    return findings

####################################
# Safe Exploitation / Escalation
####################################

def attempt_privilege_escalation(pod_name, namespace):
    """
    Attempt a naive host filesystem check by running:
      kubectl exec -n <namespace> <pod_name> -- ls /host/root
    If the container is privileged and has a /host/root mount,
    we might see the host's filesystem.
    """
    findings = []
    cmd = ["kubectl", "exec", "-n", namespace, pod_name, "--", "ls", "/host/root"]
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        # If we succeed, we have potential host-level access
        output_snippet = result.decode("utf-8", errors="ignore")[:100]
        findings.append({
            "namespace": namespace,
            "pod": pod_name,
            "issue": "Host file system is accessible (privilege escalation possible)",
            "command_run": " ".join(cmd),
            "snippet_of_output": output_snippet
        })
    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:
        pass

    return findings
