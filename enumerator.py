from .kube_api import get_kube_client

def enumerate_cluster():
    """
    Fetch cluster-wide Pods, Deployments, DaemonSets, RBAC objects.
    Return them in a dict.
    """
    core_v1, apps_v1, rbac_v1 = get_kube_client()

    pods = core_v1.list_pod_for_all_namespaces().items
    deployments = apps_v1.list_deployment_for_all_namespaces().items
    daemonsets = apps_v1.list_daemon_set_for_all_namespaces().items

    cluster_roles = rbac_v1.list_cluster_role().items
    cluster_role_bindings = rbac_v1.list_cluster_role_binding().items
    roles = rbac_v1.list_role_for_all_namespaces().items
    role_bindings = rbac_v1.list_role_binding_for_all_namespaces().items

    return {
        "pods": pods,
        "deployments": deployments,
        "daemonsets": daemonsets,
        "cluster_roles": cluster_roles,
        "cluster_role_bindings": cluster_role_bindings,
        "roles": roles,
        "role_bindings": role_bindings
    }

def enumerate_secrets(core_v1_api):
    """
    Attempt to list secrets in all namespaces. Requires RBAC permissions.
    """
    try:
        return core_v1_api.list_secret_for_all_namespaces().items
    except Exception as e:
        print(f"[!] Unable to list secrets: {e}")
        return []

def enumerate_nodes(core_v1_api):
    """
    List nodes for checking Kubelet config, insecure ports, etc.
    """
    try:
        return core_v1_api.list_node().items
    except Exception as e:
        print(f"[!] Unable to list nodes: {e}")
        return []
