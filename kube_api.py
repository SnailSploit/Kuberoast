# kuberoast/kube_api.py

import os
from kubernetes import client, config

def get_kube_client():
    """
    Return (CoreV1Api, AppsV1Api, RbacAuthorizationV1Api) clients.
    Attempts in-cluster config first, then local kubeconfig.
    """
    try:
        config.load_incluster_config()
        print("[*] Loaded in-cluster configuration.")
    except:
        kube_config_path = os.getenv('KUBECONFIG', '~/.kube/config')
        kube_config_path = os.path.expanduser(kube_config_path)
        config.load_kube_config(config_file=kube_config_path)
        print(f"[*] Loaded local kubeconfig from {kube_config_path}.")

    core_v1 = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()
    rbac_v1 = client.RbacAuthorizationV1Api()
    return core_v1, apps_v1, rbac_v1
