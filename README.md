Kuberoast
---
Kuberoast is a lightweight, 
pentester-oriented tool for Kubernetes & container misconfiguration scanning.
It enumerates pods, deployments, RBAC settings, secrets, and nodes to highlight common risks like:
---
- Privileged containers  
- Containers allowed to run as root  
- Host network/IPC usage  
- Insecure or missing security contexts (read-only root FS, dropped capabilities, etc.)  
- Overly broad RBAC bindings (e.g., cluster-admin for wildcard subjects)  
- Base64-decoded secrets possibly containing passwords or tokens  
- Kubelet insecure ports or anonymous API server access  
- _(Optional)_ **Privilege escalation** attempts by checking if a privileged pod can access the host filesystem  
---
## Features
- **Lightweight & Focused**: Ideal for quick checks or red-team engagements.  
- **Pentest-Centric**: Emphasizes misconfigurations that enable lateral movement or cluster takeovers.  
- **Extensible**: Written in Python; easy to add custom checks.  
---
## Installation

1. Clone this repo:

   ```bash
   git clone https://github.com/snailsploit/Kuberoast.git
   cd Kuberoast
   ```
#This installs the kubernetes and requests libraries required by Kuberoast.

##Usage
```bash
python main.py [OPTIONS]
```

##Common Options
```bash
--report-format <json|text>
```
#Output results in JSON (default) or a simplified text format.

```bash
--skip-secrets
```
3Skip listing and decoding Secrets. Useful if your RBAC does not allow it or if you want to avoid sensitive data.

```bash
--skip-nodes
```
3Skip enumerating Nodes and checking for insecure Kubelet ports.

```bash
--exploit-namespace <namespace>
```
#Specify a namespace for the privilege escalation check.

```bash
--exploit-pod <pod>
```
#Specify a pod name for the privilege escalation check. If both this and --exploit-namespace are provided, Kuberoast attempts to see if the container can access /host/root.

##Example Commands
#Basic All-in-One Scan (no exploitation attempt):

```bash
python main.py
```

Text-Based Output:

```bash
python main.py --report-format text
```
Skip Secrets & Node Checks (limited RBAC):

```bash
python main.py --skip-secrets --skip-nodes
```
Privilege Escalation Attempt:

```bash

python main.py \
    --exploit-namespace default \
    --exploit-pod my-privileged-pod
```
If /host/root is mounted inside my-privileged-pod, Kuberoast will detect potential host-level file access.

##Sample JSON Output
```json
{
  "privileged_containers": [
    {
      "namespace": "default",
      "pod": "test-pod",
      "container": "app",
      "issue": "Privileged container"
    }
  ],
  "kubelet_insecure": [
    {
      "node": "node1",
      "ip": "10.0.0.1",
      "port": 10255,
      "issue": "Kubelet read-only/insecure port is open"
    }
  ]
}
```


##How It Works
#Enumeration:
- Kuberoast lists Pods, Deployments, DaemonSets, RBAC objects (Roles, ClusterRoles, Bindings), and (optionally) Secrets and Nodes.
---
##Checks:
- Pod Security: Identifies privileged containers, root containers, host networking, missing read-only FS, etc.
- RBAC: Looks for cluster-admin privileges assigned to wildcard groups/users.
- Secrets: Decodes base64 data and flags suspicious keywords.
- Kubelet Ports: Probes node IPs for insecure read-only ports (default 10255).
- Privilege Escalation (optional): Executes a simple command to see if the pod can list /host/root.
- Reporting: Generates a JSON or text-based report summarizing findings.
---
##Disclaimers
- Authorization: Use Kuberoast only on clusters you have explicit permission to test.
- BAC: Some checks (e.g., enumerating Secrets) require cluster-wide permissions. If you lack them, certain checks will fail gracefully.
- privilege Escalation: Attempting to list /host/root can reveal real host files if the pod is truly privileged with a host mount. Use responsibly and with consent.
- contributing
- Fork this repository.
- Create a feature branch (git checkout -b new-feature).
- Commit your changes (git commit -m "Add some feature").
- Push to your branch (git push origin new-feature).
- Create a Pull Request against the main repo.
#We welcome bug reports, feature requests, and pull requests.
---
##License
#Kuberoast is released under the MIT License. Feel free to modify and distribute under the same license terms.

#Happy Pentesting!


---



