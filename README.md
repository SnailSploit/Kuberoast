# Kuberoast

**Kuberoast** is a lightweight, pentester-oriented tool for **Kubernetes & container misconfiguration scanning**. It enumerates pods, deployments, RBAC settings, secrets, and nodes to highlight common risks like:

- Privileged containers  
- Containers allowed to run as root  
- Host network/IPC usage  
- Insecure or missing security contexts (read-only root FS, dropped capabilities, etc.)  
- Overly broad RBAC bindings (e.g., cluster-admin for wildcard subjects)  
- Base64-decoded secrets possibly containing passwords or tokens  
- Kubelet insecure ports or anonymous API server access  
- _(Optional)_ **Privilege escalation** attempts by checking if a privileged pod can access the host filesystem  

## Features
- **Lightweight & Focused**: Ideal for quick checks or red-team engagements.  
- **Pentest-Centric**: Emphasizes misconfigurations that enable lateral movement or cluster takeovers.  
- **Extensible**: Written in Python; easy to add custom checks.  

## Installation

1. Clone this repo:

   ```bash
   git clone https://github.com/snailsploit/Kuberoast.git
   cd Kuberoast
