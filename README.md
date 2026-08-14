# SOC Analyst Home Lab

Home lab de cibersegurança focado em simulação de ataques reais,
detecção de ameaças e resposta a incidentes com Wazuh SIEM,
seguindo o framework NIST SP 800-61.

## Arquitetura do Ambiente

| Host | Sistema | IP | Função |
|------|---------|-----|--------|
| Proxmox-server | Debian | 192.168.100.200 | Hypervisor Server |
| wazuh-server | Ubuntu | 192.168.100.201 | Wazuh SIEM Server |
| vm-lab-win | Windows 10 Pro | 192.168.100.202 | Agente Windows |
| vm-kali-lab | Kali Linux | 192.168.100.203 | Agente Linux |
| vm-debian-lab | Debian 13 | 192.168.100.204 | Agente Linux |

## Casos Investigados

| ID | Título | Técnica MITRE | Link |
|----|--------|---------------|------|
| INC-001 | Força Bruta SSH | T1110.001 | [Ver relatório](alert-investigation/INC-001-forca-bruta-ssh.md) |
| INC-002 | Persistência via Usuário Backdoor | T1136.001 | [Ver relatório](alert-investigation/INC-002-file-integrity-monitoring.md) |
| INC-003 | Escalação de Privilégio via Sudo Misconfiguration | T1548.003 | [Ver relatório](alert-investigation/INC-003%20–%20escalação-de-privilégio.md) |
| INC-004 | Avaliação de Vulnerabilidades Via OpenVAS/GVM | CIS Benchmark | [Ver relatório](alert-investigation/INC-004-vulnerability-scan.md) |


## Ferramentas Utilizadas

- Wazuh 4.14.5 (SIEM/XDR)
- Debian 13 e Windows 10 Pro (agentes monitorados)
- journalctl, auth.log, GTFOBins
- MITRE ATT&CK Framework
- NIST SP 800-61 (resposta a incidentes)
- OpenVAS/GVM (scanner de falhas de segurança)


