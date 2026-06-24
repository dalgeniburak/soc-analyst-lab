# SOC Analyst Home Lab

Home lab de cibersegurança focado em simulação de ataques reais,
detecção de ameaças e resposta a incidentes com Wazuh SIEM,
seguindo o framework NIST SP 800-61.

## Arquitetura do Ambiente

| Host | Sistema | IP | Função |
|------|---------|-----|--------|
| wazuh-server | Ubuntu | 192.168.100.111 | Wazuh SIEM Server |
| vm-debian-lab | Debian 13 | 192.168.100.114 | Agente Linux |
| vm-lab-win | Windows 10 Pro | 192.168.100.113 | Agente Windows |

## Casos Investigados

| ID | Título | Técnica MITRE | Link |
|----|--------|---------------|------|
| INC-001 | Força Bruta SSH | T1110.001 | [Ver relatório](alert-investigation/INC-001-forca-bruta-ssh.md) |
| INC-002 | Persistência via Usuário Backdoor | T1136.001 | [Ver relatório](alert-investigation/INC-002-file-integrity-monitoring.md) |
| INC-003 | Escalação de Privilégio via Sudo Misconfiguration | T1548.003 | [Ver relatório](alert-investigation/INC-003%20–%20escalação-de-privilégio.md) |

## Ferramentas Utilizadas

- Wazuh 4.14.5 (SIEM/XDR)
- Debian 13 e Windows 10 Pro (agentes monitorados)
- journalctl, auth.log, GTFOBins
- MITRE ATT&CK Framework
- NIST SP 800-61 (resposta a incidentes)

## Sobre a Analista

Dalgeni Burak — Assistente de TI em transição para cibersegurança,
com foco em SOC Analyst e futuramente perícia digital forense.
Certificações: IBSEC SOC Analyst (IC-SOC-383), IBSEC Linux Security
(IC-LNX-1183), Linux Foundation Cybersecurity Essentials (LFC108),
Google Cybersecurity Certificate (em andamento).
