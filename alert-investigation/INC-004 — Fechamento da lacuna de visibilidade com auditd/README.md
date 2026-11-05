# INC-004 — Fechamento da lacuna de visibilidade com `auditd`

| Campo | Valor |
|---|---|
| **ID** | INC-004 |
| **Analista** | Dalgeni |
| **Data da simulação** | 05/11/2026 (madrugada) |
| **Fuso dos horários** | Brasília (UTC-3), salvo indicação |
| **Severidade do cenário** | Informativo / melhoria de visibilidade (não é uma exploração nova) |
| **Status** | Encerrado: visibilidade comprovada; regra ainda não persistida (ver Recomendações) |

## 1. Resumo executivo

Este incidente não simula um ataque novo — ele **fecha a lacuna estrutural identificada no INC-003**. Lá, descobri que o Wazuh não tinha visibilidade nenhuma sobre o que acontece *dentro* de um processo já autorizado (o shell root aberto via `:!/bin/bash` dentro do `vim`), porque o `auth.log` só registra autenticação e início de sessões `sudo`, não a árvore de processos filhos.

Instalei e configurei o `auditd` (equivalente Linux ao Sysmon do Windows) na `vm-debian-lab`, criei uma regra de auditoria para a chamada de sistema `execve`, e **reproduzi exatamente o mesmo ataque do INC-003** para confirmar que agora a evidência aparece. Resultado: o `auditd` capturou o processo `bash` gerado pelo `vim`, com `uid=root`/`euid=root` (provando a escalada) e `auid=user_lab` (preservando a identidade original da sessão, mesmo após `su` e `sudo`).

## 2. Ambiente

| Componente | Detalhe |
|---|---|
| Alvo | `vm-debian-lab` (Debian 13, agente Wazuh v4.14.9) |
| Ferramenta adicionada | `auditd` 4.0.2 + `audispd-plugins` |
| Pré-requisito explorado | Mesma configuração vulnerável do INC-003 (`suporte ALL=(ALL) NOPASSWD: /usr/bin/vim`), recriada só para o teste e removida ao final |

## 3. MITRE ATT&CK

Este incidente não introduz uma técnica nova — ele é uma **melhoria de detecção** para a técnica já mapeada no INC-003:

| Tática | Técnica | ID |
|---|---|---|
| Privilege Escalation, Defense Evasion | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | T1548.003 (referência ao INC-003) |

## 4. Baseline

- `which auditd` vazio — pacote não instalado antes da simulação.
- Nenhuma regra de auditoria ativa (`auditctl -s` não aplicável, serviço inexistente).

## 5. Implementação

```bash
apt update
apt install auditd audispd-plugins -y
```

Validação do serviço:

```bash
systemctl status auditd
# Active: active (running), enabled no boot

auditctl -s
# enabled 1, failure 1, pid <N>
```

Regra de auditoria criada (runtime, não persistida):

```bash
auditctl -a always,exit -F arch=b64 -S execve -k exec_monitor
```

| Parâmetro | Significado |
|---|---|
| `-a always,exit` | Adiciona à lista de "exit" e sempre gera registro quando a chamada de sistema termina |
| `-F arch=b64` | Restringe à arquitetura 64-bit da VM (`arch=64` é inválido — erro "arch elf mapping not found" na primeira tentativa) |
| `-S execve` | Chamada de sistema monitorada: execução de processo |
| `-k exec_monitor` | Tag (key) escolhida para filtrar depois com `ausearch -k exec_monitor` |

## 6. Linha do tempo

| Hora (BRT) | Evento | Visibilidade |
|---|---|---|
| 04:43:25 | `auditd` instalado e iniciado | — |
| 04:52 | Regra `exec_monitor` adicionada via `auditctl` | `auditctl -l` confirma a regra ativa |
| ~05:01 | Config `/etc/sudoers.d/suporte-edit` recriada (mesma do INC-003) | — |
| 05:02:05 | `su - suporte` → `sudo vim` → `:!/bin/bash` reproduzido | **`auditd` capturou o evento** (antes: nenhum evento) |
| 05:02:54 | Confirmação via `ausearch -k exec_monitor -i` | Evidência completa recuperada |

## 7. Achados

### 7.1 A lacuna do INC-003 foi fechada
O evento de interesse apareceu como:

```
type=SYSCALL msg=audit(05/11/2026 05:02:05.638:178): arch=x86_64 syscall=execve success=yes
 ppid=2039 pid=2043 auid=user_lab uid=root gid=root euid=root suid=root
 fsuid=root egid=root sgid=root fsgid=root tty=tty1 ses=1 comm=bash
 exe=/usr/bin/bash subj=unconfined key=exec_monitor
```

Isso confirma, de forma objetiva e auditável, exatamente o que o `auth.log` nunca mostrou: o processo `bash` com privilégio root (`uid=root`, `euid=root`) nascendo como filho do processo `vim` (`ppid=2039`), e a relação de parentesco entre eles.

### 7.2 Dois campos resolvem dois problemas distintos
| Campo | O que resolve |
|---|---|
| `uid` / `euid` = `root` | Prova que a escalada de privilégio **ocorreu de fato** (o processo passou a rodar com privilégio total) |
| `ppid` / `pid` | Reconstrói a **árvore de processos** — de onde o shell privilegiado nasceu (o `vim` autorizado via sudo) |
| `auid` = `user_lab` | Preserva a **atribuição original**: mesmo com a cadeia `user_lab → su suporte → sudo vim → bash root`, o `auid` não muda. É atribuído uma única vez no login (via PAM) e permanece fixo por toda a árvore de processos daquela sessão, inclusive através de `su`/`sudo`. |

> **Por que o `auid` importa tanto:** um atacante pode trocar de usuário quantas vezes quiser com `su`/`sudo` para tentar confundir a trilha de investigação, mas não consegue alterar o `auid` sem gerar uma nova sessão de login. É a diferença entre "quem está no controle agora" (`uid`/`euid`, mutável) e "quem autenticou primeiro" (`auid`, imutável).

### 7.3 Limite desta implementação
A regra criada com `auditctl` é **apenas em runtime** — ela não sobrevive a um reboot da VM, porque não foi persistida em `/etc/audit/rules.d/audit.rules`. Além disso, o log do `auditd` hoje fica local (`/var/log/audit/audit.log`); ele ainda **não está conectado ao Wazuh**, então não gera alerta no dashboard — só é consultável manualmente via `ausearch`.

## 8. Contenção e limpeza

```bash
rm /etc/sudoers.d/suporte-edit
visudo -c                # confirma sintaxe válida
auditctl -D               # remove a regra de auditoria em runtime
```

## 9. Recomendações

1. **Persistir a regra de auditoria** em `/etc/audit/rules.d/audit.rules`, para que sobreviva a reboots — hoje ela só existe em memória.
2. **Integrar o `auditd` ao Wazuh** via o plugin `audispd` (saída `af_unix`), para que esses eventos virem alertas de verdade no dashboard, em vez de exigirem `ausearch` manual na própria VM. Esse é o próximo passo natural de laboratório — fecharia o ciclo completo: dado existe (auditd) → decoder (Wazuh já tem um decoder nativo para `auditd`) → regra → alerta.
3. **Refinar o escopo da regra**: monitorar todo `execve` do sistema gera bastante volume. Vale estudar regras mais direcionadas (por exemplo, monitorar especificamente processos filhos de binários conhecidos por GTFOBins, ou usar `-F euid=0` para focar em execuções que resultam em privilégio root).
4. **Documentar o campo `auid` como item de treinamento da equipe**: é um dos conceitos mais mal-entendidos em investigações que envolvem `su`/`sudo`, e sua confusão inicial (uid vs. auid) é comum até entre analistas experientes — vale meio parágrafo de nota explicativa em qualquer runbook futuro.
5. **Avaliar `auditd` também para outras chamadas de sistema relevantes** além de `execve` (ex: `connect` para conexões de rede, `open`/`unlink` para acesso e exclusão de arquivos sensíveis).

## 10. Dificuldades encontradas e aprendizados

- Primeira tentativa de regra usou `arch=64`, que é inválido (`arch elf mapping not found`); o valor correto é `arch=b64`.
- O comando correto para consulta é `auditctl`, não `audittctl` (erro de digitação inicial, "comando não encontrado").
- **Lição central:** uma ferramenta de monitoramento de processos como o `auditd` resolve uma categoria de lacuna que nenhuma regra de SIEM, por mais bem escrita que seja, conseguiria fechar sozinha — porque o problema não era "falta interpretar o dado" (caso do INC-002), era "o dado nunca existia em nenhum log monitorado". A solução teve que vir de uma **fonte de dados nova**, não de uma regra nova.
- O campo `auid` foi o maior "aha": a diferença entre privilégio atual (`uid`/`euid`) e identidade original da sessão (`auid`) é um conceito que separa investigação superficial de investigação forense de verdade.

## 11. Indicadores observados (laboratório)

- Processo monitorado: `bash` (comm=bash, exe=/usr/bin/bash)
- Processo pai: `vim` (ppid=2039)
- `auid` preservado: `user_lab` (usuário de login original da sessão)
- `uid`/`euid` no momento da escalada: `root`
- Chave de auditoria usada: `exec_monitor`
- Técnica relacionada: T1548.003 (mesma do INC-003 — este incidente é a correção de visibilidade, não uma exploração nova)
