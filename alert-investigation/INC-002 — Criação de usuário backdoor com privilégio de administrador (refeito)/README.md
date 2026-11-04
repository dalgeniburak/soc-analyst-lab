# INC-002 — Criação de usuário backdoor com privilégio de administrador (refeito)

| Campo | Valor |
|---|---|
| **ID** | INC-002 (reexecução do zero) |
| **Analista** | Dalgeni |
| **Data da simulação** | 31/10/2026 (madrugada) |
| **Data da validação em evento real** | 02/11/2026 |
| **Fuso dos horários** | Brasília (UTC-3), salvo indicação |
| **Severidade do cenário** | Alta (persistência + privilégio administrativo) |
| **Status** | Encerrado: backdoor removido, detecção corrigida e validada |

## 1. Resumo executivo

Em um laboratório controlado, simulei um atacante que já tinha acesso root a uma VM Debian e criou uma conta de acesso persistente (`sysupdate`), definiu uma senha e a colocou no grupo `sudo`.

O Wazuh detectou a **criação** da conta (regras 5901 e 5902, nível 8) e a **definição da senha** (regra 5555, nível 3), mas **não gerou nenhum alerta** para a etapa mais perigosa: a inclusão da conta no grupo `sudo`. O sistema registrou o evento no `auth.log`; o SIEM não o transformou em alerta.

Corrigi a lacuna criando um **decoder** e uma **regra** customizados (regra 100100, nível 12, MITRE T1098), validei com testes positivo e negativo no Ruleset Test e confirmei com um **evento real** passando pelo agente até o dashboard.

## 2. Ambiente

| Componente | Detalhe |
|---|---|
| Alvo monitorado | `vm-debian-lab` (Debian 13, agente Wazuh v4.14.9, ID 002) |
| Manager / dashboard | `vm-wazuh-lab` (hostname `labwazuh`, Ubuntu 22.04) |
| Virtualização | Proxmox |
| Origem dos logs | `auth.log` via `journald`, coletado pelo agente |

## 3. MITRE ATT&CK

| Tática | Técnica | ID | Etapa |
|---|---|---|---|
| Persistence | Create Account (conta local) | T1136 (T1136.001) | `useradd` |
| Persistence | Account Manipulation | T1098 | `usermod -aG sudo` |

## 4. Baseline (antes da simulação)

- `/etc/passwd` sem usuário suspeito. Contas humanas: `user_lab` (1000) e `suporte` (1001); conta de serviço `wazuh` com shell `nologin`.
- Grupo `sudo` **vazio** (`sudo:x:27:`).
- Dashboard (últimas 24 h): 0 crítico, 0 alto, 0 médio, 12 baixo.
- Agentes: 1 ativo e 1 desconectado (o ativo era a `vm-debian-lab`).

Sem esse baseline não seria possível provar o que mudou depois.

## 5. Linha do tempo

| Hora (BRT) | Fonte | Evento | Detecção no Wazuh |
|---|---|---|---|
| 03:41:32 | `auth.log` | `su`: `user_lab` virou root no `tty1` | Não verificado |
| 03:44:00 | `auth.log` | `useradd`: novo grupo `sysupdate` (GID 1002) | Regra **5901**, nível 8 |
| 03:44:00 | `auth.log` | `useradd`: novo usuário `sysupdate` (UID 1002, home `/home/sysupdate`, shell `/bin/bash`) | Regra **5902**, nível 8, T1136 |
| 03:44:43 | `auth.log` | `passwd`: senha definida para `sysupdate` | Regra **5555**, nível 3 |
| 03:45:08 | `auth.log` | `usermod`: `sysupdate` adicionado ao grupo `sudo` (e ao shadow group `sudo`) | **Nenhum alerta** |

**Observação de fuso:** o mesmo evento aparece como `03:44:00` no dashboard (Brasília) e `06:44:00` no campo `predecoder.timestamp` (UTC, vindo do `journald`). Em investigações reais, misturar fusos distorce a linha do tempo, então os horários deste relatório estão padronizados em Brasília.

## 6. Investigação e achados

### 6.1 A cadeia de persistência foi parcialmente detectada
Dois alertas nível 8 no mesmo segundo, vindos do mesmo programa (`useradd`), formam a assinatura de "conta nova criada". O alerta 5902 trouxe os campos que um analista precisa: usuário, UID, home e **shell** (`/bin/bash`, um shell de login, mais suspeito que `nologin`).

### 6.2 A definição da senha ficou escondida por filtro de severidade
O alerta 5555 é de nível 3. Ao filtrar o dashboard por nível 7 a 11, só apareceu 1 evento. A cadeia completa só ficou visível ao buscar o termo `sysupdate` sem filtro de severidade.

> **Lição:** filtrar apenas por severidade alta pode esconder metade da cadeia do ataque.

### 6.3 A escalada para `sudo` não gerou alerta (lacuna de detecção)
- `getent group sudo` confirmou `sudo:x:27:sysupdate`.
- O `auth.log` registrou às 03:45:08 as duas linhas do `usermod`.
- A busca por `usermod` no Threat Hunting (últimas 24 h) retornou **zero resultados**.
- A busca por `sysupdate` retornou apenas 3 eventos (5901, 5902, 5555).

Conclusão: o sistema registrou a ação, mas nenhuma regra gerou alerta. Um analista que dependesse só do dashboard veria a conta nascer e **não veria** que ela virou administradora.

### 6.4 Limitação do diagnóstico
Um primeiro teste da linha do `usermod` no Ruleset Test retornou "No decoder matched", mas as linhas haviam sido coladas com espaços à esquerda, o que impediu a leitura da data, do hostname e do programa. Esse resultado **não foi usado como prova**. O que está comprovado é a ausência de alerta no dashboard. Não verifiquei se existia algum decoder padrão para o `usermod` além do criado por mim.

## 7. Impacto avaliado

A conta `sysupdate` reunia login interativo (`/bin/bash`), diretório pessoal e privilégio de administrador. Em um cenário real, isso é acesso persistente e privilegiado que sobrevive à troca da senha ou ao bloqueio da conta original comprometida. O nome `sysupdate` imita um serviço do sistema e dificulta a identificação em uma olhada rápida.

## 8. Contenção e erradicação

Executadas como root (`su -`; a primeira tentativa como `user_lab` foi negada, pois alterar grupos exige root):

1. `gpasswd -d sysupdate sudo`: remove a conta do grupo privilegiado.
2. `userdel -r sysupdate`: remove a conta e o diretório pessoal. O aviso sobre `/var/mail/sysupdate` não encontrado é inofensivo (a conta nunca recebeu e-mail).
3. `getent group sudo`: confirmou `sudo:x:27:`, igual ao baseline.

## 9. Melhoria de detecção

### 9.1 Decoder `usermod-custom`
O decoder transforma a linha de texto do `usermod` em campos que as regras conseguem avaliar: `dstuser` (quem) e `target_group` (qual grupo). Arquivo: `local_decoder.xml`.

### 9.2 Regra 100100 (nível 12)
A regra avalia o campo `target_group`. Se for `sudo`, `adm` ou `wheel`, gera alerta nível 12, com a descrição "User $(dstuser) added to privileged group $(target_group)" e mapeamento MITRE T1098. Arquivo: `local_rules.xml`.

**Por que nível 12:** criar um usuário (nível 8) é rotina de administração; conceder `sudo` entrega controle total do sistema, então o impacto é maior.

### 9.3 Validação

| Teste | Resultado |
|---|---|
| `GET /rules?rule_ids=100100` | Regra `enabled`, nível 12, `decoded_as: usermod-custom`, T1098 |
| Ruleset Test, positivo (`sysupdate` no `sudo`) | Fase 2: `dstuser: sysupdate`, `target_group: sudo`. Fase 3: regra **100100**, nível 12, "Alert to be generated" |
| Ruleset Test, negativo (`maria` no grupo `users`) | Fase 2 decodifica; Fase 3 **sem regra**, nenhum alerta (sem falso positivo) |
| **Evento real** (02/11/2026, 13:57:54 BRT) | Alerta **100100**, nível 12, agente `vm-debian-lab`, `location: journald`, MITRE T1098 (Persistence / Account Manipulation) visível no dashboard |

## 10. Dificuldades encontradas e aprendizados

- **Espaços invisíveis ao colar logs:** impediram a leitura da Fase 1 do Ruleset Test. Resolvido digitando a linha sem espaço à esquerda.
- **Tag XML incorreta:** usei `<decoder_name>` na regra, que não existe; o Wazuh recusou o arquivo com "XML syntax error". O correto é `<decoded_as>`. O arquivo no servidor permaneceu intacto.
- **Reinício do manager:** decoders e regras salvos só valem para os alertas reais depois do restart (`PUT /manager/restart` no Dev Tools).
- **Ruleset Test não é produção:** ele prova que a lógica funciona, mas só um evento real prova que o fluxo agente → manager → dashboard funciona.

## 11. Recomendações

1. Manter a regra 100100 e ampliar a lista de grupos privilegiados conforme o ambiente (por exemplo `docker`, cujos membros costumam ter poder equivalente ao root).
2. Criar uma regra de **correlação**: alertar quando o 5902 (usuário criado) for seguido pelo 100100 (entrou no `sudo`) na mesma conta em poucos minutos, o que eleva a confiança de que é malicioso.
3. Avaliar monitoramento de integridade de arquivos (FIM) em `/etc/passwd`, `/etc/group` e `/etc/sudoers`, para detectar mudanças mesmo quando o log não for gerado ou não for lido.
4. Padronizar o fuso dos logs e das ferramentas de investigação.
5. Na triagem, não filtrar só por severidade: buscar pelo objeto (usuário, host) para reconstruir a cadeia inteira.

## 12. Indicadores observados (laboratório)

- Usuário: `sysupdate` (UID/GID 1002), home `/home/sysupdate`, shell `/bin/bash`
- Mudança de grupo: `sysupdate` adicionado a `sudo`
- Origem da ação: sessão root aberta via `su` por `user_lab` no `tty1`

## Apêndice — arquivos de detecção

Ver `usermod-custom-decoder.xml` e `rule-100100-privileged-group.xml` neste diretório.

Observação: na VM do laboratório o pacote sudo não estava instalado, portanto a inclusão no grupo sudo não concedia privilégio efetivo. A detecção continua válida, pois em sistemas reais o sudo está presente e essa ação resulta em escalada de privilégio.
