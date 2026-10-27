# INC-001 (reproduzido) — Brute force SSH via Hydra contra vm-debian-lab

> **Exercício de laboratório próprio.** Ataque autorizado, executado pela analista contra sua própria VM, com ferramentas (Hydra, Wazuh) e rede do lab. Nenhum sistema de terceiros foi envolvido.

| Campo | Valor |
|---|---|
| Ativo-alvo | `vm-debian-lab` (192.168.100.131) |
| Ferramenta de ataque | Hydra v9.6, a partir do Kali (192.168.100.129) |
| Conta-alvo | `suporte` (criada para o exercício, senha fraca `123`) |
| Fonte de detecção | Wazuh (agente `vm-debian-lab`, id 002), correlacionado com `/var/log/auth.log` |
| Severidade | Alta (acesso obtido por força bruta) |
| Técnicas MITRE ATT&CK | **T1110.001** (Brute Force: Password Guessing), **T1021.004** (Remote Services: SSH) |

## 1. Resumo executivo

A analista reproduziu, de ponta a ponta, um ataque de força bruta contra SSH: criou uma conta com senha fraca na VM `vm-debian-lab`, atacou-a a partir do Kali com o Hydra usando uma wordlist de 7 senhas, e acompanhou em tempo real os alertas gerados pelo Wazuh — da primeira tentativa inválida até o login bem-sucedido. O objetivo foi validar o pipeline completo de detecção (log → agente → manager → alerta) e treinar a leitura de alertas correlacionados a um ataque real e controlado.

## 2. Preparação do ambiente

1. Confirmado que o agente Wazuh `vm-debian-lab` estava **Active** no manager.
2. Validado o SSH na VM (`systemctl status ssh`) e testado o pipeline com uma tentativa manual de login com usuário inexistente a partir do Windows (192.168.100.202) — gerou o alerta `sshd: Attempt to login using a non-existent user` (regra 5710, nível 5), confirmando que o caminho log → alerta funcionava antes do ataque real.
3. Criada a conta `suporte` na VM (`useradd` + senha fraca `123`), simulando uma credencial vulnerável.
4. Montada wordlist de 7 senhas no Kali (`/tmp/senhas.txt`), com `123` escondida no meio das demais.

## 3. Execução do ataque

Comando executado no Kali:

```
hydra -l suporte -P /tmp/senhas.txt ssh://192.168.100.131
```

Resultado do Hydra:

```
[22][ssh] host: 192.168.100.131   login: suporte   password: 123
1 of 1 target successfully completed, 1 valid password found
```

O Hydra testou as 7 senhas em sequência e encontrou a correta.

## 4. O que o Wazuh detectou

| Horário (local) | Alerta (rule.description) | rule.id | Nível | O que significa |
|---|---|---|---|---|
| 19:55:54–19:55:58 | `sshd: authentication failed.` / `PAM: User login failed.` / `unix_chkpwd: Password check failed.` | 5760 / 5503 / 5557 | 5 | Tentativas individuais do Hydra, uma por senha errada da lista |
| ~19:55:58 | `syslog: User missed the password more than one time` | 2502 | **10** | O Wazuh correlacionou várias falhas seguidas contra o mesmo usuário em pouco tempo e elevou a severidade — é a assinatura de um ataque automatizado, e não de erro humano |
| 19:56:26 | `PAM: Login session opened.` | 5501 | 3 | Sessão aberta com sucesso após a senha correta ser encontrada |

Evidência de uma das falhas, confirmando a origem do ataque:

```
full_log: Oct 27 22:55:56 debian sshd-session[8488]: Failed password for suporte
          from 192.168.100.129 port 43290 ssh2
data.srcip: 192.168.100.129   (Kali — máquina atacante)
agent.ip:   192.168.100.131   (vm-debian-lab — vítima)
```

**Diferença entre `agent.ip` e `data.srcip`:** `agent.ip` identifica a máquina que gerou o log (a vítima); `data.srcip` identifica de onde veio a conexão (o atacante). Confundir os dois é um erro comum de leitura de alertas.

**Por que a regra 2502 subiu para nível 10:** uma falha isolada (nível 5) pode ser um erro de digitação humano. Várias falhas contra o mesmo usuário em segundos é um padrão que só um script reproduz — é essa repetição, e não uma falha isolada, que caracteriza automação (T1110.001) e justifica a severidade mais alta.

## 5. Indicadores de comprometimento (IOCs)

| Tipo | Valor | Observação |
|---|---|---|
| IP atacante | `192.168.100.129` (Kali, lab) | Origem do brute force |
| Conta visada | `suporte` | Senha fraca, comprometida com sucesso |
| Ferramenta | Hydra v9.6 | Identificável pelo padrão de múltiplas falhas em segundos contra o mesmo usuário |

## 6. Resposta e recomendações (como seria em produção)

1. Bloquear a origem após N falhas em curto intervalo (fail2ban ou Active Response do Wazuh) — é o assunto do INC-005, ainda pendente no lab.
2. Eliminar senhas fracas: política de senha mínima, ou desativar autenticação por senha e exigir chave SSH.
3. Alertar automaticamente quando a regra 2502 disparar, em vez de depender de revisão manual.
4. Revisar o que a conta comprometida fez durante a sessão (neste exercício, nenhuma ação pós-login foi simulada).

## 7. Lições aprendidas

- O pipeline completo (log → agente → manager → alerta) foi validado na prática, não só lido em documentação.
- `agent.ip` é sempre a vítima; `data.srcip` é sempre a origem da conexão.
- A diferença entre nível 5 e nível 10 na mesma regra/família de evento costuma ser o **padrão temporal** (repetição rápida), não o tipo de evento em si.
- Um filtro de exclusão (`- Authentication failure`, `- Authentication success`) mal percebido pode esconder exatamente o evento que se procura — vale conferir os filtros ativos antes de concluir que "não há alerta".
