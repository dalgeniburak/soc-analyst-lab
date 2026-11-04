# INC-003 — Escalada de privilégio via `sudo` mal configurado (refeito)

| Campo | Valor |
|---|---|
| **ID** | INC-003 (reexecução do zero) |
| **Analista** | Dalgeni |
| **Data da simulação** | 04/11/2026 (madrugada) |
| **Fuso dos horários** | Brasília (UTC-3), salvo indicação |
| **Severidade do cenário** | Alta (escalada completa de privilégio comum → root) |
| **Status** | Encerrado: brecha removida; lacuna estrutural de visibilidade documentada |

## 1. Resumo executivo

Simulei, em laboratório controlado, uma configuração comum de erro administrativo: liberar um editor de texto (`vim`) via `sudo` para uma conta comum, sem exigir senha, "só para mexer em um arquivo de configuração". Usando a conta `suporte`, explorei essa liberação para abrir um shell com privilégio de root a partir de dentro do `vim`.

O Wazuh **detectou e classificou corretamente** o uso do `sudo` como MITRE **T1548.003** (Abuse Elevation Control Mechanism: Sudo), mas atribuiu **nível 4**, dentro da faixa de severidade baixa. Além disso, identifiquei uma lacuna de visibilidade mais profunda que a do INC-002: o Wazuh não registrou **nenhum** evento sobre o que aconteceu depois da escalada (o shell root aberto e os comandos executados dentro dele), porque a fonte de dados monitorada (`auth.log`) não captura esse tipo de atividade.

## 2. Ambiente

| Componente | Detalhe |
|---|---|
| Alvo | `vm-debian-lab` (Debian 13, agente Wazuh v4.14.9) |
| Manager / dashboard | `vm-wazuh-lab` |
| Conta explorada | `suporte` (mesma conta do INC-001) |
| Pré-requisito | Pacote `sudo` (não estava instalado; precisou ser instalado para este incidente) |

## 3. MITRE ATT&CK

| Tática | Técnica | ID |
|---|---|---|
| Privilege Escalation, Defense Evasion | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | **T1548.003** |

Confirmado diretamente no campo `rule.mitre.id` do próprio Wazuh — não foi necessário mapear manualmente, como no INC-002.

## 4. Baseline

- Pacote `sudo` **não instalado** (`which sudo` vazio, `/etc/sudoers.d/` inexistente).
- Grupo `sudo` existente, porém vazio.

**Observação relevante:** esse baseline invalida parcialmente uma conclusão do relatório do INC-002, onde eu havia descrito a entrada no grupo `sudo` como concessão efetiva de privilégio de administrador. Como o programa `sudo` não estava instalado naquele momento, essa afirmação não se sustentava na prática no ambiente do laboratório (embora a regra de detecção criada ali continue correta para ambientes reais, onde o `sudo` está presente). Uma nota de correção foi adicionada ao relatório do INC-002.

## 5. Configuração vulnerável criada

Arquivo `/etc/sudoers.d/suporte-edit`, criado com `visudo -f` (edição seções segura, que valida a sintaxe antes de salvar):

```
suporte ALL=(ALL) NOPASSWD: /usr/bin/vim
```

Essa linha autoriza a conta `suporte` a executar `/usr/bin/vim` como **qualquer usuário** (`ALL`), **sem senha**. Na superfície, parece uma liberação pontual e inofensiva. Na prática, é uma porta aberta: o `vim` possui o recurso `:!comando`, que executa comandos do sistema operacional herdando o mesmo privilégio do processo `vim` em execução — nesse caso, root. Esse padrão (programas comuns que podem ser abusados para escapar para um shell privilegiado) está documentado publicamente no catálogo GTFOBins e não é exclusivo do `vim`.

## 6. Linha do tempo

| Hora (BRT) | Evento | Detecção no Wazuh |
|---|---|---|
| 04:58:43 | `sudo vim` tentado por `suporte` **antes** de o `vim` estar instalado | Regra **5406** ("Command not allowed"), nível 5 |
| ~04:59 | `vim` instalado (`apt install vim`) | — |
| 05:01:07 | `sudo vim` executado com sucesso por `suporte` | Regra **5403** ("First time user executed sudo"), nível 4, **T1548.003** |
| 05:01:0x | Dentro do `vim`: `:!/bin/bash` — shell root aberto (prompt `root@debian:/home/suporte#`) | **Nenhum evento** |
| 05:0x | `whoami`, `id` executados dentro do shell root, confirmando privilégio | **Nenhum evento** |

## 7. Achados

### 7.1 Detecção correta, mas priorização inadequada
A regra 5403 identifica e mapeia corretamente a técnica MITRE (T1548.003, Privilege Escalation), mas atribui nível 4 (severidade baixa) para **qualquer** primeiro uso de `sudo` por um usuário — seja uma ação administrativa rotineira, seja uma escalada maliciosa completa como a simulada aqui. A regra não diferencia os dois cenários.

> **Risco prático:** um analista que triasse alertas apenas por severidade alta (nível 12+, como fizemos no INC-002) nunca veria este evento. A escalada completa de privilégio ficaria classificada no mesmo patamar de um comando `sudo apt update` legítimo.

### 7.2 Lacuna estrutural de visibilidade (mais grave que a do INC-002)
Buscas por `whoami` e `bash` no período do incidente não retornaram **nenhum resultado**. O Wazuh registrou apenas o início do `sudo vim` (evento 5403); tudo o que ocorreu depois — abertura do shell root, comandos executados dentro dele — é completamente invisível.

**Diferença importante em relação à lacuna do INC-002:**

| | INC-002 (grupo sudo) | INC-003 (shell via vim) |
|---|---|---|
| O dado chegou a ser registrado em algum log? | Sim (`auth.log`) | Não — nenhuma fonte monitorada captura isso |
| O que faltava | Decoder + regra customizados | Uma fonte de dados inteira (monitoramento de processos) |
| Corrigível só editando arquivos do Wazuh? | Sim | Não |

No INC-002, o dado existia e só precisava ser interpretado. Aqui, o dado **nunca chega a existir** em nenhum log monitorado pelo agente padrão, porque o `auth.log` registra autenticações e início de sessões `sudo`, mas não a árvore de processos filhos que um programa autorizado decide executar por dentro. Nenhuma regra, por mais bem escrita que seja, resolveria isso sem uma fonte de dados adicional.

## 8. Contenção e erradicação

```bash
rm /etc/sudoers.d/suporte-edit
visudo -c          # confirma sintaxe válida após a remoção
```

Validado: `sudo -l` como `suporte` passou a exigir senha e recusar ("usuário suporte não pode executar sudo em debian").

## 9. Recomendações

1. **Revisar regras de `sudo` existentes** no ambiente contra o catálogo GTFOBins antes de liberar qualquer binário sem restrição de argumentos — editores, paginadores, interpretadores e até utilitários como `find` costumam ter brechas equivalentes.
2. **Nunca usar `NOPASSWD` combinado com um binário que permite execução de comandos arbitrários.** Quando a liberação for estritamente necessária, restringir por argumento específico sempre que o programa suportar, e preferir exigir senha.
3. **Reclassificar a severidade da regra 5403** (ou criar uma regra de correlação) para elevar o nível quando o comando autorizado for um binário conhecido por permitir fuga de shell (vim, less, more, find, awk, entre outros do GTFOBins).
4. **Adicionar monitoramento de processos (`auditd` no Linux, equivalente ao Sysmon no Windows)** para fechar a lacuna estrutural. Sem isso, qualquer escalada que ocorra "dentro" de um processo autorizado permanece invisível, independentemente de quantas regras de SIEM sejam criadas. Esta é a recomendação de maior impacto deste relatório e um bom próximo passo de laboratório.
5. **Auditar periodicamente `/etc/sudoers` e `/etc/sudoers.d/`** em busca de liberações amplas (`ALL`, `NOPASSWD`) concedidas para resolver problemas pontuais e nunca revertidas.

## 10. Dificuldades encontradas e aprendizados

- O pacote `sudo` não estava instalado na VM, o que exigiu revisar uma conclusão já publicada no relatório do INC-002.
- Primeira tentativa de `sudo vim` falhou por o `vim` ainda não estar instalado — útil para registrar que o `sudo` valida o caminho exato do binário autorizado.
- Confusão momentânea entre prompt de root (`#`) e de usuário comum (`$`) ao rodar `sudo -l`, corrigida reexecutando no contexto certo.
- **Lição central:** classificar alertas apenas pela severidade atribuída pela regra é insuficiente. Um evento de nível 4 (baixo) pode representar uma escalada de privilégio completa, enquanto a severidade correta exigiria contexto adicional (qual comando, qual usuário, qual histórico) que a regra genérica não avalia sozinha.

## 11. Indicadores observados (laboratório)

- Conta explorada: `suporte`
- Binário abusado: `/usr/bin/vim`
- Técnica: `vim` → `:!/bin/bash` (fuga para shell privilegiado)
- Regra sudoers vulnerável: `suporte ALL=(ALL) NOPASSWD: /usr/bin/vim`
