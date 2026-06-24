# INC-003 – Escalação de Privilégio
**Data:** 22 de junho de 2026
**Analista:** Dalgeni Burak
**Status:** Resolvido

## 1. Sumário  

No dia 22/06 eu criei em laboratório uma misconfiguration sudoers, onde dei a um usuário de produção permissão NOPASSWD para execução no GTFOBins find, essa permissão escala privilégios para executar binários importantes do sistema. O perigo desse erro de configuração é que o SIEM não alerta como um ataque, pois entende que é uma operação válida, logo que o usuário que está executando tem privilégios de root. O comando find é um binário legítimo do sistema e contém o paramêtro -exec que permite executa-lo com privilégios elevados, isso dá ao usuário o poder de ler e escrever arquivos confidenciais do sistema como o /etc/shadow e escalar privilégios, como no caso da minha simulação com a permissão **sudo NOPASSWD**.  
 
### Cronologia
Jun 22 19:52:00 - criação do usuário operador via adduser  
Jun 22 19:53:44 - configuração do sudoers com visudo
Jun 22 19:57:34 - ínicio da exploração com o usuário operador
Jun 22 20:22:21 - usuário removido do sistema com userdel -r operador


## 2. Dados do Alerta
	
rule.id: 5402  

rule.level: 3  

rule.description: Successful sudo to ROOT executed.  

rule.mitre.id: T1548.003  

rule.mitre.tactic: Privilege Escalation, Defense Evasion  

rule.mitre.technique: Sudo and Sudo Caching  

location: journald  

full_log: Jun 22 23:00:30 debian sudo[9989]: operador : TTY=pts/0 ; PWD=/home/operador ; USER=root ; COMMAND=/usr/bin/find . -exec /bin/sh ; -quit  

Timestamp: Jun 22, 2026 @ 19:53:44.796  

## 3. Investigação  

Após uma consulta no log **/var/log/auth.log** para buscar eventos do usuário, identifiquei que o host não tinha o rsyslog instalado, o que estava deixando o wazuh sem visibilidade dos logs de autenticação. Após fazer a instalação do rsyslog fiz a descoberta da grave falha de configuração, (ALL) NOPASSWD: /usr/bin/find. Verificando na interface do SIEM wazuh constatei que ele estava registrando com  o evento com severidade inadequada **rule.level: 3** o que é insuficiente para falha, deveria ter feito a correlação entre o uso do parâmetro -exec do find. Isso mascarou a falha, o que faz com que esse tipo de ataque seja muito difícil de detectar.

## 4. Contenção  

Para contenção rápida utilizei o **usermod -L operador** para bloquear a conta do usuário operador e o **pkill -KILL -u operador** para derrubar qualquer conexão ativa deste usuário.


## 5. Erradicação  

Realizada a remoção do arquivo **/etc/sudoers.d/operador** com permissão do sudoers e feita uma verificação com **grep -r "NOPASSWD" /etc/sudoers **, que não retornou nenhuma entrada NOPASSWD o que confirmou que não havia outras configurações vulneráveis. Após isso o usuário foi removido completamente do sistema **userdel -r operador**


## 6. Conclusão  

Esta é uma ameaça difícil de detectar, pois o SIEM entende como uma operação legítima, uma vez que o usuário está rodando arquivos com permissões de root. É normalmente utilizada para criar persistência quando o atacante já se infiltrou no sistema ou usuários comuns acabam prejudicando o sistema por terem privilégios além do necessário oriundas de configurações erradas. 

## 7. Recomendações  

Para garantir que essa ameaça seja identificada e registrada com a severidade correta pelo SIEM, é necessário criar uma regra customizada para detectar quando o find for usado com -exec. E também é necessário uma auditoria detalhada em todos os hosts para validar que não há mais configurações indevidas.

## 8. Lições Aprendidas
Neste laboratório aprendi que não devo apenas ficar com o que os alertas convencionais do SIEM me trazem, que explorar o sistema em busca de falhas é importante. A severidade padrão engana: Ataques perigosos adoram se esconder atrás de permissões legítimas. Nível baixo no console não significa baixo risco na realidade.
