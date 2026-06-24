## INC-001 - Ataque de Força Bruta SSH 

**Data:** 14 de junho de 2026

**Analista:** Dalgeni Burak 

**Status:** Resolvido 

# 1. Sumário 


No dia 14/06/2026 o SIEM Wazuh começou a exibir alertas de uma possível tentativa de ataque de força bruta, por volta das 18:12 com duração até 18:16 aproximadamente. Foram várias tentativas de login indevido partindo do mesmo IP de origem, uma máquina Windows 192.168.100.113. Investigando mais detalhadamente os alertas, constatou-se que se tratava de um verdadeiro positivo.

# 2. Dados do Alerta

rule.id Valor:	2502  
rule.level: 10  
rule.mitre.id:	T1110  
rule.mitre.tactic: Credential Access  
rule.mitre.technique: Brute Force  
rule.firedtimes: 13  
agent.name: vm-debian-lab  
agent.ip: 192.168.100.114  
Timestamp	Jun 14: 2026 @ 18:15:30.093.

# 3. Investigação


Evidências coletadas nos logs  

Total de tentativas:	132  

Usuários inválidos testados:	96  

Usuário root testado:	36  

Período do ataque:	18:12:12 até 18:16:03  

Logins aceitos:	0  

Usuários criados pelo atacante:	0  

**Conclusão da investigação:**  

Após a investigação ficou constatado que o atacante estava usando força bruta automatizada. Não houve sucesso na tentativa de invasão quebrando senhas e nem houve criação de novos usuários pelo atacante.

# 4. Contenção


Foi adicionada uma regra de bloqueio para o IP do atacante no firewall UFW. O IP 192.168.100.113 foi bloqueado com o comando sudo ufw deny from 192.168.100.113. A regra foi confirmada via sudo ufw status, com resultado: Anywhere DENY 192.168.100.113.

# 5. Erradicação


Foi verificado via journalctl que não houve nenhum login bem sucedido ao sistema. Todos os acessos identificados foram por meio de usuário legítimo, confirmado via comando last.

# 6. Conclusão


O ataque de técnica T1110 - Brute Force foi identificado e contido. O sistema encontra-se limpo, o IP atacante 192.168.100.113 foi bloqueado no UFW e nenhuma evidência de comprometimento do sistema foi encontrada.  

**Recomendações:**  

Desabilitar o login root via SSH  

Reiniciar o serviço SSH  

Instalar e configurar o Fail2Ban  

Trocar o número da porta padrão 22/TCP  
