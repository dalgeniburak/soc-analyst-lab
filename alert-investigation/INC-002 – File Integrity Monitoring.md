INC-002 – File Integrity Monitoring
Data: 20 de junho de 2026
Analista: Dalgeni Burak
Status: Resolvido

1. Sumário
No dia 20/06/2026 o SIEM Wazuh detectou uma mudança em /etc/passwd, o arquivo mais crítico do sistema linux. O alerta exigiu verificação imediata, pois se um atacante está tentando persistência, é esse arquivo que irá modificar. Foi identificada a criação de um novo usuário.

2. Dados do Alerta
	
rule.id: 550
rule.level: 7
rule.mitre.id: T1565.001
rule.mitre.tactic: Impact
rule.mitre.technique: Stored Data Manipulation
rule.firedtimes: 10
syscheck.path: /etc/passwd
syscheck.uname_after: root
syscheck.size_before: 2,291
syscheck.size_after: 2,236
syscheck.changed_attributes: size, inode, mtime, md5, sha1, sha256
syscheck.sha256_before: a0762e9c052e74d4afccd60cf3a9ea23d0fbf01e7bde755587432151d859cb24
syscheck.sha256_after: 9138457b9ec6a0ca1a9563d70d2312fdd1dcca12e992c94f58c4dfac25b79c18  
syscheck.md5_before: 5fe3173f185544f5ba1bacc689c5e99a
syscheck.md5_after: b8901a0f8c2520c2fdc693e6f0f3de1c
syscheck.mtime_after: Jun 20, 2026 @ 19:55:32.000 
Timestamp: Jun 20, 2026 @ 19:56:35.041 

3. Investigação

Evidencias coletadas 

grep “atacante2026” /etc/passwd

/home/atacante2026: /bin/bash

Conclusão da investigação
Após a verificação foi definido que o atacante entrou na rede via ssh com privilégios root e criou uma conta com shell /bin/bash, para conseguir login interativo.

4. Contenção

#Foi realizado o bloqueio da conta do usuário.
sudo usermod -L atacante2026

#Confirmação de bloqueio bem sucedido
sudo grep “atacante2026” /etc/shadow | cut -d: -f2

5. Erradicação

#Usuário removido totalmente do sistema
sudo userdel -r atacante2026

#Confirmação de exclusão de usuário
grep “atacante2026” /etc/passwd

#Verificar se o diretório home foi removido
ls /home/atacante2026

#Verificar se ainda existe no shadow
grep "atacante2026" /etc/shadow

#Confirmar que nunca logou
last | grep "atacante2026"

6. Conclusão
FIM detectou alteração no /etc/passwd, durante a investigação foi identificado a criação do usuário atacante2026, o usuário foi bloqueado com usermod -L e logo em seguida removido com userdel -r. Após uma verificação detalhada foi constatado que não havia mais rastros no sistema.
