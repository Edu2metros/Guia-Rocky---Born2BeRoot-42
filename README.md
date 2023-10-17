# Guia Rocky - Born2BeRoot 42

## Instalação da ISO

- Baixe a ISO em [https://rockylinux.org/download/](https://rockylinux.org/download/).
- Instale a ISO em sua máquina virtual (VM).
- Clique em "NEW" na VM, selecione o nome, tipo (Linux), e versão (Red Hat 64-bit).
- Configure as seguintes opções:
  - Memory Size: 1024 MB
  - Create a virtual hard disk now
  - VDI
  - Dynamically allocated
  - File Location and size: 30.8 GB
- Crie e inicie a VM.

## Instalação
- Selecione a ISO
- Install Rocky Linux 9.2
- Selecione o seu idioma
- Selecione “Destino da Instalação”.
- Na seleção de Armazenamento, selecione “personalizada” e depois “pronto”
Abrirá uma tela similar a essa:
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-46-33%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

Antes de ir para as partições, vamos explicar algumas coisas :)

![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-46-55%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

- No subject o exemplo mostra um sda2 com size de 1K e sem Mountpoint.
Nós não conseguiremos fazer isso pois essa partição é criada automaticamente pelo Debian e não conseguiremos replicar, mas sem problema. Não terá nenhum impacto.

Começaremos criando o sda1, onde está LVM, selecione “partição padrão” e clique em ‘+’.

Ponto de montagem selecione /boot e a capacidade desejada, escreva 500m e adicionar um ponto de montagem.

![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-47-08%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

Selecione ‘+’ novamente.
Ponto de montagem selecione ‘/’ e coloque 10G
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-47-14%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

Em tipo de dispositivo, selecione LVM
Para criar um grupo de volume com LVM, vá em:
Grupo de Volume -> Modificar
Em nome, coloque: LVMGROUP
Selecione criptografar, ficará assim:

![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2018-04-33%20Guia%20Rocky%20-%20Born2BeRoot%2042.png?raw=true)


Ficará assim:
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-47-31%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

Clique em ‘+’ 
Ponto de Montagem: /home
Capacidade desejada: 5G
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-47-38%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

Tipo de dispositivo: LVM -> Atualizar configurações

Clique em ‘+’
Ponto de montagem: swap
Capacidade desejada: 2.3G
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-47-49%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

Tipo de dispositivo: LVM -> Atualizar configurações

Faremos as mesmas coisas para as próximas partições…
var:
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-47-56%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

srv:
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-48-02%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

tmp:
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-48-07%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

var–log:
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-48-15%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)


Depois de todas as criações de partições, você deve selecionar em tipo de dispositivo: LVM e depois atualizar configurações.
Ficará assim:
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-48-22%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

Aperte “pronto”.
Insira sua palavra chave.
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-48-29%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

Clique em KDUMP e em seguida pronto.

Em Fonte da Instalação


- Voltando a tela inicial, clique em: seleção de programas 
- Em Software adicional para o ambiente selecionado clique em padrão 
- Pronto
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-48-36%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)

Clique na senha do root e configure.
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-48-44%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)
Criação de Usuário:
Coloque o seu login da intra e senha do usuário.
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-48-50%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)
Finalmente, inicie a instalação :)
Enquanto instala, vamos estudar algumas coisas:
## LVM (Gerenciador de Volume Lógico) 
- O Gerenciador de Volume Lógico (LVM) é uma ferramenta poderosa usada para gerenciar o armazenamento em sistemas Linux. Ele oferece controle flexível sobre o particionamento, alocação e expansão de espaço de armazenamento. Com o LVM, você pode criar partições personalizadas e alocar espaço dinamicamente em diferentes dispositivos de armazenamento, tornando-o uma ferramenta essencial para otimizar o gerenciamento de armazenamento em computadores.

## LUKS (Linux Unified Key Setup) 
- O LUKS é um sistema de criptografia de disco amplamente usado no Linux para proteger dados armazenados em dispositivos de armazenamento. Funciona criptografando automaticamente todos os dados em um dispositivo ou partição, tornando-os ilegíveis sem a chave de descriptografia correta. O LUKS pode ser integrado ao Gerenciador de Volume Lógico (LVM), permitindo que você gerencie partições criptografadas com flexibilidade.

## SSH (Secure Shell) 
- O Secure Shell (SSH) é um protocolo e ferramenta de criptografia que fornece comunicação segura entre sistemas em uma rede não confiável, como a Internet. O SSH garante a confidencialidade e a integridade dos dados transmitidos e autentica as partes envolvidas. É amplamente usado para acesso remoto a servidores, transferência segura de arquivos e execução segura de comandos em sistemas remotos, oferecendo uma alternativa segura ao Telnet.

## DNF (Dandified Yum)
- O DNF é um gerenciador de pacotes usado em sistemas Linux, permitindo a instalação, atualização e remoção de pacotes de software. É uma ferramenta eficaz para a gestão de software, garantindo que os sistemas estejam atualizados e seguros.

-Inicie a VM

-Inicie como root e insira a senha.
As nossas partições, deverá ficar assim:
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-49-02%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)
Configuração de sudo.



- Entre no root e coloque o seu usuario como grupo do sudo:
usermod -aG wheel (seu_usuario)

## Configuração de SSH, Firewall e SELinux

### SSH
- Faça o comando: “vi /etc/ssh/sshd_config”
- Localize a linha “Port 22”, descomente e troque por “Port 4242”
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-49-11%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)
- Procure a linha “#PermitRootLogin”, descomente e deixe: “PermitRootLogin no”
- Localize a linha “PasswordAuthentication yes” e descomente. Se você não encontrar, adicione ela.
- Salve e saia do arquivo apertando ESC -> dois pontos -> digite wq -> enter.
- Escreva o comando: 
ssh-keygen -t rsa
- Pressione enter três vezes seguidas.
Na sua VirtualBox, clique em settings -> Network -> Attached to: Bridged Adapter.
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-49-17%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)
- Dê reboot e entre no root.



### Firewalld

- Abra uma porta 4242 pro SSH:
- firewall-cmd --add-port=4242/tcp --permanent
- firewall-cmd --reload


### SELinux

- sudo dnf install -y policycoreutils-python-utils
- sudo semanage port -a -t ssh_port_t -p tcp 4242
- Para testar, escreva:
sudo semanage port -l | grep ssh
- Precisa sair um output que tenha a porta 4242
- Dê reboot e entre no root.


Pronto. Agora você consegue conectar pelo SSH 🙂
- hostname -I
- Abra o terminal
- ssh (seu_usuario)@(ip do hostname -I) -p 4242

## Configuração de SUDO
O Sudo vem automaticamente instalado no Rocky, isso aconteceu quando você selecionou “Instalação mínima e padrão”, então não é necessário instalar.

O grupo wheel é um modelo mais antigo usado para conceder permissões de superusuário (root) a outros usuários. Agora o seu usuário é capaz de realizar operações usando sudo.

- Acesse seu arquivo de configuração sudo: visudo
Adicione essas linhas no final do arquivo:
```
Defaults    	passwd_tries=3
Defaults    	badpass_message="(message)" # configuração de mensagem personalizada quando erra senha. Dentro do parênteses coloque a mensagem que você quer. 
Defaults    	log_input
Defaults    	log_output
Defaults    	requiretty
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin”
Defaults	logfile=/var/log/sudo/sudo.log
``````
Pesquise o cada comando faz!
- Crie um arquivo chamado "sudo.log" na pasta /var/log/sudo:
- cd /var/log/
- mkdir sudo | cd sudo
- touch sudo.log

## Hostname e Grupo

- O subject pede para que o seu hostname seja o seu login seguido de um 42, para fazer isso, escreva:
```
sudo hostnamectl set-hostname (login_intra42)
```
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-49-28%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)
- Também pedem para que o seu usuário esteja no grupo user42, faremos isso:
```
sudo groupadd user42 
sudo usermod -aG user42 (nomeusuario)
```
![](https://github.com/Eduu19/Guia-Born2BeRoot-Rocky/blob/master/Imagens/Screenshot%202023-10-17%20at%2017-49-34%20Guia%20Rocky%20-%20Born2BeRoot%2042%20-%20Guia%20Rocky%20-%20Born2BeRoot%2042.pdf.png?raw=true)
## Script

No Subject pedem para que você crie um script que de a descrição da máquina a cada 10 minutos.
cd /usr/local/bin

vi monitoring.sh
```
#!/bin/bash

    ARCH=$(uname -m)
    KERNEL=$(uname -r)
    CPU_PHYSICAL=$(lscpu | grep "Socket(s):" | awk '{print $2}')
    VCPU=$(lscpu | grep "^CPU(s):" | awk '{print $2}')
    RAM=$(free -m | awk '/Mem/ {printf "%d MB (%.2f%%)\n", $3, $3/$2*100}')
    DISK=$(df -h / | awk '/\// {printf "%s/%s (%s)\n", $3, $2, $5}')
    CPU_LOAD=$(top -bn1 | grep "Cpu(s)" | awk '{printf "%.1f%%", $2}')
    LAST_BOOT=$(who -b | awk '{print $3, $4}')
    LVM_STATUS=$(lvdisplay > /dev/null 2>&1 && echo "yes" || echo "no")
    TCP_CONNECTIONS=$(ss -tn state established \( dport = :ssh or sport = :ssh \) | grep -c -v LISTEN)
    USER_LOG=$(who | wc -l)
    IP_MAC=$(ip -4 -o addr show | awk '!/^[0-9]*: ?lo/ {print $4 " ("$2")"}')
    SUDO_CMDS=$(journalctl _COMM=sudo | grep COMMAND | wc -l)

    wall <<EOF
==================== Server Monitoring ====================
- OS Architecture: $ARCH
- Kernel Version: $KERNEL
- Physical Processors: $CPU_PHYSICAL
- Virtual Processors: $VCPU
- RAM Usage: $RAM
- Disk Usage: $DISK
- CPU Load: $CPU_LOAD
- Last Reboot: $LAST_BOOT
- LVM use: $LVM_STATUS
- TPC Connections: $TCP_CONNECTIONS
- Users Log: $USER_LOG
- Network: $IP_MAC
- sudo: $SUDO_CMDS
============================================================
EOF
```

- chmod +x monitoring.sh
#Crontab
- Para fazer com que um programa seja executado a cada 10 minutos, precisamos usar o crontab. No entanto, o crontab opera apenas em intervalos fixos de tempo, como a cada 10 minutos, mas ele inicia nos horários redondos. Por exemplo, se você ligou o computador às 13:55 e deseja que o script seja executado 10 minutos depois, ou seja, às 14:05, o crontab não pode fazer isso diretamente.

- Para agendar o comando para ser executado nos momentos exatos que desejamos, precisamos criar um arquivo adicional. No mesmo diretório em que você criou o monitoring.sh, criaremos um arquivo chamado sleep.sh. Este arquivo calculará o tempo em segundos necessário para esperar até que o comando seja executado exatamente 10 minutos após o início.

```
-> sudo vi sleep.sh
#!/bin/bash

minutes=$(bc <<< $(uptime -s | cut -d ":" -f 2)%10)
seconds=$(uptime -s | cut -d ":" -f 3)
total_seconds=$((minutes * 60 + seconds))

sleep $total_seconds
#echo $minutes
#echo $total_seconds
bash /usr/local/bin/monitoring.sh

-> Salve e saia
-> sudo crontab -e

*/10 * * * * bash /usr/local/bin/sleep.sh
```
Eu altamente recomendo que você estude saiba o que está fazendo. Não se esqueça, aqui é só um guia!

Prontinho. Agora rodará a cada 10 minutos! :) Não se esqueça de medir se realmente está funcionando e comparar o resultado com o pdf.

Eu recomendo fortemente a você pesquisar o que o script está fazendo e para que serve cada comando.


## Política de Senha
```
cd /etc/pam.d/
sudo vi system-auth
Procure a linha:
password    requisite     pam_pwquality.so
Comente ela.
Cole essa linha:
password    requisite                                    pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type= minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 difok=3 reject_username enforce_for_root
e embaixo dela, coloque:
password    sufficient                                   pam_unix.so remember=7
Salve o arquivo e saia.
sudo vi password-auth
Faça a mesma coisa.
```
Teste criando um usuário teste e atribua uma senha a ele que não entra na política de uso:


sudo adduser teste
sudo passwd teste
Tente colocar uma senha que não se encaixa na política de senha.
sudo userdel teste


Altere também o arquivo:

sudo vi /etc/login.defs
procure as linhas:
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7

Altere-as colocando:

PASS_MAX_DAYS   30
PASS_MIN_DAYS   2
PASS_WARN_AGE   7
Essas configurações só vão valer para usuários novos, então atualize para os usuários já criado:
sudo chage -M 30 (seu_usuario)
sudo chage -m 2 (seu_usuario)
sudo chage -W 7 (seu_usuario)

sudo chage -M 30 root
sudo chage -m 2 root
sudo chage -W 7 root
```
## Comandos avaliação:

Você consegue acessar a régua de avaliação por [aqui](https://github.com/gemartin99/Born2beroot-Tutorial#9--hoja-de-correcci%C3%B3n-).
```
## Comandos durante a avaliação

- Checar se o serviço firewalld está funcionando:
sudo systemctl status firewalld

- Checar se o SSH está funcionando:
sudo systemctl status sshd

- Checar o sistema operacional escolhido:
sudo cat /etc/os-release

- Checar se o seu usuário está no grupo de sudo e user42:
groups (name_user)

Checar arquivos que foram alterados para configuração de senha
sudo vi /etc/pam.d/password-auth
sudo vi /etc/pam.d/system-auth
sudo vi /etc/login.defs
Também o comando chage -l (nome_usuario).

- Criar um usuário e atribuir senha à ele:
sudo adduser (nome)
sudo passwd (nome)

- Criar, mover e checar esse usuário a um novo grupo:
sudo groupadd evaluating
sudo usermod -aG evaluating (nome_user)
groups (usuario)

- Checar se o usuário está com login da intra seguido de 42:
hostname

- Mudar nome hostname:
sudo hostnamectl set-hostname (nome)
reboot

- Ver as partições:
lsblk

- Checar arquivo alterado no sudo:
sudo visudo

- Mandar o novo usuario criado pro grupo sudo:
sudo usermod -aG wheel (nome)

- Histórico de configuração sudo:
sudo cat /var/log/sudo/sudo.log

Checar regras ativas: 
sudo firewall-cmd --list-all

Criar e remover uma porta no firewall:
sudo firewall-cmd --add-port=(numero)/tcp --permanent
sudo firewall-cmd --reload

sudo firewall-cmd --remove-port=(numero)/tcp --permanent

- Checar se está aberta a porta 4242 no SSH:
sudo vi /etc/ssh/sshd_config ou sudo systemctl status sshd

- Conectar via SSH
hostname -I

Abre um terminal
ssh (nome_usuario)@(ip do hostname -I) -p 4242

- Checar script, sleep e cron
cd /usr/local/bin
sudo vi monitoring.sh
sudo vi sleep.sh
sudo crontab -e
