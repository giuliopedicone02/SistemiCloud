### VARIABILI DA CONFIGURARE (vedi sezioni ##)          ###
### ATTENZIONE, in "V=DEF" NO SPAZI PRIMA E DOPO "="    ###


## Definizioni per cluster dei nodi kubernetes

KHOSTS_NETWORK=192.168.45.0/24

# nomi con cui sono noti in k8s gli host del cluster e loro IP nel cluster k8s
#KHOSTS[s7]=192.168.45.67
#KHOSTS[s8]=192.168.45.68
KHOSTS[s9]=192.168.45.69
KHOSTS[s10]=192.168.45.70
KHOSTS[s11]=192.168.45.71
#KHOSTS[s12]=192.168.45.72

# i nomi possono essere quelli ufficiali degli host del
# cluster o possono essere inventati e introdotti qui
#KHOSTS[m0]=192.168.45.69
#KHOSTS[w1]=192.168.45.70
#KHOSTS[w2]=192.168.45.71

# se gli IP degli host nel cluster sono diversi dagli IP per raggiungerli dall'esterno,
# come per istanze cloud o VM, questi IP di accesso esterno sono in xhosts.conf


## Definizioni rete dei Pod e dei servizi

POD_NETWORK_CIDR="10.10.0.0/16"
# blocco di IP allocato per la rete dei Pod

SERVICE_CIDR="172.96.0.0/16"
# blocco CIDR allocato per gli IP "virtuali" dei servizi


## Quale container engine usa il cluster?
CONTAINER_RUNTIME=containerd
#CONTAINER_RUNTIME=crio


#KUSER=gp
KUSER=ubuntu
# si presume che su ognuno degli host del cluster vi sia l'utente $KUSER,
# con home directory con lo stesso nome, che utilizzera` k8s e che,
# $KUSER di ciascun host abbia accesso ssh con chiave (gia' presente) agli altri host

## $KEYFILE sul cliente deve consentire accesso ssh da cliente agli host (v. upload_scripts.sh)

#KEYFILE=$HOME/.ssh/id_rsa
#KEYFILE=another_key_file

# se la variabile d'ambiente KEYFILE non e' definita in questo script, set_vars.sh definisce:
#KEYFILE=xhosts_key.pem
#se xhosts.conf non e` vuoto, oppure, se e' vuoto, set_vars.sh definisce:
#KEYFILE=/home/$KUSER/.ssh/id_rsa

# ma mi sono convinto che sia meglio definire esplicitamente qui
KEYFILE=xhosts_key.pem
# e rigenerarlo spesso (per la security), con (senza passphrase e con commento "k8s"):
# ssh-keygen -P "" -C "k8s"" -f xhosts_key.pem


### FINE VARIABILI DA CONFIGURARE                   ###
