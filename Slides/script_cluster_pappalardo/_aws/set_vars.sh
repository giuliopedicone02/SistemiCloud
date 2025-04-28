# Includere questo script in altri con "source"
# Per debugging si puo' esgeuire con "source" anche direttamente da bash

# determina non via sourcing di config.sh, ma *calcolandole*, le variabili
##BASENAME|CRI_RUNTIMES|NODES0|NODES|KHOSTIPS0|KHOSTIPS|UNIXNAME|MYIPS|\
##THISNODE|THISIP|THISINDEX|EGREP|FGREP|GREP|SETUPDIR|BASESETUPDIR|\
##LOCALIP|LOCALNETINTFC|MYPUBIP|KHOME
# se se ne definiscono di nuove, conviene aggiungerle all'elenco qui sopra

get_my_vars() {
   grep '^##' ${BASH_SOURCE[0]} | \
   sed -e 's/##//g' -e 's/\\//g' | \
   tr -d '\n'
   echo
}

. colors.sh

BASENAME=$0
if [[ $0 != "-bash" && $0 != "bash" ]] ; then
BASENAME=$(basename $0)
fi

if [[ ("$BASENAME" != "upload_scripts.sh") && ("$BASENAME" != "prova.sh")  &&  ("$BASENAME" != "-bash") && ("$BASENAME" != "bash")  && \
      ( "$0" != ./aws_kcluster_* ) ]] ; then
if [ "$EUID" -ne 0 ] ; then
   echo -e "${BOLDRED}Please run as root$NC (BASENAME==$BASENAME, \$0==$0)" 1>&2 
   exit
fi
fi

if [[ "$BASENAME" == "upload_scripts.sh" || "$BASENAME" == "prova.sh" || "$BASENAME" == "prova" ]] ; then
if [ "$EUID" -eq 0 ] ; then
   echo -e "${BOLDRED}Please do not run as root$NC" 1>&2 
   exit
fi
fi

PROMPT_SRC="${RED}[$(basename ${BASH_SOURCE[0]})"
[[ ${#BASH_SOURCE[@]} == 1 ]] && PROMPT_SRC="$PROMPT_SRC $@"
PROMPT_SRC="$PROMPT_SRC @$(hostname)]${NC}"

# debug
#echo -e $PROMPT_SRC
#echo jumping out of set_vars.sh early
#return
#end debug

if [[ $0 == -bash || $0 == bash ]] ; then
   echo -e "$PROMPT_SRC ${IT}${BASH_SOURCE[0]}${NOIT} sourced" 1>&2
fi

if [[ $OSTYPE == 'darwin'* ]]; then
EGREP="/usr/bin/egrep"
FGREP="/usr/bin/fgrep"
GREP="/usr/bin/grep"
else
EGREP="egrep"
FGREP="fgrep"
GREP="grep"
fi

FIND_VARS_CMD="$EGREP -e '^[A-Za-z][A-Za-z0-9_]*=' ./config.sh | cut -d'=' -f1 | tr '\n' ' '"
CONF_VARS=$(eval $FIND_VARS_CMD)

# clear variables defined in config.sh

unset KHOSTS
declare -A KHOSTS
unset -v $CONF_VARS KEYFILE
CRI_RUNTIMES="containerd crio"

. ./config.sh
echo -ne "\n$PROMPT_SRC Variabili lette in config.sh: "
echo -e $CONF_VARS
echo -n "KEYFILE=" ; test -n "$KEYFILE" && echo $KEYFILE || echo '<NOT SET>'

NODES0="${!KHOSTS[@]}"
NODES=$(echo $NODES0 | xargs -n1 | sort -V | xargs)
# sort -V mette (p. es.) s9 prima di s10
KHOSTIPS0="${KHOSTS[@]}"
KHOSTIPS=$(echo $KHOSTIPS0 | xargs -n1 | sort -V | xargs)

# KNAMES is KHOSTS inverted
unset KNAMES
unset KINDEX
declare -A KNAMES
declare -A KINDEX

build_names_indexes() {
   local i
   i=0
   for N in ${NODES}; do
      IPN=${KHOSTS[$N]}
      KNAMES[$IPN]=$N
      KINDEX[$N]=$i
      let i+=1
   done
}

build_names_indexes

UNIXNAME=$( uname -s )
if [[ "$UNIXNAME" == @(Linux|GNU|GNU/*) ]]; then
MYIPS=$(hostname -I)
elif [[ "$UNIXNAME" =~ "MINGW" ]]; then
MYIPS=$(ipconfig //all | grep -B4 'Default Gateway.*: .' | head -1 | cut -d':' -f2 | tr -dc 0-9.)
else
MYIPS=$(for name in $(/sbin/ifconfig -l) ; do \
   /sbin/ifconfig $name | awk -v name=$name '/inet / {printf "%s ", $2; }'; \
done)
fi

THISNODE=none
THISIP=none
THISINDEX=none
for N in ${NODES}; do
   IPN=${KHOSTS[$N]}
   INDXN=${KINDEX[$N]}
   for A in $MYIPS; do
      if [[ "$IPN" == "$A" ]]; then
         THISNODE=$N
         THISIP=$IPN
         THISINDEX=$INDXN
         break 2
      fi
   done
done

# su ogni host, troviamo l'IP dell'host stesso
#THISIP=$(grep ${THISHOST} /etc/hosts | grep -v 127.0. | cut -f1 -d' ')

SETUPDIR=$(pwd)
BASESETUPDIR=$(basename $SETUPDIR)
if [[ "$UNIXNAME" =~ "MINGW" ]]; then
LOCALIP=$MYIPS
else
LOCALNETINTFC=$(ip route | grep default | cut -d' ' -f5)
LOCALIP=$(ip addr show dev $LOCALNETINTFC | $EGREP '^[[:blank:]]*inet ' | tr -dc '0-9. /' | tr -s ' ' | cut -d' ' -f 2)
LOCALIP=${LOCALIP/\/[0-9]*/}
fi
MYPUBIP=$(curl -s https://ipinfo.io/ip)

echo -ne "\n$PROMPT_SRC "

if [[ "$THISNODE" == "none" ]] ; then
   printf "Questo cliente ($(hostname) - $LOCALIP - $MYPUBIP) non e\` destinato a essere un nodo del cluster composto da:\n[%s]/[%s]\ne definito in ./config.sh\n" "${NODES/ /,}" "${KHOSTIPS/ /,}"
else
   printf "Questo host e\` il nodo %s (IP %s) del cluster definito in $SETUPDIR/config.sh\n" "$THISNODE" "$THISIP"
fi

if [[ $THISNODE != none ]] ; then
   KCOLOR=34
   let KCOLOR+=$THISINDEX
   RED="\033[0;"$KCOLOR"m"
fi

unset KRED
declare -A KRED
for N in ${NODES}; do
   NCOLOR=34
   let NCOLOR+=${KINDEX[$N]}
   KRED[$N]="\033[0;"$NCOLOR"m"
done

if [[ $OSTYPE == 'darwin'* ]]; then
KHOME=/Users/$KUSER
else
KHOME=/home/$KUSER
fi

unset XHOSTIPS
unset XHOSTS
declare -A XHOSTS

if [[ -f xhosts.conf ]] &&  grep -q -e '^XHOSTS\[.*\]=' xhosts.conf ; then
   echo -e "${RED}reading xhosts.conf$NC"
   . xhosts.conf
   for n in $NODES ; do
      XHOSTIPS="$XHOSTIPS ${XHOSTS[$n]}"
   done
   : ${KEYFILE:=xhosts_key.pem}
else
   for n in $NODES ; do
      XHOSTS[$n]=${KHOSTS[$n]}
   done
   : ${KEYFILE:=$KHOME/.ssh/id_rsa}
fi

echo -e "\n$PROMPT_SRC Variabili principali qui determinate:"
echo '$CRI_RUNTIMES
$NODES / $KHOSTIPS / $MYIPS
$THISNODE $THISIP $THISINDEX
$SETUPDIR $BASESETUPDIR $KHOME
$LOCALIP $LOCALNETINTFC $MYPUBIP / $XHOSTIPS'
echo -e "\n$PROMPT_SRC Variabili da ${IT}config.sh$NC:"
echo "KEYFILE=$KEYFILE"
echo "KUSER=$KUSER"

for n in $NODES ; do
   if [[ "x${XHOSTS[$n]}" == x"${KHOSTS[$n]}" ]] ; then
      if [[ "x$KUSER" == "xubuntu" ]] ; then
         echo -e "${BOLDRED}Check if $IT\$KUSER=$KUSER$NOIT is the intended user on host $IT$n$NOIT$NC"
         break
      fi
   fi
done

# Update /etc/hosts file with cluster node entries

update_hosts() {
  sed -i '/# inserted by/d' /etc/hosts
  for N in ${NODES}; do
    HOSTIP=${KHOSTS[$N]//./\\.}
  # NN="[[:space:]]+$N([[:space:]]+|$)"
  # precedente impreciso
    NN=".*$N.*"
    HOSTLINE="^$HOSTIP"
    if ! grep -q -e "$HOSTLINE$NN" /etc/hosts ; then
  # if ! host $N 127.0.0.53 >/dev/null ; then
      printf "%s\t%s\t# inserted by %s\n" ${KHOSTS[$N]} $N $0 >> /etc/hosts
      printf "${RED}%s (${KHOSTS[$N]}) just inserted into /etc/hosts${NC}\n" $N
    else
      printf "${RED}%s (${KHOSTS[$N]}) already in /etc/hosts${NC}\n" $N
  #   printf "${RED}% at lines:${NC}\n"
  #   $EGREP -nT -e "$NN" /etc/hosts
    fi
  done
}

echo -e "\n$PROMPT_SRC finito\n"

# se questo script set_vars.sh e' stato sourced direttamente (come in 
# set_clnt_env.sh) e non dentro un altro script, con il trucco sotto 
# si può eseguire questo script con un argomento nome di
# funzione, p. es. update_hosts (come in set_clnt_env.sh)

[[ ${#BASH_SOURCE[@]} == 1 ]] && "$@"
