#!/usr/bin/env bash

# v. https://docs.aws.amazon.com/vpc/latest/userguide/vpc-subnets-commands-example.html
# ma piu` sofisticato

# Termina gracefully se invocata come script anziche' sourcing ($0==-bash per bash primaria)
# man bash: a login shell is one whose first character of argument zero is a -, or 
#           one started with the --login option


if [[ $0 != "-bash" && $0 != "bash" ]]  ; then
   . ../colors.sh
   echo -e "${RED}You ran this script $(basename $0) ($0), "
   echo -e "but should have sourced it by running:${NC}"
   echo -e "${IT}\t. $(basename $0)${NC}"
   echo -e "${RED}in order to define its functions${NC}"
   exit
fi

AWS_VERS=$(aws --version 2> /dev/null | tr '/.' '\t' | cut -f2)
[ ${AWS_VERS:-1} = 2 ] || { echo "Install AWS CLI version 2" ; return; }

# Quando si cercava di eseguirle questo script sia in sourcing che come 
# script eseguibile, occorreva un accorgimento per uscire dal sourcing senza exit 
# e si poteva sfruttare il comando BACK2BASH sotto 
# In realtà, però, questo accade in pochi casi, visto che questo script e' ora
# organizzato in funzioni, dalle quali si esce con return, ma per tornare al 
# chiamante (codice di livello "main")

BACK2BASH="{ [[ $0 == "-bash" || $0 == "bash" ]] && return -1 || exit;  }"
RETVAL=0

_set_verb_strings() {
   if [[ "x$1" == "x-v" ]] ; then
      SEP="\t"
      VERB_INDENT="\t${IT}"
      VERB_BREAK="${NC}\n"
   else
      SEP=""
      VERB_INDENT=""
      VERB_BREAK=" "
   fi
}
_verb_indent() {
   echo -ne "${VERB_INDENT}"
}

_verbose() {
   local cmd
   cmd="$2"
   [[ "x$1" == "x-v" ]] && echo -e "${GREEN}${cmd}${NC}"
   _verb_indent $1
}

_get_key_pair() {
   local cmd
   cmd="aws ec2 describe-key-pairs --filters Name=key-name,Values=$KEYNAME --query KeyPairs[0].KeyPairId --output text"
   _verb_indent $1
## debug
#  echo $cmd
#  eval $cmd
## end debug
   KEYPAIRID=$(eval $cmd) && 
      {
         echo -e "found ssh key pair $KEYPAIRID, set${VERB_BREAK}KEYPAIRID=$KEYPAIRID";
      } ||
      {
         echo -e "${BOLDRED}Failed to determine key pair Id KEYPAIRID$NC"
         { ${BACK2BASH}; }
      }
## debug
#  echo $KEYPAIRID
## end debug

   if [[ "x$KEYPAIRID" == "x" || $KEYPAIRID == None ]]; then
      cmd ="aws ec2 import-key-pair --key-name $KEYNAME \
            --public-key-material fileb://../$KEYFILE.pub \
            --query 'KeyPairId' --output text"
      _verbose $1 "$cmd"
      KEYPAIRID=$(eval $cmd) && echo -e "created key pair $KEYPAIRID, set${VERB_BREAK}KEYPAIRID=$KEYPAIRID" || {
         echo -e "${BOLDRED}Failed to create key pair$NC"
         { ${BACK2BASH}; }
      }
   fi
}

_get_sg() {
   SGID_OUT=$(aws ec2 describe-security-groups --filters \
      Name=tag-value,Values=kcluster Name=tag-value,Values=kcluster-sg \
      --output text) ||
      {
         echo -e "${BOLDRED}Failed to determine security group$NC"
         { ${BACK2BASH}; }
      }

   SGID=$(echo "$SGID_OUT" | grep SECURITYGROUPS | cut -f3)
   [[ "x$SGID" != "x" ]] && echo -ne "found security group $SGID, set SGID=${SGID}\n"
   echo -e "\t${IT}this host has IP ${RIT}$MYPUBIP${NC}"

   if [[ "x$SGID" == "x" || $SGID == None ]]; then
      local cmd
      cmd="aws ec2 create-security-group --group-name kcluster-access-sg\
 --description \"Security group for an AWS k8s-oriented instance cluster\"\
 --vpc-id ${VPCID}\
 --tag-specifications 'ResourceType=security-group,Tags=[{Key=esperimento,Value=kcluster},{Key=Name,Value=kcluster-sg}]'\
 --query 'GroupId' --output text"
      _verbose $1 "$cmd"
      SGID=$(eval $cmd) || {
         echo -e "${BOLDRED}Failed to create security group$NC"
         { ${BACK2BASH}; }
      }

      echo -e "created security group $SGID, set SGID=$SGID$NC"

      cmd="aws ec2 authorize-security-group-ingress --group-id ${SGID} --protocol all --cidr $KHOSTS_NETWORK"
      _verbose $1 "$cmd"
      eval $cmd >/dev/null &&
         echo -e "${SEP}opened $SGID for all protocols from nodes in $KHOSTS_NETWORK$NC" ||
         echo -e "${BOLDRED}Failed to open security group $SGID for all protocols from nodes in $KHOSTS_NETWORK"

      cmd="aws ec2 authorize-security-group-ingress --group-id ${SGID} --protocol all --cidr $POD_NETWORK_CIDR"
      _verbose $1 "$cmd"
      eval $cmd >/dev/null &&
         echo -e "${SEP}opened $SGID for all protocols from nodes in $POD_NETWORK_CIDR$NC" ||
         echo -e "${BOLDRED}Failed to open security group $SGID for all protocols from nodes in $POD_NETWORK_CIDR$NC"

      for port in 22 6443 80 443 ; do
      # ports 80 443 are for typical web/echo servers, you may add other ports; must specify also FromPort
      cmd="aws ec2 authorize-security-group-ingress --group-id ${SGID}\
 --ip-permissions IpProtocol=tcp,FromPort=$port,ToPort=$port,IpRanges=[{CidrIp=$MYPUBIP/32},{CidrIp=$EC2_CONNECT_CIDR},{CidrIp=$KHOSTS_NETWORK}]"
      _verbose $1 "$cmd"
      eval $cmd >/dev/null &&
         echo -e "${SEP}opened $SGID, port $port, to:\n\
               this host ($MYPUBIP), regional AWS EC2 ($EC2_CONNECT_CIDR) and $KHOSTS_NETWORK$NC" ||
         echo -e "${BOLDRED}Failed to open security group $SGID, port $port, to $KHOSTS_NETWORK or $MYPUBIP or $EC2_CONNECT_CIDR$NC"
      done

      cmd="aws ec2 authorize-security-group-ingress --group-id ${SGID}\
 --ip-permissions IpProtocol=icmp,FromPort=-1,ToPort=-1,IpRanges=[{CidrIp=$MYPUBIP/32},{CidrIp=$EC2_CONNECT_CIDR},{CidrIp=$KHOSTS_NETWORK}]"
      _verbose $1 "$cmd"
      eval $cmd >/dev/null &&
         echo -e "${SEP}opened $SGID to ping (icmp) from\n\
               this host ($MYPUBIP), regional AWS EC2 ($EC2_CONNECT_CIDR) and $KHOSTS_NETWORK$NC" ||
         echo -e "${BOLDRED}Failed to open security group $SGID for icmp to $KHOSTS_NETWORK or $MYPUBIP or $EC2_CONNECT_CIDR$NC"

      cmd="aws ec2 describe-security-groups --filters Name=tag-value,Values=kcluster Name=tag-value,Values=kcluster-sg\
 --output text"
      SGID_OUT=$(eval $cmd)
   else
      echo -e "\tsecurity group is open to: "
      echo "$SGID_OUT" | grep '^IP' | sed -e 's/^IPP/\tIPP/' -e 's/^IPR/\t   IPR/'
   fi

   echo "$SGID_OUT" | grep -q -E -e "^IPRANGES[[:blank:]]$MYPUBIP" ||
      echo -e "${BOLDRED}Warning:$NC  Security group $SGID is not open to your IP ${RED}${MYPUBIP}${NC}\n\
A possible reason is you created the s.g. when your client was on another network.${NC}\n\
${BOLDRED}Solution${NC}: delete this security group and run function ${IT}aws_get_net [-v]${NC} again$NC"

   echo "$SGID_OUT" | grep -q -E -e "^IPRANGES[[:blank:]]$KHOSTS_NETWORK" ||
      echo -e "${BOLDRED}Warning:$NC Security group $SGID is not open to host cluster $RED$KHOSTS_NETWORK$NC"

   echo "$SGID_OUT" | grep -q -E -e "^IPRANGES[[:blank:]]$EC2_CONNECT_CIDR" ||
      echo -e "${BOLDRED}Warning:$NC Security group $SGID is not open to AWS EC2 connect service $RED$EC2_CONNECT_CIDR$NC"
}

_get_vpc() {
   local cmd
   VPCID=$(
      aws ec2 describe-vpcs --filters Name=tag-value,Values=kcluster \
         --query 'Vpcs[*].VpcId' --output text
   )
   if [[ "x$VPCID" != "x" ]]; then
      echo -e "found vpc $VPCID, set VPCID=$VPCID"
   else
      cmd="aws ec2 create-vpc --cidr-block ${KHOSTS_NETWORK}\
 --tag-specifications 'ResourceType=vpc,Tags=[{Key=esperimento,Value=kcluster},{Key=Name,Value=kcluster-vpc}]'\
 --query 'Vpc.VpcId' --output text"
      _verbose $1 "$cmd"
      VPCID=$(eval $cmd) && echo -e "created vpc $VPCID, set VPCID=$VPCID$NC" || {
         echo -e "${BOLDRED}Failed to create VPC$NC"
         { ${BACK2BASH}; }
      }
   fi
}

_get_subnet() {
   # nel determinare SUBNETID si usano 3 filtri (in AND per default), in effetti ne basterebbe uno...
   # qui si adotta la programmazione difensiva;
   # il filtro Name=tag-value,Values=kcluster Name=tag-value,Values=kcluster-subnet significa:
   # trova un tag di "Key" qualunque (di fatto "esperimento") e "Value" kcluster e
   # un tag di "Key" qualunque (di fatto "Name") e "Value" kcluster-subnet
   local cmd
   _verb_indent $1
   SUBNETID=$(
      aws ec2 describe-subnets --filters Name="vpc-id",Values="$VPCID" \
         Name=tag-value,Values=kcluster Name=tag-value,Values=kcluster-subnet \
         --query 'Subnets[0].SubnetId' --output text
   ) && echo -e "found subnet $SUBNETID, set SUBNETID=$SUBNETID$NC" || {
      echo -e "${BOLDRED}Failed to determine subnet$NC"
      { ${BACK2BASH}; }
   }

   if [[ "x$SUBNETID" == "x" || $SUBNETID == None ]]; then
      cmd="aws ec2 create-subnet --vpc-id $VPCID --cidr-block ${KHOSTS_NETWORK}\
 --tag-specifications 'ResourceType=subnet,Tags=[{Key=esperimento,Value=kcluster},{Key=Name,Value=kcluster-subnet}]'\
 --query 'Subnet.SubnetId' --output text"
      _verbose $1 "$cmd"
      SUBNETID=$(eval $cmd) && echo -e "created $SUBNETID, set SUBNETID=$SUBNETID$NC" || {
         echo -e "${BOLDRED}Failed to create subnet$NC"
         { ${BACK2BASH}; }
      }
      cmd="aws ec2 modify-subnet-attribute --subnet-id $SUBNETID --map-public-ip-on-launch"
      _verbose $1 "$cmd"
      eval $cmd >/dev/null ||
         {
            echo failed to modify subnet attribute map-public-ip-on-launch
            { ${BACK2BASH}; }
         }
   fi
}

_get_igw() {
   # nel determinare IGID si usano 3 filtri (in AND per default), in effetti basterebbe vpc-id...
   # qui si adotta la programmazione difensiva;
   local cmd
   _verb_indent $1
   IGID=$(
      aws ec2 describe-internet-gateways --filters Name="attachment.vpc-id",Values="$VPCID" \
         Name=tag-value,Values=kcluster Name=tag-value,Values=kcluster-igw \
         --query 'InternetGateways[0].InternetGatewayId' --output text
   ) &&  echo -e "found internet gateway $IGID, set IGID=$IGID$NC" ||
      {
         echo -e "${BOLDRED}Failed to determine Internet gateway Id IGID$NC"
         { ${BACK2BASH}; }
      }

   if [[ "x$IGID" == "x" || $IGID == None ]]; then
      cmd="aws ec2 create-internet-gateway \
            --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=esperimento,Value=kcluster},{Key=Name,Value=kcluster-igw}]' \
            --query 'InternetGateway.InternetGatewayId' --output text"
      _verbose $1 "$cmd"
      IGID=$(eval $cmd) \
      && echo -e "created Internet gateway $IGID, set IGID=$IGID$NC" || {
         echo -e "${BOLDRED}Failed to create Internet gateway$NC"
         { ${BACK2BASH}; }
      }
# a new internet gateway is not attached to any VPC
      cmd="aws ec2 attach-internet-gateway --internet-gateway-id $IGID --vpc-id $VPCID"
      _verbose $1 "$cmd"
      eval $cmd >/dev/null &&
         echo -e "attached Internet gateway $IGID to $VPCID$NC" ||
         {
            echo -e "${BOLDRED}Failed to attach Internet gateway $IGID to $VPCID$NC"
            { ${BACK2BASH}; }
         }
   fi
}

_clean_unassoc_rt() {
   local krt_out_1
   local cmd
   echo cleaning unassociated RTs/subnets
   krt_out_1=$(
      aws ec2 describe-route-tables --filters Name="vpc-id",Values="$VPCID" \
         Name=tag-value,Values=kcluster Name=tag-value,Values=kcluster-rt \
         --query 'RouteTables[?Associations==`[]`].RouteTableId' --output text
      #  --query 'RouteTables[].[Associations[].[RouteTableAssociationId,RouteTableId],
      #                          Routes[].DestinationCidrBlock,Routes[].GatewayId] | [0]' \
   ) || {
      echo "Failed in determining unassociated Route tables"
      { ${BACK2BASH}; }
   }

   if [[ -n $krt_out_1 ]]; then
      for rt in $krt_out_1; do
         echo -e "found route table $rt non associated to $SUBNETID, deleting both"
         cmd="aws ec2 delete-route-table --route-table-id $rt"
         echo $cmd
         eval $cmd
         cmd="aws ec2 delete-subnet --subnet-id $SUBNETID"
         echo $cmd
         eval $cmd
      done
      echo -e "relaunch this script ${BASH_SOURCE[0]}"
      echo -e "if deleting $RTID or $SUBNETID failed, maybe instances must be deleted (or their networking fixed by hand)"
      return
   fi
}

_get_rt() {
   # Ora occorre una Route Table per la subnet creata, la main r.t. (di default) NON ha rotta
   #    per esterno, quindi:
   #    o si aggiunge tale rotta alla main r.t. di $VPCID:
   #        aws ec2 replace-route-table-association --association-id $MAINRT_ASSOC_ID --route-table-id $RTID
   #    o si crea RT con i tag ad hoc (faremo questo)

   # ci sono tre casi possibili qui, per le RT di VPCID
   # 1. esistono RT con tag, senza associazioni: non dovrebbe capitare, ma le cancelliamo, v.
   #    _clean_unassoc_rt, e usciamo e diciamo di riprovare
   # 2. non esiste RT con tag: va creata, dotata di rotta e associata e si prosegue
   # 3. escluso (1), esiste una RT con tag e associazione con subnet (quindi non main), si procede
   #    (dovremmo verificare che abbia la rotta di default, ma lo ignoriamo)

   # caso (1), per ora lo ignoriamo, vedi _rt_case_1

   # casi 2 e 3 per route table

   local krt_out
   local cmd
   krt_out=$(
      aws ec2 describe-route-tables --filters Name="vpc-id",Values="$VPCID" \
         Name=tag-value,Values=kcluster Name=tag-value,Values=kcluster-rt \
         Name="association.subnet-id",Values="$SUBNETID" --output text
   ) || {
      echo "Failed in determining associated Route tables"
      { ${BACK2BASH}; }
   }

   RTID=$(echo "$krt_out" | head -1 | cut -f3)
   [[ "x$RTID" != "x" ]]  && echo -e "found route table $RTID , set RTID=$RTID"

   if [[ "x$RTID" == "x" || $RTID == None ]]; then
      # caso 2: crea RT con route di default e associala
      cmd="aws ec2 create-route-table --vpc-id ${VPCID}\
 --tag-specifications 'ResourceType=route-table,Tags=[{Key=esperimento,Value=kcluster},{Key=Name,Value=kcluster-rt}]'\
 --query 'RouteTable.RouteTableId' --output text"
      _verbose $1 "$cmd"
      RTID=$(eval $cmd) && echo -e "created route table $RTID, set RTID=$RTID$NC" ||
         {
            echo -e "${BOLDRED}Failed to create route table$NC"
            { ${BACK2BASH}; }
         }
      cmd="aws ec2 create-route --route-table-id $RTID --destination-cidr-block 0.0.0.0/0 --gateway-id $IGID"
      _verbose $1 "$cmd"
      eval $cmd >/dev/null &&
         echo -e "created default (0.0.0.0/0) route to gateway $IGID for table $RTID$NC" ||
         {
            echo -e "failed to create route to gateway $IGID for table $RTID$NC"
            { ${BACK2BASH}; }
         }
      cmd="aws ec2 associate-route-table --route-table-id $RTID --subnet-id $SUBNETID"
      _verbose $1 "$cmd"
      eval $cmd >/dev/null &&
         echo -e "associated route-table $RTID to $SUBNETID$NC" ||
         {
            echo -e "failed to associate route table $RTID to subnet ${SUBNETID}$NC"
            _clean_unassoc_rt
            { ${BACK2BASH}; }
         }
   else
      # caso 3: dovrebbe esserci già una RT adatta
      echo -ne "\tassociation: "
      echo "$krt_out" | grep "ASSOCIATIONS[^T]" | cut -f4,5
      echo "$krt_out" | grep ROUTES | cut -f1-3 | sed 's/ROUTES/\troute:/'
   fi

   # Checking association RT/SUBNET... useless

   #RT_SUBNET_ASSOC=$(aws ec2 describe-route-tables --filters Name="route-table-id",Values="$RTID" \
   #   Name="association.route-table-id",Values="$RTID" Name="association.subnet-id",Values="$SUBNETID" \
   #   --query 'RouteTables[].Associations[?SubnetId==`'$SUBNETID'`]' --output text)
   #[[ $RT_SUBNET_ASSOC ]] && echo -e "      $RTID associated to $SUBNETID" || \
   #   {
   #      echo -e "      $RTID ${RED}not associated to$NC $SUBNETID";
   #      echo -e "      try: aws ec2 delete-subnet --subnet-id $SUBNETID";
   #      { ${BACK2BASH}; };
   #   }

   # Following for main Route Table... Don't actually need it

   #MAINRT_OUT=$(aws ec2 describe-route-tables --filters Name="vpc-id",Values="$VPCID" Name="association.main",Values="true" \
   #   --query 'RouteTables[].[Associations[].[RouteTableAssociationId,RouteTableId] | [0],
   #                           Routes[].DestinationCidrBlock,Routes[].GatewayId] | [0]'    --output text \
   ##  --query 'RouteTables[].Associations[].[RouteTableAssociationId,RouteTableId]' --output text
   ##  --query 'RouteTables[?Associations[?Main]].Associations[].[RouteTableAssociationId,RouteTableId]' --output text \
   #)
   #MAINRT_ID=$(echo "$MAINRT_OUT" | head -1 | cut -f2)
   #MAINRT_ASSOC_ID=$(echo "$MAINRT_OUT" | head -1 | cut -f1)
   #echo -e " main route table $MAINRT_ID , associated to $VPCID with $MAINRT_ASSOC_ID"
   #NROUTES=$(echo "$MAINRT_OUT" | tail -n +3 | wc -w)
   #echo -n "      routes: "
   #for n in $(seq 1 $NROUTES) ; do
   #MAINRT_ROUTE_n=$(echo "$MAINRT_OUT" | tail -n +2 | cut -f $n | tr '\n' ' ' | sed -e 's/ / via /' )
   #echo -ne $MAINRT_ROUTE_n ", "
   #done
   #echo
}

aws_get_net() {
   unset VPCID RTIDS SUBNETIDS SGIDS IGIDS INSTIDS RTIDS1 SUBNETIDS1 SGIDS1 IGIDS1
   unset KEYNAME KEYABSFILE REGION RT_SUBNET_ASSOC RUN_NODES krt_out
   _set_verb_strings $1
   # Fingerprinting a private/public key without AWS CLI
   #ssh-keygen -ef xhosts_key.pem -m PEM | openssl rsa -RSAPublicKey_in -outform DER 2> /dev/null | openssl md5 -c | tr -d ' ' | cut -d '=' -f2
   #ssh-keygen -f xhosts_key.pem.pub -e -m PKCS8 | openssl pkey -pubin -outform DER | openssl md5 -c | tr -d ' ' |  cut -d '=' -f2
   if [[ ! -f ../$KEYFILE ]]; then
      echo -e "${BOLDRED}file della chiave privata${BIT} $KEYFILE $NC${BOLDRED}non presente in$BIT $(dirname ${PWD})${NC}" >/dev/stderr
      echo -e "${BOLDRED}you should call function${BIT} $FUNCNAME $NC${BOLDRED}from directory${BIT} ${K8SDIR}/aws${NC}" >/dev/stderr
      echo -e "${BOLDRED}also, check${BIT} KEYFILE $NC${BOLDRED}in$BIT ${K8SDIR}/config.sh${NC}" >/dev/stderr
      echo -e "${BOLDRED}and from${BIT} ${K8SDIR}/aws ${NC}${BOLDRED}re-source script :${BIT} ${BASH_SOURCE[0]}$NC" >/dev/stderr
      { ${BACK2BASH}; }
   else
      KEYNAME=$(basename $KEYFILE .pem)
      KEYABSFILE=$(dirname $PWD)/$KEYFILE
      _verb_indent $1
      echo -e "file della chiave AWS: $BOLD$IT$KEYABSFILE$NC"
   fi
   _verb_indent $1
   echo -e "Determining/setting cluster parameters$NC"

   REGION=$(aws configure get region)
   EC2_CONNECT_CIDR=$(curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | \
      grep -B2 EC2_INSTANCE_CONNECT | grep -C1 $REGION | grep ip_prefix | tr -cd '0-9./')
   _verb_indent $1
   echo -e "Current region is: $BOLD$IT$REGION$NC"

   _get_key_pair $1 ; [[ $? != 0 ]] && return -1
   _get_vpc $1 ; [[ $? != 0 ]] && return -1
   _get_subnet $1 ; [[ $? != 0 ]] && return -1
   _get_igw $1 ; [[ $? != 0 ]] && return -1
   _get_rt $1 ; [[ $? != 0 ]] && return -1
   _get_sg $1 ; [[ $? != 0 ]] && return -1

   echo -ne "\n${RED}Using:\tVPC$NC $VPCID${RED}, subnet $NC$SUBNETID${RED} \n"
   echo -e "\tsecurity group $NC$SGID${RED}, route table $NC$RTID${RED} \n\tinternet gateway $NC$IGID"

   echo -e "\n${RED}You have re-read AWS environment vars$NC"
   echo -e   "${RED}To reload/list AWS related functions, source the ${BASH_SOURCE[0]} script with ${BOLDGREEN}${IT}. ${BASH_SOURCE[0]}$NC"
}

aws_del_net() {
   [[ x$SUBNETID != x ]] && { aws ec2 delete-subnet --subnet-id $SUBNETID ; echo -e "deleted $SUBNETID" ; unset SUBNETID; }
   [[ x$SGID != x ]] && { aws ec2 delete-security-group --group-id $SGID  ; echo -e "deleted $SGID" ; unset SGID; }
   [[ x$IGID != x ]] &&
   {
      [[ x$VPCID != x ]] && aws ec2 detach-internet-gateway --internet-gateway-id $IGID --vpc-id $VPCID
      aws ec2 delete-internet-gateway --internet-gateway-id $IGID && { echo -e "deleted $IGID" ; unset IGID; }
   }
   [[ x$RTID != x ]] && { aws ec2 delete-route-table --route-table-id $RTID ; echo -e "deleted $RTID" ; unset RTID; }
   [[ x$VPCID != x ]] && { aws ec2 delete-vpc --vpc-id  $VPCID ; echo -e "deleted $VPCID" ; unset VPCID; }
}

aws_read_nodes() {
   if [[ $PWD != $AWSSETUPDIR ]] ; then
      echo -e "${BOLDRED}must run from $AWSSETUPDIR$NC" > /dev/stderr
      return 1
   fi
   >xhosts.tsv
   for N in $NODES; do
      aws ec2 describe-instances \
         --filters Name=tag-value,Values=$N \
         --query 'Reservations[].Instances[?State.Name==`running`].[(Tags[?Value==`'$N'`].Value)[0],PrivateIpAddress,PublicIpAddress,InstanceId] | [] ' \
         --output text | tee -a xhosts.tsv
   done
   awk '{print "XHOSTS[" $1 "]=" $3 }' xhosts.tsv > ../xhosts.conf
   XHOSTS=()
   . ../xhosts.conf
   if [[ ${#XHOSTS[@]} -ne ${#KHOSTS[@]} ]] ; then
      for N in ${!KHOSTS[@]} ; do
         if [[ ! ${XHOSTS[$N]} ]] ; then
            echo -e "${BOLDRED}instance ${BIT}${N}${NC}${BOLDRED} not running (yet?)$NC"
         fi
      done
      return
   fi
   echo rebuilt XHOSTS: ${XHOSTS[@]}
}

aws_create_nodes() {
   local failed
   local inst_ids
   local inst_id
   local cmd
   for N in $NODES; do
      IP_N=${KHOSTS[$N]}
      cmd="aws ec2 run-instances\
 --image-id ami-09e67e426f25ce0d7\
 --instance-type t2.medium\
 --key-name ${KEYNAME}\
 --tag-specifications 'ResourceType=instance,Tags=[{Key=esperimento,Value=kcluster},{Key=Name,Value='$N'}]'\
 --subnet-id ${SUBNETID}\
 --security-group-ids ${SGID}\
 --private-ip-address ${IP_N}\
 --user-data file://aws_1st_boot.sh\
 --query Instances[0].InstanceId"
# Following always prints command :-)
      [[ "x$1" == "x-v" ]] && echo $cmd || echo $cmd
      inst_id="$(eval $cmd)" || \
      {
         DESCRINSTOUT=$(aws ec2 describe-instances --filters Name=tag-value,Values=kcluster \
            Name=tag-value,Values=$N Name=private-ip-address,Values=$IP_N \
            Name=instance-state-name,Values=running \
         --query Reservations[0].Instances[0].InstanceId --output=text)
         [[ $DESCRINSTOUT != None ]] && \
            echo -e "$DESCRINSTOUT running with name $N, private IP $IP_N" || \
            {
               echo -ne "${BOLDRED}instance creation for node $N (IP ${IP_N}) failed$NC\n" ;
               echo -e  "${RED}... perhaps you should terminate any running instance first \nand/or just retry ${NC}${IT}create_nodes${NC}${RED} as soon as$NC"
               echo -e  "${IT}find_instances${NC}${RED} prints out no, or terminating-only, instances$NC"
               return ;
            }
      }
      inst_ids="$inst_ids $inst_id"
   done
   local cmd
   cmd="aws ec2 wait instance-running --instance-ids $inst_ids"
   [[ "x$1" == "x-v" ]] && echo $cmd
   eval $cmd
# Polling is unnecessary, thanks to previous "aws ec2 wait"
   echo -e "\n-----------------Polling nodes--------------------"
   aws_read_nodes
   until [[ ${#XHOSTS[@]} -eq ${#KHOSTS[@]} ]] ; do
      sleep 2
      aws_read_nodes
   done
}

aws_find_instances() {
   for N in $NODES; do
      aws ec2 describe-instances \
         --filters Name=tag-value,Values=$N \
         --query 'Reservations[].Instances[?State.Name!=`terminated`].[(Tags[?Value==`'$N'`].Value)[0],PrivateIpAddress,PublicIpAddress,InstanceId,State.Name] | [] ' \
         --output text
   done
}

kssh() {
   [[ ${#XHOSTS[@]} != ${#KHOSTS[@]} ]] && aws_read_nodes
   local host=${XHOSTS[$1]}
   shift
   ssh -o StrictHostKeyChecking=no -i $KEYABSFILE $KUSER@$host $*
}
complete -F _ssh kssh

kscp() {
   local scp_params
   if [[ ${#XHOSTS[@]} == 0 || ! -f $AWSSETUPDIR/xhosts.tsv ]]; then
      echo -e "${BOLDRED}run prep_nodes first$NC" > /dev/stderr
      return
   fi
   scp_params=" $(echo $*)"
   for N in $NODES; do
      scp_params=${scp_params/ ${N}:/ ${XHOSTS[$N]}:}
   done
   scp -o StrictHostKeyChecking=no -i $KEYABSFILE -o User=$KUSER $scp_params
}
complete -o nospace -F _scp kscp

aws_prep_nodes() {
   aws_read_nodes
   if [[ $? == 1 ]] ; then
      return
   fi
   RUN_NODES0=$(cut -f 1 xhosts.tsv | tr '\n' ' ' | sed -e 's/^ //' -e 's/ $//')
   RUN_NODES=$(echo $RUN_NODES0 | xargs -n1 | sort -V | xargs)
   echo -e "Nodes on AWS EC2: $RUN_NODES"
   echo -e "Nodes declared in config.sh: $NODES"
   if [[ $RUN_NODES != $NODES ]]; then
      echo -e "only $RUN_NODES are running, wait for all $NODES to be running"
      return
   fi
   for N in $NODES; do
      echo -e "\npreparing $N (IP: ${XHOSTS[$N]})"
      if [[ ! ${XHOSTS[$N]} ]]; then
         echo -e "node $N has no IP, failing" >/dev/stderr
         return
      fi
      scp -i $KEYABSFILE $KEYABSFILE $KUSER@${XHOSTS[$N]}:~/.ssh/id_rsa &&
         echo -e "${RED}you can now run:  ${NC}${IT}kssh $N${NC}  ${RED}or${NC}  ${IT}kscp $N${NC}" ||
         echo -e "${RED}node $N (${XHOSTS[$N]}) ${BOLDRED} unreachable! \n\
(You may re-try running this ${FUNCNAME[0]} function once or twice before giving up)${NC} \n\
${BOLDRED}In case of problems, check the security group allows instance to be reached$NC"
   done
   echo -ne "${RED}to send k8s scripts to AWS cluster nodes:$NC "
   echo -e "${IT}cd .. ; ./upload_scripts.sh$NC"
}

echo -e "\n${RED}This script helps to manage and create an AWS cluster and prepare it to run k8s\n${NC}"
echo -e "sourcing config.sh"
IN_XHOST_SETUP=1
unset KUSER
cd ..
. ./set_vars.sh >/dev/null
cd - > /dev/null

if [[ $KUSER != ubuntu ]] ; then
   echo -e "${BOLDRED}you should perhaps set KUSER to ubuntu in ../config.sh${NC} " > /dev/stderr
   return
fi

AWSSETUPDIR=$PWD
K8SDIR=$(dirname $PWD)

echo -e "\n${RED}Environment vars for your AWS resources:$NC"

if [[ "x$VPCID" != "x" ]] ; then
aws ec2 describe-vpcs --vpc-ids $VPCID >& /dev/null || unset VPCID
fi
echo "VPCID=\"$VPCID\"         (vpc)"

if [[ "x$SUBNETID" != "x" ]] ; then
aws ec2 describe-subnets --subnet-ids $SUBNETID >& /dev/null || unset SUBNETID
echo "SUBNETID=\"$SUBNETID\"   (subnet)"
else
echo "SUBNETID=\"$SUBNETID\"      (subnet)"
fi

if [[ "x$IGID" != "x" ]] ; then
aws ec2 describe-internet-gateways --internet-gateway-ids >& /dev/null $IGID || unset IGID
fi
echo "IGID=\"$IGID\"          (internet gateway)"

if [[ "x$RTID" != "x" ]] ; then
aws ec2 describe-route-tables --route-table-ids $RTID >& /dev/null || unset RTID
fi
echo "RTID=\"$RTID\"          (route table)"

if [[ "x$SGID" != "x" ]] ; then
aws ec2 describe-security-groups --group-ids $SGID >& /dev/null || unset SGID
echo "SGID=\"$SGID\"           (security group)"
else
echo "SGID=\"$SGID\"          (security group)"
fi

if [[ "x$KEYPAIRID" != "x" ]] ; then
aws ec2 describe-key-pairs --key-pair-ids $KEYPAIRID >& /dev/null || unset KEYPARID
fi
echo "KEYPARID=\"$KEYPAIRID\"      (key pair)"

if [[ x$VPCID == x || x$SUBNETID == x || x$IGID == x || x$RTID == x || x$SGID == x || x$KEYPAIRID == x ]] ; then
   echo -ne "\n${BOLDRED}Some variable above is undefined, but the related AWS resource could exist anyway$NC"
   echo -ne "\n${RED}Before launching instances, all needed AWS networking resources ${BOLDRED}must exist${NC}${RED}, "
   echo -ne "\n${RED}\tand the above related environment vars be set$NC "
   echo -ne "\n${RED}To create missing, and re-read existing, AWS networking resources, run:$NC "
   echo -e "${IT}aws_get_net [-v]$NC\n"
   return
fi

unset XHOSTS
declare -A XHOSTS

if [[ (-f ../xhosts.conf) && (-s ../xhosts.conf) ]] ; then
   . ../xhosts.conf
   echo XHOSTS[${!XHOSTS[@]}]=[${XHOSTS[@]}]
   echo -e "${RED}Above XHOSTS may nomore exist (${NC}${IT}find_instances${NC}${RED} to check)${NC}"
else
   echo -n XHOSTS[${!XHOSTS[@]}]=[${XHOSTS[@]}]
   if [[ (-f ../xhosts.conf) ]] ; then
      echo -ne "\n${BOLDRED}Empty  ../xhosts.conf${NC}"
   else
      echo -ne "\n${BOLDRED}No  ../xhosts.conf${NC}"
   fi
   echo -ne "${RED}, you'll probably want to run: ${NC}"
   echo -e "${BOLD}${IT}aws_create_nodes$NC\n"
   echo -ne "${RED}However, ${NC}"
fi

echo -e "${RED}on your nodes (i.e. running AWS instances named $NC$IT${NODES/ /,}$NOIT$RED) you may call:${NC}"
echo -e "\
- ${IT}aws_read_nodes$NC (find running AWS nodes in $IT${NODES/ /,}$NOIT and rebuild ${IT}xhosts${NC})\n\
- ${IT}aws_prep_nodes$NC (to check which nodes in $IT${NODES/ /,}$NOIT are running and prepare calls to ${IT}kssh/kscp$NC)\n\
- ${IT}kssh$NC or ${IT}kscp$NC to a running node in $IT${NODES/ /,}$NOIT "

echo -ne "\n${RED}To find ${BOLD}${IT}any$NC$RED instances in your AWS region (do not reset ${IT}xhosts$NOIT): $NC"
echo -e "${IT}aws_find_instances$NC"
echo -ne "${RED}to re-read AWS related data:$NC                                    "
echo -e "${IT}aws_get_net $NC"
echo -ne "${RED}to create AWS networking resources:$NC                             "
echo -e "${IT}aws_get_net [-v]$NC"
echo -ne "${RED}to delete AWS networking resources (not instances):$NC             "
echo -e "${IT}aws_del_net$NC"
echo -ne "${RED}to check AWS networking resources:$NC                              "
echo -e "$IT./aws_kcluster_info.sh$NC"
echo -ne "${RED}to send k8s scripts to AWS cluster nodes:$NC                       "
echo -e "${IT}cd .. ; ./upload_scripts.sh$NC"
