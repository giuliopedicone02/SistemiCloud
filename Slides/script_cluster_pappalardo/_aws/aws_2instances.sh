#!/usr/bin/env bash

unset DEFAULT_VPC SUBNET_AZ_ID_PAIRS SUBNET_ID SG_ID_HOST SG_ID_ELB 

## Scelta della regione (meglio con poche AZs) e altre definizioni
export AWS_REGION=us-east-2
MYTAG="{Key=esercizio,Value=load_balancing}"
MYPUBIP=$(curl -s https://ipinfo.io/ip)
## AMI id di Ubuntu 22.04 LTS server da https://cloud-images.ubuntu.com/locator/ec2/
AMI_ID=ami-05f4e4084abd205cf
AWS_KEYNAME=mac13
INST_NAME_PREFIX=WebServer

## Trova la VPC di default
DEFAULT_VPC=$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query Vpcs[0].VpcId --output text)

## Trova le subnet
cmd="aws ec2 describe-subnets --filters Name=vpc-id,Values=$DEFAULT_VPC"
cmd="$cmd --query Subnets[*].[AvailabilityZone,SubnetId] --output text"
SUBNET_AZ_ID_FIND_CMD="$cmd | sed -e 's/'$AWS_REGION'\([a-z]\)\t\(.*\)/[\1]=\2/g' | tr '\n' ' ' "
SUBNET_AZ_ID_PAIRS=$(eval "$SUBNET_AZ_ID_FIND_CMD")
echo $SUBNET_AZ_ID_PAIRS

# SUBNET_ID e' un array associativo e SUBNET_ID_DEF il suo inizializzatore
declare -A SUBNET_ID="( $SUBNET_AZ_ID_PAIRS )"
#${SUBNET_ID[a]} e' la subnet della AZ a, cosi' per b, c...


## Definisci security groups

# Cancella istanze e security group preesistenti

MYASSETS=$(aws ec2 describe-tags --filters Name=tag-value,Values=load_balancing \
   --query 'Tags[*].{ResType:ResourceType,ResId:ResourceId}' --output text)

INSTIDS=$(echo "$MYASSETS" | grep instance | cut -f 1 | tr '\n' ' ')
[[ "x$INSTIDS" != "x" ]] && aws ec2 terminate-instances --instance-ids $INSTIDS --output text

for sg in $(echo "$MYASSETS" | grep security-group | cut -f 1) ; do
   aws ec2 delete-security-group --group-id $sg
done

# security group per le istanze (accesso solo dal cliente, per ssh e http)

SG_ID_HOST=$(aws ec2 create-security-group --group-name WebHostSG \
   --tag-specifications "ResourceType=security-group,Tags=[$MYTAG]" \
   --description "Security group per Web App (port 80)" \
   --vpc-id $DEFAULT_VPC  --query 'GroupId' --output text)
echo -e "SG_ID_HOST=$SG_ID_HOST"

aws ec2 authorize-security-group-ingress --group-id ${SG_ID_HOST} --protocol tcp --port 80 \
   --cidr $MYPUBIP/32 --query SecurityGroupRules[0].[FromPort,CidrIpv4] --output text
aws ec2 authorize-security-group-ingress --group-id ${SG_ID_HOST} --protocol tcp --port 22 \
   --cidr $MYPUBIP/32 --query SecurityGroupRules[0].[FromPort,CidrIpv4] --output text

# security group per il Load Balancer (accesso da ovunque, solo http)

SG_ID_ELB=$(aws ec2 create-security-group --group-name HttpElbSG \
   --tag-specifications "ResourceType=security-group,Tags=[$MYTAG]" \
   --description "Security group per Web App (port 80)" \
   --vpc-id $DEFAULT_VPC  --query 'GroupId' --output text)
echo -e "SG_ID_ELB=$SG_ID_ELB"

aws ec2 authorize-security-group-ingress --group-id ${SG_ID_ELB} --protocol tcp --port 80 \
   --cidr 0.0.0.0/0 --query SecurityGroupRules[0].[FromPort,CidrIpv4] --output text


## Alternativa per trovare a runtime AMI_ID aggiornata, attivando prossimo comando
LAST_UBU_VER="ubuntu-pro-server/images/hvm-ssd/ubuntu-jammy-22.04-amd64-pro-server*"
cmd="aws ec2 describe-images --filters Name=name,Values=$LAST_UBU_VER"
cmd="$cmd --query Images[*].[ImageId,Name] --output text"
#AMI_ID=$(eval $cmd | tail -1 | tee /dev/stderr | cut -f1)


## Crea launch template

for lt in $(echo "$MYASSETS" | grep launch-template | cut -f 1) ; do
   aws ec2 delete-launch-template --launch-template-id $lt >/dev/null
done

MYJTAG=${MYTAG//=/\":\"}
MYJTAG=${MYJTAG/\{/\{\"}
MYJTAG=${MYJTAG/,/\",\"}
MYJTAG=${MYJTAG/\}/\"\}}

USERDATA64=$(base64 -w0 aws_1st_boot.sh)

aws ec2 create-launch-template --launch-template-name esercizio_LB \
   --tag-specifications "ResourceType=launch-template,Tags=[$MYTAG]" \
   --launch-template-data '{
         "ImageId":"'$AMI_ID'",
         "InstanceType":"t2.micro",
         "KeyName":"'$AWS_KEYNAME'",
         "SecurityGroupIds":["'$SG_ID_HOST'"],
         "UserData":"'$USERDATA64'"
      }' \
      --query LaunchTemplate.[LaunchTemplateName,LaunchTemplateId] \
      --output text

#         "TagSpecifications":[{"ResourceType":"launch-template","Tags":['$MYJTAG']}],


## Avvia istanze

zone=a
# Il nome della zona va in maiuscolo nel nome dell'istanza
INST_NAME=${INST_NAME_PREFIX}${zone^^}

return >& /dev/null ; exit

INST_ID=$(aws ec2 run-instances --launch-template LaunchTemplateName=esercizio_LB \
   --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INST_NAME}]" \
   --subnet-id ${SUBNET_ID[$zone]} \
   --query Instances[0].InstanceId  --output text)
echo "Launching $INST_ID"

aws ec2 wait instance-running --instance-ids $INST_ID
