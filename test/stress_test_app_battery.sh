#!/usr/bin/env bash

# Test a running server. If the certificate directory does not exist,
# a new CA will be created in it.

# Fail on any error
set -e

PASSED=0
FAILED=0

if [ $# \< 5 ]
then
  echo "$0 <certificate directory> <CT server public key> <server> <start cert id> <end cert id>"
  exit 1
fi

CERT_DIR=$1
CT_KEY=$2
SERVER=$3
STARTID=$4
ENDID=$5

echo $SERVER

. generate_certs.sh

if [ ! -e $CERT_DIR/ca-database ]
then
  echo "Initialise CA"
  ca_setup $CERT_DIR ca false
fi

ct_bin=ct
# FIXME(benl): share with sslconnect_test.sh?
audit() {
  cert_dir=$1
  log_server=$2
  sct=$3
  local local_server=$4

  set +e
  echo DWC ../cpp/client/$ct_bin audit --ct_server="http://$local_server" \
      --ct_server_public_key=$CT_KEY \
          --ssl_client_ct_data_in=$sct --logtostderr=true
  ../cpp/client/$ct_bin audit --ct_server="http://$local_server" \
    --ct_server_public_key=$CT_KEY \
    --ssl_client_ct_data_in=$sct --logtostderr=true
  retcode=$?
  set -e
}

do_audit() {
  ct_data=$1
  local local_server=$2
  T=`date +%s`
  T=`expr $T + 90`

  while true
  do
    audit $CERT_DIR ca $ct_data $local_server
    if [ $retcode -eq 0 ]; then
      echo "PASS audit"
      echo "PASS audit" >> results.txt
      let PASSED=$PASSED+1
      break
    else
      if [ `date +%s` \> $T ]
      then
        echo "FAIL audit"
	      echo "FAIL audit" >> results.txt
	      let FAILED=$FAILED+1
	      break
      fi
    fi
    sleep 10
  done
}

get_sth() {
  local file=$1
  local local_server=$2

  ../cpp/client/$ct_bin sth --ct_server="http://$local_server" \
    --ct_server_public_key=$CT_KEY --logtostderr=true \
    --ct_server_response_out=$file
}

consistency() {
  local file1=$1
  local file2=$2
  local local_server=$3

  ../cpp/client/$ct_bin consistency --ct_server="http://$local_server" \
    --ct_server_public_key=$CT_KEY --logtostderr=true \
    --sth1=$file1 --sth2=$file2

  if [ $? -eq 0 ]; then
    echo "PASS consistency"
    echo "PASS consistency" >> results.txt
  else
    echo "FAIL consistency"
    echo "FAIL consistency" >> results.txt
  fi
}

get_entries() {
  local first=$1
  local last=$2
  local local_server=$3

  ../cpp/client/$ct_bin get_entries --ct_server="http://$local_server" \
    --ct_server_public_key=$CT_KEY --logtostderr=true \
      --get_first=$first --get_last=$last --certificate_base=$CERT_DIR/cert.
}

port_one=800
port_two=801
port=$port_one
other_port=$port_two
pick_port() {
  if [ `rand` -lt 16288 ] 
  then
    port=$port_one
    other_port=$port_two
  else
    port=$port_two
    other_port=$port_one
  fi
}



counter=$STARTID
while true
do
  echo $counter
  pick_port
  echo $port
  echo "counter:$counter port:$port oport:$other_port"
  echo "counter:$counter port:$port oport:$other_port" >> results.txt 
  get_sth $CERT_DIR/sth$counter.1 $SERVER:$port

  #Produce certs and add to each ct instance
  echo DWC make_cert $CERT_DIR test$counter.1 ca http://$SERVER:$port false $CT_KEY
  make_cert $CERT_DIR test$counter.1 ca http://$SERVER:$port false $CT_KEY
  sleep 1
  echo  DWC make_cert $CERT_DIR test$counter.2 ca http://$SERVER:$other_port false $CT_KEY
  make_cert $CERT_DIR test$counter.2 ca http://$SERVER:$other_port false $CT_KEY
  sleep 300

  # Do the audits.  Audit for the cert produced on the other ct instance
  do_audit $CERT_DIR/test$counter.1-cert.ctdata $SERVER:$other_port
  sleep 1
  do_audit $CERT_DIR/test$counter.2-cert.ctdata $SERVER:$port
  sleep 1

  #Get sth for other ct instance
  get_sth $CERT_DIR/sth$counter.2 $SERVER:$other_port
  sleep 1

  #Check consistency on both ct instances
  echo "Check consistency on $port from $CERT_DIR/sth$counter.1 $CERT_DIR/sth$counter.2"
  consistency $CERT_DIR/sth$counter.1 $CERT_DIR/sth$counter.2 $SERVER:$port
  sleep 1
  echo "Check consistency on $other_port from $CERT_DIR/sth$counter.1 $CERT_DIR/sth$counter.2"
  consistency $CERT_DIR/sth$counter.1 $CERT_DIR/sth$counter.2 $SERVER:$other_port
  sleep 1

  #get_entries 0 2 $SERVER:$port
  
  (( counter += 1 ))
  if [ $counter -eq $ENDID ] 
  then
    break
  fi
done


echo $PASSED passed
echo $FAILED failed
