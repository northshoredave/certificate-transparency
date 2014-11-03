#!/usr/bin/env bash

# Note: run make freebsd-links, make linux-links or make local-links
# before running this test

# TODO(ekasper): This test is getting too long. Split into smaller test cases.

source generate_certs.sh

PASSED=0
FAILED=0

if [ $# -lt 3 ]
then 
  echo "$0 <certDir> <port> <HTTP> <numCerts> <logOutput>"
  exit 1
fi

TMPDIR=$1
MYPORT=$2
if [ $3 == "YES" ]; then
  HTTP_LOG=-http_log
  SERVER=ct-server
else
  SERVER=ct-server
fi
NUMCERTS=$4
LOGOUTPUT=$5
if [ $6 == "akamai" ]; then
  AKAMAI="--akamai_run --akamai_db_cert=/home/dcurrie/MyStuff/AppBatteryCT/tmp/cert_db/dcurrie_testnet_kdc_ca.crt.pem --akamai_db_key=/home/dcurrie/MyStuff/AppBatteryCT/tmp/cert_db/dcurrie_testnet_kdc_ca.key.pem --akamai_db_hostname=api-prod.dbattery.sqa2.qa.akamai.com --akamai_db_preface=/v1/apps/"
else
  AKAMAI=""
fi

if [ "$OPENSSLDIR" != "" ]; then
  MY_OPENSSL="$OPENSSLDIR/apps/openssl"
  export LD_LIBRARY_PATH=$OPENSSLDIR:$LD_LIBRARY_PATH
fi

if [ ! $MY_OPENSSL ]; then
# Try to use the system OpenSSL
  MY_OPENSSL=openssl
fi

test_connect() {
  cert_dir=$1
  hash_dir=$2
  log_server=$3
  ca=$4
  port=$5
  expect_fail=$6
  strict=$7
  audit=$8
 
  if [ "$audit" == "true" ]; then
    local client_flags="--ssl_client_ct_data_out=$cert_dir/$port.sct"
  fi

  # Continue tests on error
  echo DWC:test_connect:../cpp/client/ct connect --ssl_server="127.0.0.1" --ssl_server_port=$port \
    --ct_server_public_key=$cert_dir/$log_server-key-public.pem \
    --ssl_client_trusted_cert_dir=$hash_dir --logtostderr=true \
    --ssl_client_require_sct=$strict \
    --ssl_client_expect_handshake_failure=$expect_fail $client_flags
  set +e
  ../cpp/client/ct connect --ssl_server="127.0.0.1" --ssl_server_port=$port \
    --ct_server_public_key=$cert_dir/$log_server-key-public.pem \
    --ssl_client_trusted_cert_dir=$hash_dir --logtostderr=true \
    --ssl_client_require_sct=$strict \
    --ssl_client_expect_handshake_failure=$expect_fail $client_flags

  local retcode=$?
  set -e

  if [ $retcode -eq 0 ]; then
    echo "PASS"
    let PASSED=$PASSED+1
  else
    echo "FAIL"
    let FAILED=$FAILED+1
  fi
}

audit() {
  cert_dir=$1
  log_server=$2
  port=$3

  echo DWC:audit:../cpp/client/ct audit --ct_server="127.0.0.1" --ct_server_port=8124 \
    --ct_server_public_key=$cert_dir/$log_server-key-public.pem \
    --ssl_client_ct_data_in=$cert_dir/$port.sct --logtostderr=true
  set +e
  ../cpp/client/ct audit --ct_server="127.0.0.1" --ct_server_port=8124 \
    --ct_server_public_key=$cert_dir/$log_server-key-public.pem \
    --ssl_client_ct_data_in=$cert_dir/$port.sct --logtostderr=true
  local retcode=$?
  set -e

  if [ $retcode -eq 0 ]; then
    echo "PASS"
    let PASSED=$PASSED+1
  else
    echo "FAIL"
    let FAILED=$FAILED+1
  fi
}

test_range() {
  ports=$1
  cert_dir=$2
  hash_dir=$3
  log_server=$4
  ca=$5
  conf=$6
  expect_fail=$7
  strict=$8
  audit=$9
  apache=${10}

  echo "Starting Apache"
  export APACHE_ENVVARS=./httpd.envvars # workaround Debian's apachectl
  echo DWC:test_range:$apache -d `pwd`/$cert_dir -f `pwd`/$conf -k start
  $apache -d `pwd`/$cert_dir -f `pwd`/$conf -k start

  for port in $ports; do
    test_connect $cert_dir $hash_dir $log_server $ca $port $expect_fail \
      $strict $audit
  done

  echo "Stopping Apache"
  echo DWC:test_range $apache -d `pwd`/$cert_dir -f `pwd`/$conf -k stop
  $apache -d `pwd`/$cert_dir -f `pwd`/$conf -k stop
  # Wait for Apache to die
  sleep 5

  if [ "$audit" == "true" ]; then
    echo "Starting audit"
    for port in $ports; do
      audit $cert_dir $log_server $port
    done
  fi
}

# Regression tests against known good/bad certificates
mkdir -p ca-hashes
hash=$($MY_OPENSSL x509 -in testdata/ca-cert.pem -hash -noout)
cp testdata/ca-cert.pem ca-hashes/$hash.0

echo "Testing known good/bad certificate configurations" 
mkdir -p testdata/logs

#test_range "8125 8126 8127 8128 8129 8130" testdata ca-hashes ct-server ca \
#  httpd-valid.conf false true false ./apachectl
#test_range "8125 8126 8127 8128" testdata ca-hashes ct-server ca \
#  httpd-invalid.conf false false false ./apachectl
#test_range "8125 8126 8127 8128" testdata ca-hashes ct-server ca \
#  httpd-invalid.conf true true false ./apachectl

rm -rf ca-hashes

# Generate new certs dynamically and repeat the test for valid certs
mkdir -p $TMPDIR
# A directory for trusted certs in OpenSSL "hash format"
mkdir -p $TMPDIR/ca-hashes

#echo "Not generating CA and log keys again.  Comment this, and uncomment below to generate"
echo "Generating CA certificates in $TMPDIR and hashes in $TMPDIR/ca"
echo make_ca_certs `pwd`/$TMPDIR `pwd`/$TMPDIR/ca-hashes ca $MY_OPENSSL
make_ca_certs `pwd`/$TMPDIR `pwd`/$TMPDIR/ca-hashes ca $MY_OPENSSL
ca_file="$TMPDIR/$ca-cert.pem"
echo "Generating log server keys in $TMPDIR"
make_log_server_keys `pwd`/$TMPDIR ct-server

# Start the log server and wait for it to come up
mkdir -p $TMPDIR/storage
mkdir -p $TMPDIR/storage/certs
mkdir -p $TMPDIR/storage/tree

test_ct_server() {
  flags=$@

  # Set the tree signing frequency to 0 to ensure we sign as often as possible.
  echo "Starting CT server with trusted certs in $ca_file"
  echo DWC:test_ct_server:../cpp/server/$SERVER $AKAMAI --port=$MYPORT --key=\"$cert_dir/$log_server-key.pem\" \
    --trusted_cert_file="$ca_file" --log_dir=./$LOGOUTPUT \
    --tree_signing_frequency_seconds=15 $flags &

  ../cpp/server/$SERVER $AKAMAI --port=$MYPORT --key="$cert_dir/$log_server-key.pem" \
    --trusted_cert_file="$ca_file" --log_dir=./$LOGOUTPUT \
    --tree_signing_frequency_seconds=15 $flags &

  server_pid=$!
  sleep 5

  echo "Generating test certificates"
  for i in `seq 1 $NUMCERTS` 
  do
    echo "DWC do test$i"
    make_cert `pwd`/$TMPDIR test$i ca http://127.0.0.1:$MYPORT false \
      `pwd`/$TMPDIR/ct-server-key-public.pem
    make_embedded_cert `pwd`/$TMPDIR test$i-embedded ca \
      http://127.0.0.1:$MYPORT false false `pwd`/$TMPDIR/ct-server-key-public.pem
    make_embedded_cert `pwd`/$TMPDIR test$i-embedded-with-preca \
      ca http://127.0.0.1:$MYPORT false true `pwd`/$TMPDIR/ct-server-key-public.pem
  done
  #DWC wait until tree signs the first set of 3
  sleep 15
  # Generate a second set of certs that chain through an intermediate
  #  First setup a second ca
  make_intermediate_ca_certs `pwd`/$TMPDIR intermediate ca

  for i in `seq 1 $NUMCERTS` 
  do 
    make_cert `pwd`/$TMPDIR test$i-intermediate intermediate \
      http://127.0.0.1:$MYPORT true `pwd`/$TMPDIR/ct-server-key-public.pem
    make_embedded_cert `pwd`/$TMPDIR \
      test$i-embedded-with-intermediate intermediate http://127.0.0.1:$MYPORT true \
        false `pwd`/$TMPDIR/ct-server-key-public.pem
    make_embedded_cert `pwd`/$TMPDIR \
      test$i-embedded-with-intermediate-preca intermediate http://127.0.0.1:$MYPORT \
        true true `pwd`/$TMPDIR/ct-server-key-public.pem
  done

  # Wait a bit to ensure the server signs the tree.
  #sleep 5

  echo "Testing valid configurations with new certificates"
  mkdir -p $TMPDIR/logs
#  test_range "8125 8126 8127 8128 8129 8130" $TMPDIR $TMPDIR/ca-hashes ct-server ca \
#    httpd-valid.conf false true true ./apachectl

  # Stop the log server
#  echo "Stopping CT server"
#  kill -9 $server_pid  
  sleep 2
}

test_ct_server --sqlite_db=$TMPDIR/storage/ct

#test_ct_server --cert_dir="$TMPDIR/storage/certs"  --tree_dir="$TMPDIR/storage/tree" \
#    --cert_storage_depth=3 --tree_storage_depth=8

echo "Cleaning up"
#rm -rf $TMPDIR
#if [ $FAILED == 0 ]; then
#  rm -rf testdata/logs
#fi
echo "PASSED $PASSED tests"
echo "FAILED $FAILED tests"
