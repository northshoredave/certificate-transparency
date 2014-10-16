#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <string>
#include <fstream>
#include <algorithm>

#include "log/cert.h"
#include "log/cert_checker.h"
#include "log/ct_extensions.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/frontend.h"
#include "log/frontend_signer.h"
#include "log/log_lookup.h"
#include "log/log_signer.h"
#include "log/logged_certificate.h"
#include "log/sqlite_db.h"
#include "log/databattery_db.h"
#include "log/tree_signer.h"
#include "proto/ct.pb.h"
#include "util/json_wrapper.h"
#include "util/openssl_util.h"
#include "log/data_battery.h"
#include "util/openssl_thread_locks.h"

DEFINE_string(akamai_db_app,"ct",
             "App name used by databattery for CT");
DEFINE_string(akamai_db_hostname,"", "Hostname of DataBattery");
DEFINE_string(akamai_db_serv,"443",
              "Port or service for DataBattery");
DEFINE_string(akamai_db_cert,"", "Cert to use when accessing DataBattery");
DEFINE_string(akamai_db_key,"", "Key to use when accessing DataBattery");
DEFINE_string(akamai_db_pending,"pending","What table to get pending from.");
DEFINE_string(akamai_db_leaves,"leaves","What table to get leaves from");
DEFINE_string(akamai_db_index,"index","Key name for index in any DB table");
DEFINE_string(akamai_db_config_table,"pending","What table to get config from");
DEFINE_string(akamai_db_config_key,"config","What key to retrieve from config table");
DEFINE_string(akamai_db_roots_table,"leaves","What table to put roots in");
DEFINE_string(akamai_db_roots_key,"roots","What key to put roots in");
DEFINE_uint64(akamai_clear_removed_peers,0,"Clear pending table of the removed peers older then this.  0 disables");
DEFINE_bool(akamai_clear_pending,false,"Clear pending table of pending certs");
DEFINE_bool(akamai_clear_leaves,false,"Clear leaves table");
DEFINE_bool(akamai_clear_peers,false,"Clear the peers");
DEFINE_bool(akamai_yes_really_clear,false,"Failsafe so you have to set 2 flags to actually clear");
DEFINE_bool(akamai_print_peers,false,"Get peers from DB and print it out");
DEFINE_bool(akamai_print_config,false,"Get config from DB and print it out");
DEFINE_string(akamai_print_index,"empty","Print index from table.  Requires string index or pending");
DEFINE_uint64(akamai_db_request_bytes,5242880,"size of DB max entry size");
DEFINE_string(akamai_submit_root_ca,"empty","Give filename of roots ca to submit.  Carefull, this overwrites what's in the DB.  Only takes effect when CT restarts");
DEFINE_bool(akamai_print_root_ca,false,"Print out subj of root ca");

using namespace std;
using namespace Akamai;

void clear_leaves(DataBattery* db) {
  LOG(INFO) << "clear leaves";
  DBIndex index;
  index.set_last_key(0);
  index.set_first_key(0);
  db->put_index(FLAGS_akamai_db_leaves,FLAGS_akamai_db_index,index);
  ct::LoggedCertificatePBList tmp;
  string data;
  tmp.SerializeToString(&data);
  db->PUT(FLAGS_akamai_db_leaves,"0",data);
}

void clear_pending(DataBattery* db,set<string>& peer_set) {
  for (set<string>::const_iterator p = peer_set.begin(); p != peer_set.end(); ++p) {
    string index_key = *p+string(".index");
    DBIndex index;
    db->get_index(FLAGS_akamai_db_pending,index_key,index);
    vector<string> keys;
    index.get_all_keys_from_zero(*p,keys);
    for (vector<string>::const_iterator k = keys.begin(); k != keys.end(); ++k) {
      LOG(INFO) << "Delete key " << *k;
      db->DELETE(FLAGS_akamai_db_pending,*k);
    }
    LOG(INFO) << "Delete index " << index_key;
    db->DELETE(FLAGS_akamai_db_pending,index_key);
  }
}

void clear_all_pending(DataBattery* db) {
  LOG(INFO) << "clear all pending";
  Peers p(0,0,0);
  if (!p.GET(db,FLAGS_akamai_db_pending)) {
    LOG(ERROR) << "Failed to get pending";
    return;
  }
  set<string> peer_set;
  p.get_removed_peer_set(peer_set,0);
  clear_pending(db,peer_set);
  p.get_peer_set(peer_set);
  clear_pending(db,peer_set);
}

void clear_removed_pending(DataBattery* db) {
  LOG(INFO) << "clear removed pending";
  Peers p(0,0,0);
  if (!p.GET(db,FLAGS_akamai_db_pending)) {
    LOG(ERROR) << "Failed to get pending";
    return;
  }
  set<string> peer_set;
  p.get_peer_set(peer_set);
  set<string> removed_peer_set;
  p.get_removed_peer_set(removed_peer_set,FLAGS_akamai_clear_removed_peers);
  //Shoudn't have peers in both removed and active.  But just in case.
  set<string> diff_peer_set;
  set_difference(removed_peer_set.begin(),removed_peer_set.end(),
                 peer_set.begin(), peer_set.end(),
                 inserter(diff_peer_set,diff_peer_set.begin()));
  for (set<string>::const_iterator pIt = diff_peer_set.begin();
      pIt != diff_peer_set.end(); ++pIt) {
    LOG(INFO) << "Diff_peer: " << *pIt;
  }
  clear_pending(db,diff_peer_set);

  //Get the peers again before clearing and re-committing.  The reason being that the index delete above may
  // take some time.  When you commit the peers back to DB, the times are old and you've possibly lost data that
  // might have been added while you were clearing things up.
  if (!p.GET(db,FLAGS_akamai_db_pending)) {
    LOG(ERROR) << "Failed to get pending before clear removed";
    return;
  }
  //Now clear the removed peers in the peerset. 
  p.clear_removed_peers(removed_peer_set);

  p.PUT(db,FLAGS_akamai_db_pending);
}

void clear_peers(DataBattery* db) {
  LOG(INFO) << "clear peers";
  Peers p(0,0,0);
  p.PUT(db,FLAGS_akamai_db_pending);
}

void print_peers(DataBattery* db) {
  LOG(INFO) << "print peers";
  Peers p(0,0,0);
  p.GET(db,FLAGS_akamai_db_pending);
  string tmp;
  google::protobuf::TextFormat::PrintToString(p.get_msg(),&tmp);
  LOG(INFO) << tmp;
}

void print_config(DataBattery* db) {
  LOG(INFO) << "print config";
  ct::AkamaiConfig config;
  string value;
  if (!db->GET_key_from_table(FLAGS_akamai_db_config_table,FLAGS_akamai_db_config_key,
        FLAGS_akamai_db_request_bytes,value)) {
    LOG(ERROR) << "Couldn't get config from DB";
  }
  config.ParseFromString(value);
  string tmp;
  google::protobuf::TextFormat::PrintToString(config,&tmp);
  LOG(INFO) << tmp;
}

void print_index(DataBattery* db,string table) {
  LOG(INFO) << "print index for table " << table;
  DBIndex index;
  if (!db->get_index(table,"index",index)) {
    LOG(ERROR) << "Couldn't get index for table " << table;
  }
  string tmp;
  google::protobuf::TextFormat::PrintToString(index.get_msg(),&tmp);
  LOG(INFO) << tmp;
}

void print_pending_indexes(DataBattery* db) {
  LOG(INFO) << "print pending indexes of live peers";
  Peers p(0,0,0);
  p.GET(db,FLAGS_akamai_db_pending);
  set<string> peer_set;
  p.get_peer_set(peer_set);
  for (set<string>::const_iterator pIt = peer_set.begin(); pIt != peer_set.end(); ++pIt) {
    string index_key = *pIt+string(".index");
    DBIndex index;
    db->get_index(FLAGS_akamai_db_pending,index_key,index);
    string tmp;
    google::protobuf::TextFormat::PrintToString(index.get_msg(),&tmp);
    LOG(INFO) << "PeerIndex:" << *pIt << " " << tmp;
  }
}

void submit_root_ca(DataBattery* db, string &cert_file) {
  ct::CertChecker checker;
   if (!checker.LoadTrustedCertificates(cert_file)) {
     LOG(INFO) << "Opps, couldn't read cert_file " << cert_file;
   }
   ct::X509Root roots;
   for (multimap<string,const ct::Cert*>::const_iterator cIt = checker.GetTrustedCertificates().begin();
       cIt != checker.GetTrustedCertificates().end(); ++cIt) {
     string der_encoding;
     LOG(INFO) << "Adding cert " << cIt->second->PrintSubjectName();
     cIt->second->DerEncoding(&der_encoding);
     roots.add_roots(der_encoding);
   }
   string data;
   roots.SerializeToString(&data);
   if (!db->PUT(FLAGS_akamai_db_roots_table,FLAGS_akamai_db_roots_key,data)) {
     LOG(INFO) << "Put roots failed";
   }
}

void print_root_ca(DataBattery* db) {
  string data;
  if (!db->GET(FLAGS_akamai_db_roots_table,FLAGS_akamai_db_roots_key,data)) {
    LOG(INFO) << "Failed to get roots";
  }
  ct::X509Root roots;
  if (!roots.ParseFromString(data)) {
    LOG(INFO) << "Failed to parse roots";
  }
  for (int i = 0; i < roots.roots_size(); ++i) {
    ct::Cert tmp;
    tmp.LoadFromDerString(roots.roots(i));
    LOG(INFO) << tmp.PrintSubjectName();
  }
}

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  ct::LoadCtExtensions();

  DataBattery::Settings db_settings(FLAGS_akamai_db_app,FLAGS_akamai_db_hostname,
  FLAGS_akamai_db_serv, FLAGS_akamai_db_cert, FLAGS_akamai_db_key,5);
  DataBattery* db = new DataBattery(db_settings);
  CHECK(db->is_good()) << "Failed to create DataBattery instance for db";

  if (FLAGS_akamai_print_peers) {
    print_peers(db);
  }
  if (FLAGS_akamai_print_config) {
    print_config(db);
  }
  if (FLAGS_akamai_print_index == "pending") {
    print_pending_indexes(db);
  }
  if (FLAGS_akamai_print_index == "leaves") {
    print_index(db,FLAGS_akamai_db_leaves);
  }

  if (FLAGS_akamai_yes_really_clear) {
    if (FLAGS_akamai_clear_leaves) { clear_leaves(db); }
    if (FLAGS_akamai_clear_pending) { clear_all_pending(db); }
    if (FLAGS_akamai_clear_peers) { clear_peers(db); }
  }
  if (FLAGS_akamai_clear_removed_peers) {
    clear_removed_pending(db);
  }

  if (FLAGS_akamai_submit_root_ca != "empty") {
    submit_root_ca(db,FLAGS_akamai_submit_root_ca);
  }
  if (FLAGS_akamai_print_root_ca) {
    print_root_ca(db);
  }

  delete db;
  return 0;
}
