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
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/date_time/local_time/local_time.hpp"
#include "boost/filesystem.hpp"

DEFINE_string(akamai_db_app,"ct",
             "App name used by databattery for CT");
DEFINE_string(akamai_db_hostname,"", "Hostname of DataBattery");
DEFINE_string(akamai_db_preface,"","Preface when GET, PUT access DB");
DEFINE_string(akamai_db_serv,"443",
              "Port or service for DataBattery");
DEFINE_string(akamai_db_cert,"", "Cert to use when accessing DataBattery");
DEFINE_string(akamai_db_key,"", "Key to use when accessing DataBattery");
DEFINE_string(akamai_db_cert_dir,"","What directory to look in for DataBattery cert/key");
DEFINE_string(akamai_db_pending,"pending","What table to get pending from.");
DEFINE_string(akamai_db_leaves,"leaves","What table to get leaves from");
DEFINE_string(akamai_db_index,"index","Key name for index in any DB table");
DEFINE_string(akamai_db_config_table,"pending","What table to get config from");
DEFINE_string(akamai_db_config_key,"config","What key to retrieve from config table");
DEFINE_string(akamai_db_roots_table,"leaves","What table to put roots in");
DEFINE_string(akamai_db_roots_key,"roots","What key to put roots in");
DEFINE_string(akamai_db_all_roots_key,"all_roots","What key to put all roots in");
DEFINE_uint64(akamai_clear_removed_peers,0,"Clear pending table of the removed peers older then this.  0 disables");
DEFINE_bool(akamai_clear_pending,false,"Clear pending table of pending certs");
DEFINE_bool(akamai_clear_leaves,false,"Clear leaves table");
DEFINE_bool(akamai_clear_peers,false,"Clear the peers");
DEFINE_bool(akamai_yes_really_clear,false,"Failsafe so you have to set 2 flags to actually clear");
DEFINE_bool(akamai_print_peers,false,"Get peers from DB and print it out");
DEFINE_bool(akamai_print_config,false,"Get config from DB and print it out");
DEFINE_string(akamai_read_config,"empty","Read config from file to get config settings");
DEFINE_string(akamai_print_index,"empty","Print index from table.  Requires string index or pending");
DEFINE_uint64(akamai_db_request_bytes,5242880,"size of DB max entry size");
DEFINE_string(akamai_submit_root_ca,"empty","Give filename of roots ca to submit for reduced set.  Carefull, this overwrites what's in the DB.  Only takes effect when CT restarts");
DEFINE_string(akamai_submit_all_root_ca,"empty","Give filename of roots ca to submit for complete set.  Carefull, this overwrites what's in the DB.  Only takes effect when CT restarts");
DEFINE_string(akamai_dump_root_ca,"empty","Dumps out the reduced root ca in entirety");
DEFINE_string(akamai_dump_all_root_ca,"empty","Dumps out the complete root ca in entirety");
DEFINE_bool(akamai_print_root_ca,false,"Print out subj of reduced root ca");
DEFINE_bool(akamai_print_all_root_ca,false,"Print out subj of complete root ca");
DEFINE_string(akamai_dump_leaves,"empty","Dump the leaves in serialized form to a file.  The file could then be read by another tool, or if we ever move to another database");
DEFINE_string(akamai_read_leaves,"empty","Read leaves from file and load into DataBattery.");
DEFINE_string(akamai_dump_pending,"empty","Dump the pending in serialized form to a file.  The file could then be read by another tool, or if we ever move to another database");
DEFINE_string(akamai_read_pending,"empty","Read pending from file and load into DataBattery.");
DEFINE_string(akamai_log_cert,"empty","Write log cert to this file");
DEFINE_string(akamai_log_cert_key,"log_cert","What key to retrieve log_cert from");

//CHECKPOINTING options.  Almost a seperate tool, but let's keep it all fun in the family
DEFINE_bool(run_checkpointer,false,"Go into checkpointing loop");
DEFINE_string(dir_name,"checkpoint/","What directory to store checkpoints in");
DEFINE_uint64(max_num,1000,"Maximum number of checkpoints you can keep");
DEFINE_uint64(max_space,1000000000,"Maximum amount of space checkpoints can occupy");
DEFINE_uint64(max_age,604800,"Maximum age of a checkpoint");
DEFINE_uint64(checkpoint_sleep_time,300,"Amount of time to sleep between checkpoints");

using namespace std;
using namespace Akamai;

//Utilities:
class checkPointer {
  public:
    checkPointer(string dir_name, string leaves, string pending, uint64_t max_num, uint64_t max_space, int max_age)
      : _dir_name(dir_name)
        , _leaves(leaves)
        , _pending(pending)
        , _max_num(max_num)
        , _max_space(max_space)
        , _max_age(max_age)
  {}
    void create_checkpoint();
    void update_timestamp_file();
  private:
    void dir_manager(int force_remove);
    void get_time_str(char* buffer, time_t* t = NULL);

  private:
    string _dir_name;
    string _leaves;
    string _pending;
    uint64_t _max_num;
    uint64_t _max_space;
    uint64_t _max_age;
};

void checkPointer::create_checkpoint() {
  char buffer[80]; get_time_str(buffer);
  //Generate new name
  string checkpoint = "checkpoint."+string(buffer)+".tar";

  //Create tar cmd and execute
  string cmd = "tar -C " + _dir_name + string(" -cf ") + _dir_name + checkpoint;
  cmd += string(" ") + _leaves + string(" ") + _pending;

  int retCode = system(cmd.c_str());
  if (retCode) {
    LOG(INFO) << "Failed checkpoint create";
  }

  cmd = "gzip " + _dir_name + checkpoint;
  retCode = system(cmd.c_str());
  if (retCode) {
    LOG(INFO) << "Failed gzip of checkpoint";
  }
  LOG(INFO) << "Create checkpoint " << checkpoint;
  dir_manager(0);
  update_timestamp_file();
}

void checkPointer::update_timestamp_file() {
  char buffer[80]; get_time_str(buffer);
  string timestamp_file = _dir_name+"last_write.txt";
  ofstream ofs(timestamp_file.c_str());
  ofs << buffer;
  ofs.close();
}

struct mngCmp {
  bool operator()(const boost::filesystem::path& f1, 
      const boost::filesystem::path& f2) {
    return boost::filesystem::last_write_time(f1) > 
      boost::filesystem::last_write_time(f2);
  }
};

//Manages the files in a directory by removing any that exceed given limits
//Limits are:
//    max_num - maximum number of files in directory
//    _max_space - maximum space in bytes that files can occupy
//    _max_age - maximum age (in seconds).
//    force_remove - remove X files, if possible
//Files are removed in order of age (oldest first) until thresholds are met
void checkPointer::dir_manager(int force_remove) {
  namespace fs = boost::filesystem;
  try {
    fs::path mng_dir(_dir_name);
    if (!fs::exists(mng_dir)||!fs::is_directory(mng_dir)) {
      LOG(INFO) << "dirManager: dir not found " << mng_dir.string();
    } else {
      double usedSpace(0);
      //Build up filelist in order of last_write_time
      LOG(INFO) << "dirManager: build up file list";
      vector<fs::path> mngFiles;
      fs::directory_iterator end_iter;
      for (fs::directory_iterator dir_itr(mng_dir); 
          dir_itr != end_iter; ++dir_itr) {
        if (fs::is_regular_file(dir_itr->status())) {
          usedSpace += fs::file_size(dir_itr->path()); 
          mngFiles.push_back(dir_itr->path());
        }
      }
      LOG(INFO) << "dirManager: sort files by timestamp";
      sort(mngFiles.begin(),mngFiles.end(),mngCmp());
      bool removeFile(true);
      double amountToRemove(0);
      if (_max_space && usedSpace > _max_space) { amountToRemove = usedSpace - _max_space; }
      LOG(INFO) << "dirManager: UsedSpace " << usedSpace << " _max_space " << _max_space << " amountToRem:"
        << amountToRemove;
      while (removeFile && !mngFiles.empty()) {
        removeFile = false;
        if (amountToRemove > 0) { 
          amountToRemove -= fs::file_size(mngFiles.back());
          removeFile = true;
        } else if (_max_num && mngFiles.size() > _max_num) {
          removeFile = true;
        } else if (_max_age && 
            fs::last_write_time(mngFiles.back())+_max_age < (uint)time(NULL)) {
          removeFile = true;
        } else if (force_remove > 0) {
          removeFile = true;
        }
        if (removeFile) { 
          if (!remove(mngFiles.back())) {
            LOG(INFO) << "Failed to remove file " << mngFiles.back().filename();
          } else {
            LOG(INFO) << "Removed file " << mngFiles.back().filename();
          }
          mngFiles.pop_back(); 
          if (force_remove > 0) { --force_remove; }
        }
      }
    }
  } catch (exception& e) {
    LOG(INFO) << "Caught exception " << e.what();
  } catch(...) {
    LOG(INFO) << "Unknown exception";
  }
}

//Generate a string with current date/time in human readable
void checkPointer::get_time_str(char* buffer, time_t* t) {
  //Generate current date/time
  time_t* localT;
  time_t tmp;
  if (t) { 
    localT = t; 
  } else { 
    localT = &tmp; 
    time(localT);
  } 
  struct tm * timeinfo;
  timeinfo = localtime(localT);
  strftime(buffer,80,"%b_%d_%Y.%H.%M.%S",timeinfo);
}

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
  Peers p(0,0,0,10,1);
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
  Peers p(0,0,0,10,1);
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
  Peers p(0,0,0,10,1);
  p.PUT(db,FLAGS_akamai_db_pending);
}

void print_peers(DataBattery* db) {
  LOG(INFO) << "print peers";
  Peers p(0,0,0,10,1);
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
  Peers p(0,0,0,10,1);
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

void submit_root_ca(DataBattery* db, string &cert_file, bool all_roots) {
  cert_trans::CertChecker checker;
   if (!checker.LoadTrustedCertificates(cert_file)) {
     LOG(INFO) << "Opps, couldn't read cert_file " << cert_file;
   }
   ct::X509Root roots;
   for (multimap<string,const cert_trans::Cert*>::const_iterator cIt = checker.GetTrustedCertificates().begin();
       cIt != checker.GetTrustedCertificates().end(); ++cIt) {
     string der_encoding;
     LOG(INFO) << "Adding cert " << cIt->second->PrintSubjectName();
     cIt->second->DerEncoding(&der_encoding);
     roots.add_roots(der_encoding);
   }
   string data;
   roots.SerializeToString(&data);
   string key = FLAGS_akamai_db_roots_key;
   if (all_roots) { key = FLAGS_akamai_db_all_roots_key; }
   if (!db->PUT(FLAGS_akamai_db_roots_table,key,data)) {
     LOG(INFO) << "Put roots failed";
   }
}

void print_root_ca(DataBattery* db, bool all_roots) {
  string data;
  string key = all_roots?FLAGS_akamai_db_all_roots_key:FLAGS_akamai_db_roots_key;
  if (!db->GET(FLAGS_akamai_db_roots_table,key,data)) {
    LOG(INFO) << "Failed to get roots";
  }
  ct::X509Root roots;
  if (!roots.ParseFromString(data)) {
    LOG(INFO) << "Failed to parse roots";
  }
  for (int i = 0; i < roots.roots_size(); ++i) {
    cert_trans::Cert tmp;
    tmp.LoadFromDerString(roots.roots(i));
    LOG(INFO) << tmp.PrintSubjectName();
  }
}

void dump_root_ca(DataBattery* db, bool all_roots) {
  string data;
  string key = all_roots?FLAGS_akamai_db_all_roots_key:FLAGS_akamai_db_roots_key;
  if (!db->GET(FLAGS_akamai_db_roots_table,key,data)) {
    LOG(INFO) << "Failed to get roots";
  }
  ct::X509Root roots;
  if (!roots.ParseFromString(data)) {
    LOG(INFO) << "Failed to parse roots";
  }
  ofstream ofs(FLAGS_akamai_dump_root_ca.c_str());
  for (int i = 0; i < roots.roots_size(); ++i) {
    ofs << roots.roots(i);
  }
  ofs.close();
}

uint64_t dump_leaves(DataBattery* db, CertTables& cert_tables,string to_file) {
  ct::LoggedCertificatePBList lcpbl;
  uint64_t last_key;
  cert_tables.get_all_leaves(0,FLAGS_akamai_db_leaves,FLAGS_akamai_db_request_bytes,
      db,lcpbl,last_key);
  LOG(INFO) << "Dumping " << lcpbl.logged_certificate_pbs_size() << " to file " << to_file;
  std::ofstream ofs(to_file.c_str());
  lcpbl.SerializeToOstream(&ofs);
  ofs.close();
  return last_key;
}

void read_leaves(DataBattery* db, ConfigData& cnfg) {
  ct::LoggedCertificatePBList lcpbl;
  ifstream ifs(FLAGS_akamai_read_leaves.c_str());
  lcpbl.ParseFromIstream(&ifs);
  LOG(INFO) << "Got " << lcpbl.logged_certificate_pbs_size() << " leaves from disk";
  ifs.close();
  //Clear out what's there
  clear_leaves(db);
  //Restore leaves from file
  CertTables cert_tables(db,"id",NULL,NULL,NULL,&cnfg);
  cert_tables.add_leaves(lcpbl,0);
}

void read_config(DataBattery* db, ct::AkamaiConfig* cnfg) {
  std::ifstream ifs(FLAGS_akamai_read_config.c_str());
  if (ifs.fail()) {
    LOG(ERROR) << "Unable to open config file " << FLAGS_akamai_read_config;
    return;
  }
  google::protobuf::io::IstreamInputStream* ifo = 
    new google::protobuf::io::IstreamInputStream(&ifs);
  if (!google::protobuf::TextFormat::Parse(ifo,cnfg)) {
    LOG(ERROR) << "Failed to parse config file ";
    return;
  }
  delete ifo;
  ifs.close();
}

uint dump_pending(CertTables& cert_tables,string to_file) {
  ct::LoggedCertificatePBList pending_lcpbl;
  cert_tables.get_all_pending(pending_lcpbl);
  LOG(INFO) << "Got " << pending_lcpbl.logged_certificate_pbs_size() << " pending certs";
  std::ofstream ofs(to_file.c_str());
  pending_lcpbl.SerializeToOstream(&ofs);
  ofs.close();
  return pending_lcpbl.logged_certificate_pbs_size();
}

void read_pending(DataBattery* db, ConfigData& cnfg) {
  //Retrieve pending certs from file
  std::ifstream ifs(FLAGS_akamai_read_pending.c_str());
  if (ifs.fail()) {
    LOG(ERROR) << "Unable to open pending file " << FLAGS_akamai_read_pending;
    return;
  }
  ct::LoggedCertificatePBList pending_lcpbl;
  pending_lcpbl.ParseFromIstream(&ifs);
  ifs.close();

  //Generate a uuid and add yourself to the peers
  Peers p(cnfg.fixed_peer_delay(),cnfg.random_peer_delay(),cnfg.max_peer_age_removal(),
      cnfg.max_time_skew(),cnfg.quorum());
  string id = Peers::randByteString(16); 
  p.update_peer(id,db,FLAGS_akamai_db_pending);

  //Now add all the pending to that peer
  PendingData pd;
  CertTables cert_tables(db,id,&pd,NULL,NULL,&cnfg);
  cert_tables.init_pending_data(&pd);

  for (int i = 0; i < pending_lcpbl.logged_certificate_pbs_size(); ++i) {
    cert_tables.pending_add(&pending_lcpbl.logged_certificate_pbs(i));
  }
}

void check_point_loop(DataBattery* db, ConfigData& cnfg) {
  string leaves_pb = FLAGS_akamai_db_leaves+".pb";
  string pending_pb = FLAGS_akamai_db_pending+".pb";
  checkPointer cp(FLAGS_dir_name,leaves_pb,pending_pb,FLAGS_max_num,FLAGS_max_space,FLAGS_max_age);
  LeavesData ld;
  leaves_thread_data ltd(db,&ld,&cnfg);
  CertTables cert_tables(db,"id",NULL,&ld,NULL,&cnfg);
  while (true) {
    uint num_of_leaves = ltd._ld->get_hash_size(); 
    leaves_helper(&ltd);
    std::ofstream ofs(string(FLAGS_dir_name+leaves_pb).c_str());
    LOG(INFO) << "Write leaves to " << FLAGS_dir_name+leaves_pb;
    ld.get_leaves().SerializeToOstream(&ofs);
    ofs.close();

    uint num_of_pending = dump_pending(cert_tables,FLAGS_dir_name+pending_pb);
    if ((num_of_leaves != ltd._ld->get_hash_size()) ||
        (num_of_pending != 0)) {
      cp.create_checkpoint();
    } else {
      LOG(INFO) << "Leaves unchanged and no pending, so skipping checkpoint";
      cp.update_timestamp_file();
    }
    sleep(FLAGS_checkpoint_sleep_time);
  }
}

void print_log_cert(DataBattery* db) {
  std::string value;
  if (!db->GET(FLAGS_akamai_db_pending,FLAGS_akamai_log_cert_key,value)) {
    LOG(ERROR) << "Unable to retrieve key " << FLAGS_akamai_log_cert_key;
    return;
  }
  std::ofstream ofs(FLAGS_akamai_log_cert.c_str());
  if (ofs.fail()) {
    LOG(ERROR) << "Failed to open file " << FLAGS_akamai_log_cert;
    return;
  }
  ofs << value;
  ofs.close();
}

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  cert_trans::LoadCtExtensions();

  DataBattery::Settings db_settings(FLAGS_akamai_db_app,FLAGS_akamai_db_hostname,
    FLAGS_akamai_db_serv, FLAGS_akamai_db_cert, FLAGS_akamai_db_key, FLAGS_akamai_db_cert_dir,
    5,0,FLAGS_akamai_db_preface);
  DataBattery* db = new DataBattery(db_settings);
  CHECK(db->is_good()) << "Failed to create DataBattery instance for db";

  if (FLAGS_akamai_read_config == "empty" &&
      (FLAGS_akamai_dump_leaves != "empty" ||
       FLAGS_akamai_read_leaves != "empty")) {
    LOG(ERROR) << "You must read config if you want to invoke dump_leaves or read_leaves";
    return 0;
  }
  ct::AkamaiConfig cnfg;
  if (FLAGS_akamai_read_config != "empty") { read_config(db,&cnfg); } 
  ConfigData cnfg_data(cnfg);
  if (FLAGS_akamai_print_peers) { print_peers(db); }
  if (FLAGS_akamai_print_config) { print_config(db); }
  if (FLAGS_akamai_print_index == "pending") { print_pending_indexes(db); }
  if (FLAGS_akamai_print_index == "leaves") { print_index(db,FLAGS_akamai_db_leaves); }
  if (FLAGS_akamai_yes_really_clear) {
    if (FLAGS_akamai_clear_leaves) { clear_leaves(db); }
    if (FLAGS_akamai_clear_pending) { clear_all_pending(db); }
    if (FLAGS_akamai_clear_peers) { clear_peers(db); }
  }
  if (FLAGS_akamai_clear_removed_peers) { clear_removed_pending(db); }
  if (FLAGS_akamai_submit_root_ca != "empty") { submit_root_ca(db,FLAGS_akamai_submit_root_ca,false); }
  if (FLAGS_akamai_submit_all_root_ca != "empty") { submit_root_ca(db,FLAGS_akamai_submit_all_root_ca,true); }
  if (FLAGS_akamai_print_root_ca) { print_root_ca(db,false); }
  if (FLAGS_akamai_print_all_root_ca) { print_root_ca(db,true); }
  if (FLAGS_akamai_dump_root_ca != "empty") { dump_root_ca(db,false); }
  if (FLAGS_akamai_dump_all_root_ca != "empty") { dump_root_ca(db,true); }
  if (FLAGS_akamai_log_cert != "empty") { print_log_cert(db); }

  //These create certtables which owns db, so don't free again, just return
  if (FLAGS_akamai_dump_leaves != "empty") { 
    CertTables cert_tables(db,"id",NULL,NULL,NULL,&cnfg_data);
    dump_leaves(db,cert_tables,FLAGS_akamai_dump_leaves); return 1; 
  }
  if (FLAGS_akamai_read_leaves != "empty") { read_leaves(db,cnfg_data); return 1; }
  if (FLAGS_akamai_dump_pending != "empty") { 
    CertTables cert_tables(db,"id",NULL,NULL,NULL,&cnfg_data);
    dump_pending(cert_tables,FLAGS_akamai_dump_pending); return 1; 
  }
  if (FLAGS_akamai_read_pending != "empty") { read_pending(db,cnfg_data); return 1; }
  if (FLAGS_run_checkpointer) { check_point_loop(db,cnfg_data); return 1; }

  delete db;
  return 1;
}
