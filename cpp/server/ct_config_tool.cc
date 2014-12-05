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
DEFINE_string(akamai_db_preface,"","Preface when GET, PUT access DB");
DEFINE_string(akamai_db_serv,"443",
              "Port or service for DataBattery");
DEFINE_string(akamai_db_cert,"", "Cert to use when accessing DataBattery");
DEFINE_string(akamai_db_key,"", "Key to use when accessing DataBattery");
DEFINE_string(akamai_db_cert_dir,"","What directory to look in for DataBattery cert/key");
DEFINE_string(akamai_db_config_table,"pending","What table to get config from.");
DEFINE_string(akamai_db_config_key,"config","What key to retrieve from config_table");
DEFINE_string(akamai_input_file,"empty","File to read config from");
DEFINE_string(akamai_output_file,"empty","File to output config to.  If input_file==empty then we retrieve config from DB and print to this file.");
DEFINE_uint64(akamai_db_request_bytes,5242880,"size of DB max entry size");

using namespace std;
using namespace Akamai;

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  cert_trans::LoadCtExtensions();

  DataBattery::Settings db_settings(FLAGS_akamai_db_app,FLAGS_akamai_db_hostname,
  FLAGS_akamai_db_serv, FLAGS_akamai_db_cert, FLAGS_akamai_db_key,FLAGS_akamai_db_cert_dir,
  5,0,FLAGS_akamai_db_preface);
  DataBattery* db = new DataBattery(db_settings);
  CHECK(db->is_good()) << "Failed to create DataBattery instance for db";

  //Read in the input file and submit to DB
  ct::AkamaiConfig actmp;
  if (FLAGS_akamai_input_file != "empty") {
    std::ifstream ifs(FLAGS_akamai_input_file.c_str());
    if (ifs.fail()) {
      LOG(ERROR) << "Unable to open input file " << FLAGS_akamai_input_file;
      return 1;
    }
    google::protobuf::io::IstreamInputStream* ifo = 
      new google::protobuf::io::IstreamInputStream(&ifs);
    if (!google::protobuf::TextFormat::Parse(ifo,&actmp)) {
      LOG(ERROR) << "Failed to parse config file ";
      return 1;
    }
    delete ifo;
    ifs.close();

    string value;
    actmp.SerializeToString(&value);
    if (!db->PUT(FLAGS_akamai_db_config_table,FLAGS_akamai_db_config_key,value)) {
      LOG(ERROR) << "ERROR: Couldn't update config in DB";
      return 1;
    }
    LOG(INFO) << "Updated CONFIG in DB";
  }

  //Write out a check file.  Just a debug thing or to look at whats in DB already
  if (FLAGS_akamai_output_file != "empty") {
    //Retrieve DB entry if input file is not specified
    if (FLAGS_akamai_input_file == "empty") {
      string value;
      if (!db->GET_key_from_table(FLAGS_akamai_db_config_table,FLAGS_akamai_db_config_key,
            FLAGS_akamai_db_request_bytes,value)) {
        LOG(ERROR) << "Couldn't get config from DB";
      }
      actmp.ParseFromString(value);
    }
    std::ofstream ofs(FLAGS_akamai_output_file.c_str());
    google::protobuf::io::OstreamOutputStream* ofo = 
      new google::protobuf::io::OstreamOutputStream(&ofs);
    google::protobuf::TextFormat::Print(actmp,ofo);
    delete ofo;
    ofs.close();
  }

  return 0;
}

