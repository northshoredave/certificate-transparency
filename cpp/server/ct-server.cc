/* -*- indent-tabs-mode: nil -*- */

#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/make_shared.hpp>
#include <boost/scoped_ptr.hpp>
#include <event2/thread.h>
#include <gflags/gflags.h>
#include <openssl/err.h>
#include <string>

#include "log/cert_checker.h"
#include "log/cert_submission_handler.h"
#include "log/ct_extensions.h"
#include "log/file_db.h"
#include "log/file_storage.h"
#include "log/frontend.h"
#include "log/frontend_signer.h"
#include "log/log_lookup.h"
#include "log/log_signer.h"
#include "log/sqlite_db.h"
#include "log/databattery_db.h"
#include "log/tree_signer.h"
#include "server/handler.h"
#include "util/libevent_wrapper.h"
#include "util/read_private_key.h"
#include "util/thread_pool.h"
#include "log/data_battery.h"
#include "log/akamai-query.h"
#include "util/openssl_thread_locks.h"

DEFINE_string(server, "localhost", "Server host");
DEFINE_int32(port, 9999, "Server port");
DEFINE_string(key, "", "PEM-encoded server private key file");
DEFINE_string(trusted_cert_file, "",
              "File for trusted CA certificates, in concatenated PEM format");
DEFINE_string(cert_dir, "", "Storage directory for certificates");
DEFINE_string(tree_dir, "", "Storage directory for trees");
DEFINE_string(sqlite_db, "", "Database for certificate and tree storage");
// TODO(ekasper): sanity-check these against the directory structure.
DEFINE_int32(cert_storage_depth, 0,
             "Subdirectory depth for certificates; if the directory is not "
             "empty, must match the existing depth.");
DEFINE_int32(tree_storage_depth, 0,
             "Subdirectory depth for tree signatures; if the directory is not "
             "empty, must match the existing depth");
DEFINE_int32(log_stats_frequency_seconds, 3600,
             "Interval for logging summary statistics. Approximate: the "
             "server will log statistics if in the beginning of its select "
             "loop, at least this period has elapsed since the last log time. "
             "Must be greater than 0.");
DEFINE_int32(tree_signing_frequency_seconds, 600,
             "How often should we issue a new signed tree head. Approximate: "
             "the signer process will kick off if in the beginning of the "
             "server select loop, at least this period has elapsed since the "
             "last signing. Set this well below the MMD to ensure we sign in "
             "a timely manner. Must be greater than 0.");
DEFINE_bool(akamai_run,false,"Whether we should do akamai or not");
DEFINE_bool(akamai_get_roots_from_db,false,"Whether we should attempt to get ca roots from DB");
DEFINE_string(akamai_db_app,"ct",
             "App name used by databattery for CT");
DEFINE_string(akamai_db_hostname,"", "Hostname of DataBattery");
DEFINE_string(akamai_db_serv,"443",
              "Port or service for DataBattery");
DEFINE_string(akamai_db_cert,"", "Cert to use when accessing DataBattery");
DEFINE_string(akamai_db_key,"", "Key to use when accessing DataBattery");
DEFINE_string(akamai_db_request_bytes,"request_bytes","name of limit to get max entry value size");
DEFINE_string(akamai_db_config_table,"pending","What table to get config from.");
DEFINE_string(akamai_db_config_key,"config","What key to retrieve from config_table");
DEFINE_string(akamai_tableprov_dir,"query","What directory to write query tables in to get picked up by tabelprov");
DEFINE_bool(akamai_allow_cert_sub,true,"Whether to allow cert submission (is this a query only ct?)");
DEFINE_bool(akamai_allow_audit,true,"Whether to allow audit,proof queries?");
DEFINE_int32(akamai_sleep,5,"How long to sleep when key is missing before trying again");


namespace libevent = cert_trans::libevent;

using boost::bind;
using boost::function;
using boost::make_shared;
using boost::scoped_ptr;
using boost::shared_ptr;
using cert_trans::CertChecker;
using cert_trans::HttpHandler;
using cert_trans::LoggedCertificate;
using cert_trans::ThreadPool;
using cert_trans::util::ReadPrivateKey;
using google::RegisterFlagValidator;
using std::string;

namespace Akamai {
  class main_setup {
    public:
      main_setup() 
        : _cert_tables(NULL)
          , _commit_cert_tables(NULL)
          , _hbtd(NULL)
          , _ltd(NULL)
          , _ctd(NULL)
          , _cnfgtd(NULL)
      {}

      void init() 
      {
        _id = Peers::randByteString(16);
        LOG(INFO) << "New id " << _id;
        //Setup query
        query_interface::init(FLAGS_akamai_tableprov_dir,_id);
        query_interface::instance()->get_main_data()->_start_time = time(0);

        //thread safety for openssl
        thread_setup();
        
        //First DB instance
        DataBattery::Settings db_settings(FLAGS_akamai_db_app,FLAGS_akamai_db_hostname,
            FLAGS_akamai_db_serv, FLAGS_akamai_db_cert, FLAGS_akamai_db_key, FLAGS_akamai_sleep);
        DataBattery* cnfg_db = new DataBattery(db_settings);
        CHECK(cnfg_db->isGood()) << "Failed to create DataBattery instance for cnfg_db";
        //Need to query databattery to get max size of a value in DB table and to get config, so use cnfg_db before
        // giving it away
        string value;
        CHECK(cnfg_db->GETLIMIT(FLAGS_akamai_db_request_bytes,value)) << "Failed to get max value size from DB";
        uint64_t db_max_entry_size = atoi(value.c_str());
        if (_cnfgd.db_max_entry_size() != 0) {
          _cnfgd.set_db_max_entry_size(std::min(_cnfgd.db_max_entry_size(),db_max_entry_size));
        } else {
          _cnfgd.set_db_max_entry_size(db_max_entry_size);
        }
        LOG(INFO) << "Set db_max_entry_size " << _cnfgd.db_max_entry_size();

        //Now get the config
        _cnfgtd = new config_thread_data(cnfg_db,FLAGS_akamai_db_config_table,FLAGS_akamai_db_config_key,
            &_cnfgd);
        CHECK(create_config_thread(_cnfgtd));

        //Init some query stuff now that you have config
        LOG(INFO) << "Set bucket_sets " << _cnfgd.bucket_sets().size() << " bucket_time " << _cnfgd.bucket_time();
        query_interface::instance()->req_count_init(_id,_cnfgd.bucket_sets(),
            _cnfgd.bucket_time());

        //DataBattery is owned and deleted by the object it's given to in all cases
        DataBattery* ct_db = new DataBattery(db_settings);
        CHECK(ct_db->isGood()) << "Failed to create DataBattery instance for ct_db";
        _cert_tables = new CertTables(ct_db,_id,&_pd,&_ld,&_hbd,&_cnfgd);
        //Don't create a pending index if you don't allow submissions
        if (FLAGS_akamai_allow_cert_sub) { _cert_tables->init_pending_data(&_pd); }

        //Create heartbeat thread if you allow submissions
        if (FLAGS_akamai_allow_cert_sub) {
          DataBattery* hd_db = new DataBattery(db_settings);
          CHECK(hd_db->isGood()) << "Failed to create DataBattery instance for hd_db";
          _hbtd = new heartbeat_thread_data(hd_db,_id,&_hbd,&_cnfgd);
          CHECK(create_heartbeat_thread(_hbtd));
        }
        //End of hearbeat thread
        
        //Create leaves thread data but don't start until after SQLiteDB created
        DataBattery* ld_db = new DataBattery(db_settings);
        CHECK(ld_db->isGood()) << "Failed to create DataBattery instance for ld_db";
        _ltd = new leaves_thread_data(ld_db,&_ld,&_cnfgd);  
        CHECK(create_leaves_thread(_ltd));
        //End of leaves thread
        
        //Create commit thread if you allow submissions
        if (FLAGS_akamai_allow_cert_sub) {
          DataBattery* cct_db = new DataBattery(db_settings);
          CHECK(cct_db->isGood()) << "Failed to create DataBattery instance for cct_db";
          _commit_cert_tables = new CertTables(cct_db,_id,&_pd,&_ld,&_hbd,&_cnfgd);
          _ctd = new commit_thread_data(_commit_cert_tables,&_cnfgd);
          CHECK(create_commit_thread(_ctd));
        }
      }

      void get_roots() {
        LOG(INFO) << "Get roots";
        DataBattery::Settings db_settings(FLAGS_akamai_db_app,FLAGS_akamai_db_hostname,
            FLAGS_akamai_db_serv, FLAGS_akamai_db_cert, FLAGS_akamai_db_key,FLAGS_akamai_sleep);
        DataBattery db(db_settings);
        CHECK(db.isGood()) << "Failed to create DataBattery instance for db";
        string data;
        CHECK(db.GET_key_from_table(_cnfgd.db_root_table(),_cnfgd.db_root_key(),_cnfgd.db_max_entry_size(),
              data)) << "Failed to retrieve roots from DB";
        ct::X509Root roots; 
        CHECK(roots.ParseFromString(data)) << "Failed to parse roots from DB";
        std::ofstream ofs(FLAGS_trusted_cert_file.c_str());
        for (int i = 0; i < roots.roots_size(); ++i) {
          ct::Cert* new_root = new ct::Cert;
          new_root->LoadFromDerString(roots.roots(i));
          string pem_enc;
          new_root->PemEncoding(&pem_enc);
          ofs << pem_enc;
        }
        ofs.close();
      }

      ~main_setup() {
        thread_cleanup();
        if (_cert_tables) { delete _cert_tables; }
        if (_commit_cert_tables) { delete _commit_cert_tables; }
        if (_hbtd) { delete _hbtd; }
        if (_ltd) { delete _ltd; }
        if (_ctd) { delete _ctd; }
        if (_cnfgtd) { delete _cnfgtd; }
      }

      CertTables* get_cert_tables() { return _cert_tables; }
      const ConfigData& get_config() const { return _cnfgd; } 
      void get_stats(ct_stats_data_def* t) {
        t->_tree_size = _ld.get_leaves_count();
        t->_leaves_time = _ld.get_timestamp();
        t->_peers_time = _hbd.get_timestamp();
        if (_ctd) { t->_commit_time = _ctd->get_timestamp(); }
        t->_config_time = _cnfgd.get_timestamp();
      }
      void get_config_data(ct_config_data_def* d) {
        _cnfgd.gen_key_values(d->_config_key_value);
      }
      void get_cert_info(ct_cert_info_data_def* d) {
        //Shared data struct, must lock
        _ld.lock();
        const ct::LoggedCertificatePBList& leaves = _ld.get_leaves();
        d->_info.clear();
        d->_info.resize(leaves.logged_certificate_pbs_size());
        for (int i = 0; i < leaves.logged_certificate_pbs_size(); ++i) {
          const ct::LoggedCertificatePB& lcpb = leaves.logged_certificate_pbs(i);
          ct::Cert tmp;
          if (lcpb.contents().entry().type() == 0) { 
            tmp.LoadFromDerString(lcpb.contents().entry().x509_entry().leaf_certificate());
          } else {
            tmp.LoadFromDerString(lcpb.contents().entry().precert_entry().pre_certificate());
          }
          d->_info[i]._cert_type = (lcpb.contents().entry().type() == 0) ? "x509":"pre-cert";
          d->_info[i]._subject = tmp.PrintSubjectName();
          d->_info[i]._issuer = tmp.PrintIssuerName();
          d->_info[i]._not_before = tmp.PrintNotBefore();
          d->_info[i]._not_after = tmp.PrintNotAfter();
        }
        //Make sure to unlock shared data struct
        _ld.unlock();
      }
    private:
      ConfigData _cnfgd;
      PendingData _pd;
      LeavesData _ld;
      HeartBeatData _hbd;
      CertTables* _cert_tables;
      CertTables* _commit_cert_tables;
      heartbeat_thread_data* _hbtd;
      leaves_thread_data* _ltd;
      commit_thread_data* _ctd;
      config_thread_data* _cnfgtd;
      string _id;
  };
}

static const int kCtimeBufSize = 26;

// Basic sanity checks on flag values.
static bool ValidatePort(const char* flagname, int port) {
  if (port <= 0 || port > 65535) {
    std::cout << "Port value " << port << " is invalid. " << std::endl;
    return false;
  }
  return true;
}

static const bool port_dummy =
    RegisterFlagValidator(&FLAGS_port, &ValidatePort);

static bool ValidateRead(const char* flagname, const string& path) {
  if (access(path.c_str(), R_OK) != 0) {
    std::cout << "Cannot access " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static const bool cert_dummy =
    RegisterFlagValidator(&FLAGS_trusted_cert_file, &ValidateRead);

static bool ValidateWrite(const char* flagname, const string& path) {
  if (path != "" && access(path.c_str(), W_OK) != 0) {
    std::cout << "Cannot modify " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static const bool cert_dir_dummy =
    RegisterFlagValidator(&FLAGS_cert_dir, &ValidateWrite);

static const bool tree_dir_dummy =
    RegisterFlagValidator(&FLAGS_tree_dir, &ValidateWrite);

static bool ValidateIsNonNegative(const char* flagname, int value) {
  if (value < 0) {
    std::cout << flagname << " must not be negative" << std::endl;
    return false;
  }
  return true;
}

static const bool c_st_dummy =
    RegisterFlagValidator(&FLAGS_cert_storage_depth, &ValidateIsNonNegative);
static const bool t_st_dummy =
    RegisterFlagValidator(&FLAGS_tree_storage_depth, &ValidateIsNonNegative);

static bool ValidateIsPositive(const char* flagname, int value) {
  if (value <= 0) {
    std::cout << flagname << " must be greater than 0" << std::endl;
    return false;
  }
  return true;
}

static const bool stats_dummy =
    RegisterFlagValidator(&FLAGS_log_stats_frequency_seconds,
                          &ValidateIsPositive);

static const bool sign_dummy =
    RegisterFlagValidator(&FLAGS_tree_signing_frequency_seconds,
                          &ValidateIsPositive);

// Hooks a repeating timer on the event loop to call a callback. It
// will wait "interval_secs" between calls to "callback" (so this
// means that if "callback" takes some time, it will run less
// frequently).
class PeriodicCallback {
 public:
  PeriodicCallback(const shared_ptr<libevent::Base>& base, int interval_secs,
                   const function<void()>& callback)
      : base_(base),
        interval_secs_(interval_secs),
        event_(*base_, -1, 0, bind(&PeriodicCallback::Go, this)),
        callback_(callback) {
    event_.Add(interval_secs_);
  }

 private:
  void Go() {
    callback_();
    event_.Add(interval_secs_);
  }

  const shared_ptr<libevent::Base> base_;
  const int interval_secs_;
  libevent::Event event_;
  const function<void()> callback_;

  DISALLOW_COPY_AND_ASSIGN(PeriodicCallback);
};

void SignMerkleTree(TreeSigner<LoggedCertificate> *tree_signer,
                    LogLookup<LoggedCertificate> *log_lookup,
                    bool akamai_run) {
  CHECK_EQ(tree_signer->UpdateTree(akamai_run),
           TreeSigner<LoggedCertificate>::OK);
  CHECK_EQ(log_lookup->Update(), LogLookup<LoggedCertificate>::UPDATE_OK);

  const time_t last_update(
      static_cast<time_t>(tree_signer->LastUpdateTime() / 1000));
  char buf[kCtimeBufSize];
  LOG(INFO) << "Tree successfully updated at " << ctime_r(&last_update, buf);
}

void AkamaiQueryEvent(Akamai::main_setup* main_data,
                      LogLookup<LoggedCertificate> *log_lookup) {
  LOG(INFO) << "Query event";
  const ct::SignedTreeHead &sth = log_lookup->GetSTH();
  Akamai::query_interface::instance()->get_main_data()->_root_hash =
    util::ToBase64(sth.sha256_root_hash());
  main_data->get_stats(Akamai::query_interface::instance()->get_stats_data());
  if (main_data->get_config().publish_cert_info()) {
    main_data->get_cert_info(Akamai::query_interface::instance()->get_cert_info_data());
  }
  main_data->get_config_data(Akamai::query_interface::instance()->get_config_data());
  LOG(INFO) << "Query success";
  CHECK(Akamai::query_interface::instance()->update_tables());
}

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  cert_trans::LoadCtExtensions();

  EVP_PKEY *pkey = NULL;
  while (ReadPrivateKey(&pkey, FLAGS_key) != cert_trans::util::KEY_OK) {
    LOG(INFO) << "Have not received private key yet sleep";
    sleep(FLAGS_akamai_sleep);
  }
  LogSigner log_signer(pkey);

  Akamai::main_setup* akamai(NULL);
  if (FLAGS_akamai_run) { 
    akamai = new Akamai::main_setup(); 
    akamai->init();
  }
  if (FLAGS_akamai_run&&FLAGS_akamai_get_roots_from_db) {
    //Load roots from DB and write to the file read below.  Avoids changing any CT code in cert_checker.
    akamai->get_roots();
  } 
  CertChecker checker;
  CHECK(checker.LoadTrustedCertificates(FLAGS_trusted_cert_file))
      << "Could not load CA certs from " << FLAGS_trusted_cert_file;

  if (FLAGS_sqlite_db == "")
    CHECK_NE(FLAGS_cert_dir, FLAGS_tree_dir)
        << "Certificate directory and tree directory must differ";

  if ((FLAGS_cert_dir != "" || FLAGS_tree_dir != "") &&
      FLAGS_sqlite_db != "") {
    std::cerr << "Choose either file or sqlite database, not both"
              << std::endl;
    exit(1);
  }

  Database<LoggedCertificate>* db;

  if (FLAGS_sqlite_db != "") {
    if (FLAGS_akamai_run) {
      db = new Akamai::DataBatteryDB<LoggedCertificate,
                                     ct::LoggedCertificatePBList>(
          FLAGS_sqlite_db, akamai->get_cert_tables());
    } else {
      db = new SQLiteDB<LoggedCertificate>(FLAGS_sqlite_db);
    }
  } else {
      db = new FileDB<LoggedCertificate>(
               new FileStorage(FLAGS_cert_dir, FLAGS_cert_storage_depth),
               new FileStorage(FLAGS_tree_dir, FLAGS_tree_storage_depth));
  }

  evthread_use_pthreads();
  const shared_ptr<libevent::Base> event_base(make_shared<libevent::Base>());

  Frontend frontend(new CertSubmissionHandler(&checker),
                    new FrontendSigner(db, &log_signer));
  TreeSigner<LoggedCertificate> tree_signer(db, &log_signer);
  LogLookup<LoggedCertificate> log_lookup(db);

  // This function is called "sign", but it also loads the LogLookup
  // object from the database as a side-effect.
  SignMerkleTree(&tree_signer, &log_lookup,FLAGS_akamai_run);

  const time_t last_update(
      static_cast<time_t>(tree_signer.LastUpdateTime() / 1000));
  if (last_update > 0) {
    char buf[kCtimeBufSize];
    LOG(INFO) << "Last tree update was at " << ctime_r(&last_update, buf);
  }

  ThreadPool pool;
  HttpHandler handler(&log_lookup, db, &checker, &frontend, &pool);

  LOG(INFO) << "Create tree signing event "
            << FLAGS_tree_signing_frequency_seconds;
  PeriodicCallback tree_event(event_base, FLAGS_tree_signing_frequency_seconds,
                              boost::bind(&SignMerkleTree, &tree_signer,
                                          &log_lookup, FLAGS_akamai_run));

  PeriodicCallback* akamai_query_event(NULL);
  if (FLAGS_akamai_run) {
    LOG(INFO) << "Create akamai query event " << akamai->get_config().query_freq();
    akamai_query_event = new PeriodicCallback(
        event_base, akamai->get_config().query_freq(), 
        boost::bind(&AkamaiQueryEvent,akamai,&log_lookup));
  }

  libevent::HttpServer server(*event_base);
  if (FLAGS_akamai_run) {
    handler.Add(&server,FLAGS_akamai_allow_audit,FLAGS_akamai_allow_cert_sub);
  } else {
    handler.Add(&server,true,true);
  }
  server.Bind(NULL, FLAGS_port);

  std::cout << "READY" << std::endl;

  event_base->Dispatch();
  if (akamai) { delete akamai; }
  if (akamai_query_event) { delete akamai_query_event; }

  return 0;
}
