/* -*- indent-tabs-mode: nil -*- */

#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/make_shared.hpp>
#include <boost/scoped_ptr.hpp>
#include <event2/thread.h>
#include <gflags/gflags.h>
#include <openssl/err.h>
#include <string>
#include <vector>

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
              "File for trusted CA certificates (reduced set), in concatenated PEM format");
DEFINE_string(trusted_cert_all_roots_file, "",
              "File for trusted CA certificates (full set), in concatenated PEM format");
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
DEFINE_string(akamai_config_file,"/a/app_metadata/ct_config","Where to get mdt delivered config");
DEFINE_string(akamai_static_config_file,"empty","Workaround for production until I get a proper ump channel.  It will read static config but overwrite it with the dynamic config given by akamai_config_file if present");
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

      void load_config() {
        //Before anything else, get the config
        //First see if you need to get static config
        bool got_static_config = read_config(FLAGS_akamai_static_config_file,&_cnfgd); 
        //Now fire up the thread looking for dynamic config
        _cnfgtd = new config_thread_data(FLAGS_akamai_config_file,&_cnfgd,
            got_static_config);
        CHECK(create_config_thread(_cnfgtd));
      }

      void init() 
      {
        _id = Peers::randByteString(16);
        LOG(INFO) << "New id " << _id;

        //Setup query
        query_interface::init(_cnfgd.tableprov_dir(),_id);
        query_interface::instance()->get_main_data()->_start_time = time(0);
        LOG(INFO) << "Set bucket_sets " << _cnfgd.bucket_sets().size() << " bucket_time " 
          << _cnfgd.bucket_time();
        query_interface::instance()->req_count_init(_id,_cnfgd.bucket_sets(),
            _cnfgd.bucket_time());

        //thread safety for openssl
        thread_setup();

        //First DB instance
        DataBattery::Settings db_settings(_cnfgd.db_app(),_cnfgd.db_hostname(),
            _cnfgd.db_serv(), _cnfgd.db_cert(), _cnfgd.db_key(), 
            _cnfgd.db_cert_dir(), _cnfgd.short_sleep(), _cnfgd.cert_check_delay(),
            _cnfgd.db_preface());
        DataBattery* ct_db = new DataBattery(db_settings);
        //DataBattery is owned and deleted by the object it's given to in all cases
        CHECK(ct_db->is_good()) << "Failed to create DataBattery instance for ct_db";
        _cert_tables = new CertTables(ct_db,_id,&_pd,&_ld,&_hbd,&_cnfgd);
        //Don't create a pending index if you don't allow submissions
        if (FLAGS_akamai_allow_cert_sub) { _cert_tables->init_pending_data(&_pd); }

        //Need to query databattery to get max size of a value in DB table and to get config, so borrow
        //  ct_db
        string value;
        CHECK(ct_db->GETLIMIT(_cnfgd.db_request_bytes(),value)) 
          << "Failed to get max value size from DB";
        uint64_t db_max_entry_size = atoi(value.c_str());
        _cnfgd.set_db_limit_max_entry_size(db_max_entry_size);
        LOG(INFO) << "Set db_max_entry_size " << _cnfgd.db_max_entry_size();

        //Also borrow it to load log cert into databattery if specified
        //Borrow ct_db to do the DataBattery stuff
        if (_cnfgd.log_cert() != "empty") { save_log_cert_to_db(ct_db); }

        //Create heartbeat thread if you allow submissions
        if (FLAGS_akamai_allow_cert_sub) {
          DataBattery* hd_db = new DataBattery(db_settings);
          CHECK(hd_db->is_good()) << "Failed to create DataBattery instance for hd_db";
          _hbtd = new heartbeat_thread_data(hd_db,_id,&_hbd,&_cnfgd);
          CHECK(create_heartbeat_thread(_hbtd));
        }
        //End of hearbeat thread
        
        //Create leaves thread data
        DataBattery* ld_db = new DataBattery(db_settings);
        CHECK(ld_db->is_good()) << "Failed to create DataBattery instance for ld_db";
        _ltd = new leaves_thread_data(ld_db,&_ld,&_cnfgd);  
        CHECK(create_leaves_thread(_ltd));
        //End of leaves thread
        
        //Create commit thread if you allow submissions
        if (FLAGS_akamai_allow_cert_sub) {
          DataBattery* cct_db = new DataBattery(db_settings);
          CHECK(cct_db->is_good()) << "Failed to create DataBattery instance for cct_db";
          _commit_cert_tables = new CertTables(cct_db,_id,&_pd,&_ld,&_hbd,&_cnfgd);
          _ctd = new commit_thread_data(_commit_cert_tables,&_cnfgd);
          CHECK(create_commit_thread(_ctd));
        }
        LOG(INFO) << "Completed intialization";
        //End of commit thread
      }

      void save_log_cert_to_db(DataBattery* db) {
        string log_cert_file = _cnfgd.log_cert_dir()+_cnfgd.log_cert();
        std::ifstream ifs(log_cert_file.c_str());
        if (ifs.fail()) {
          LOG(ERROR) << "Failed to open cert " << _cnfgd.log_cert();
          return;
        }
        string log_cert_pem;
        //Reserve adequate space in the string
        ifs.seekg(0, std::ios::end);
        log_cert_pem.reserve(ifs.tellg());
        ifs.seekg(0, std::ios::beg);
        //Now copy in the file
        log_cert_pem.assign((std::istreambuf_iterator<char>(ifs)),
                             std::istreambuf_iterator<char>());
        ifs.close();
        //Check that it's a valid cert
        cert_trans::Cert log_cert(log_cert_pem);
        if (!log_cert.IsLoaded()) {
          LOG(ERROR) << "Failed to load a valid cert " << _cnfgd.log_cert();
          return;
        }
        //Write it to DB
        CHECK(db->PUT(_cnfgd.db_pending(),_cnfgd.log_cert_db_key(),log_cert_pem));
        LOG(INFO) << "Wrote public cert to DB";
      }

      void get_roots_helper(string key, string filename, DataBattery& db) {
        string data;
        CHECK(db.GET_key_from_table(_cnfgd.db_root_table(),key,_cnfgd.db_max_entry_size(),
              data)) << "Failed to retrieve roots from DB";
        ct::X509Root roots; 
        CHECK(roots.ParseFromString(data)) << "Failed to parse roots from DB";
        std::ofstream ofs(filename.c_str());
        for (int i = 0; i < roots.roots_size(); ++i) {
          cert_trans::Cert* new_root = new cert_trans::Cert;
          new_root->LoadFromDerString(roots.roots(i));
          string pem_enc;
          new_root->PemEncoding(&pem_enc);
          ofs << pem_enc;
        }
        ofs.close();
      }

      void get_roots() {
        LOG(INFO) << "Get roots";
        DataBattery::Settings db_settings(_cnfgd.db_app(), _cnfgd.db_hostname(),
            _cnfgd.db_serv(), _cnfgd.db_cert(), _cnfgd.db_key(),
            _cnfgd.db_cert_dir(), _cnfgd.short_sleep(), _cnfgd.cert_check_delay(),
            _cnfgd.db_preface());
        DataBattery db(db_settings);
        CHECK(db.is_good()) << "Failed to create DataBattery instance for db";
        get_roots_helper(_cnfgd.db_root_key(),FLAGS_trusted_cert_file,db);
        get_roots_helper(_cnfgd.db_all_root_key(),FLAGS_trusted_cert_all_roots_file,db);
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
      void get_stats(ct_stats_data_def* t) const {
        t->_tree_size = _ld.get_leaves_count();
        t->_leaves_time = _ld.get_timestamp();
        t->_peers_time = _hbd.get_timestamp();
        if (_ctd) { t->_commit_time = _ctd->get_timestamp(); }
        t->_config_time = _cnfgd.get_timestamp();
      }
      string is_ok() const {
        uint64_t current_time = util::TimeInMilliseconds();
        uint64_t max_hb_age = 1000*(_hbd.get_timestamp() + _cnfgd.max_peer_age_suspension());
        if (current_time > max_hb_age) {
          LOG(INFO) << "Main: heartbeat hasn't been updated recently ct:" << current_time << " ha:" << max_hb_age;
          return "heartbeat_failure";
        }
        uint64_t max_leaves_age = 1000*(_ld.get_timestamp() + 2*_cnfgd.leaves_update_freq());
        if (current_time > max_leaves_age) {
          LOG(INFO) << "Main: leaves haven't been updated recently ct:" << current_time << " la:" << max_leaves_age;
          return "leaves_failure";
        }
        //Should always both be true or neither
        if (_ctd&&_commit_cert_tables) {
          uint64_t peer_delay = _commit_cert_tables->get_peer_order()*_cnfgd.commit_peer_delay();
          //Need to account for fixed commit delay as well as commit_peer_delay
          uint64_t max_commit_age = 1000*(_ctd->get_timestamp() + 2*(_cnfgd.commit_delay()+peer_delay));
          if (current_time > max_commit_age) {
            LOG(INFO) << "Main: commit hasn't been done recently ct:" << current_time << " ca:" << max_commit_age;
            return "commit_failure";
          }
        }
        return "ok";
      }
      void get_config_data(ct_config_data_def* d) {
        _cnfgd.gen_key_values(d->_config_key_value);
      }
      void get_auth_users(std::set<std::string>& auth_users) {
        auth_users = _cnfgd.auth_users();
      }
      void get_cert_info(ct_cert_info_data_def* d) {
        //Shared data struct, must lock
        _ld.lock();
        const ct::LoggedCertificatePBList& leaves = _ld.get_leaves();
        d->_info.clear();
        d->_info.resize(leaves.logged_certificate_pbs_size());
        for (int i = 0; i < leaves.logged_certificate_pbs_size(); ++i) {
          const ct::LoggedCertificatePB& lcpb = leaves.logged_certificate_pbs(i);
          cert_trans::Cert tmp;
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
  PeriodicCallback(const shared_ptr<libevent::Base>& base, 
                   const function<int()>& time_interval,
                   const function<void()>& callback)
      : base_(base),
        event_(*base_, -1, 0, bind(&PeriodicCallback::Go, this)),
        time_interval_(time_interval),
        callback_(callback) {
    event_.Add(time_interval_());
  }

 private:
  void Go() {
    callback_();
    event_.Add(time_interval_());
  }

  const shared_ptr<libevent::Base> base_;
  libevent::Event event_;
  const function<int()> time_interval_;
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

int SignMerkleTree_interval(Akamai::main_setup* main_data) {
  return main_data->get_config().tree_signing_freq();
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
  Akamai::query_interface::instance()->update_auth_users(main_data->get_config().auth_users());
  LOG(INFO) << "Query success";
  CHECK(Akamai::query_interface::instance()->update_tables());
}

int AkamaiQueryEvent_interval(Akamai::main_setup* main_data) {
  return main_data->get_config().query_freq();
}

void AkamaiHealthCheck(Akamai::main_setup* main_data) {
  LOG(INFO) << "Run health check";
  Akamai::query_interface::instance()->set_is_main_ok(main_data->is_ok());
}

int AkamaiHealthCheck_interval(Akamai::main_setup* main_data) {
  return main_data->get_config().health_check_freq();
}

int main(int argc, char* argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  cert_trans::LoadCtExtensions();

  string log_key = FLAGS_key;
  Akamai::main_setup* akamai(NULL);
  if (FLAGS_akamai_run) { 
    akamai = new Akamai::main_setup(); 
    akamai->load_config();
    log_key = akamai->get_config().log_cert_dir()+akamai->get_config().log_key();
  }

  EVP_PKEY *pkey = NULL;
  while (ReadPrivateKey(&pkey, log_key) != cert_trans::util::KEY_OK) {
    LOG(INFO) << "Have not received private key yet sleep";
    sleep(FLAGS_akamai_sleep);
  }
  LogSigner log_signer(pkey);

  if (FLAGS_akamai_run) {
    akamai->init();
    //Load roots from DB and write to the file read below.  Avoids changing any CT code in cert_checker.
    if (akamai->get_config().get_roots_from_db()) { akamai->get_roots(); }
  } 
  CertChecker checker;
  CHECK(checker.LoadTrustedCertificates(FLAGS_trusted_cert_file))
      << "Could not load reduced CA certs from " << FLAGS_trusted_cert_file;
  CertChecker checker_all_roots;
  CHECK(checker_all_roots.LoadTrustedCertificates(FLAGS_trusted_cert_all_roots_file))
      << "Could not load complete CA certs from " << FLAGS_trusted_cert_all_roots_file;

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

  Frontend frontend(new CertSubmissionHandler(&checker,&checker_all_roots),
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
  PeriodicCallback tree_event(event_base,
                              boost::bind(&SignMerkleTree_interval, akamai),
                              boost::bind(&SignMerkleTree, &tree_signer,
                                          &log_lookup, FLAGS_akamai_run));

  PeriodicCallback* akamai_query_event(NULL);
  PeriodicCallback* akamai_health_check_event(NULL);
  if (FLAGS_akamai_run) {
    LOG(INFO) << "Create akamai query event " << akamai->get_config().query_freq();
    akamai_query_event = new PeriodicCallback(
        event_base, boost::bind(&AkamaiQueryEvent_interval,akamai),
        boost::bind(&AkamaiQueryEvent,akamai,&log_lookup));
    LOG(INFO) << "Create akamai health check event " << akamai->get_config().health_check_freq();
    akamai_health_check_event = new PeriodicCallback(
        event_base, boost::bind(&AkamaiHealthCheck_interval,akamai),
        boost::bind(&AkamaiHealthCheck,akamai));
  }

  libevent::HttpServer server(*event_base);
  if (FLAGS_akamai_run) {
    handler.Add(&server,FLAGS_akamai_allow_audit, FLAGS_akamai_allow_cert_sub);
  } else {
    handler.Add(&server,true,true);
  }
  server.Bind(NULL, FLAGS_port);

  std::cout << "READY" << std::endl;

  event_base->Dispatch();
  if (akamai) { delete akamai; }
  if (akamai_query_event) { delete akamai_query_event; }
  if (akamai_health_check_event) { delete akamai_health_check_event; }

  return 0;
}
