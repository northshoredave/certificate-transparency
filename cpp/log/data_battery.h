#ifndef DATA_BATTERY_H
#define DATA_BATTERY_H

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <proto/ct.pb.h>
#include "util/util.h"
#include <string>
#include <map>
#include <vector>
#include <set>

namespace Akamai {
  /* Purpose of this class is to parse the returned header from a http call. *
   *  We're using http 1.0 at this point, so we don't pay much attention to the *
   * options returned in the header, but the process_option method may be 
   * completed if it becomes useful.  Right now we just look for the status 
   *   success:  value expected for a successfull call to DB. GET is 200 for example. 
   */
  class ScanHeader {
    public:
      ScanHeader(int success)
        : _success(success) 
        , _processedHeader(false)
        , _foundStatus(false)
        , _status(0)
        , _state(0)
    {}
      bool scan(char* recvline, int n, char** start, int& len) {
        *start = recvline; len = n;
        //Once you've processed the header, just return the retrieved data
        if (_processedHeader) { return true; }
        //Attempt to process the header
        if (!process_header(n,start,len)) { return false; }
        return true;
      }
      bool get_found_status() const { return _foundStatus; }
      int get_status() const { return _status; }
      bool finished_header() const { return _processedHeader; }
    private:
      bool process_line(std::string line) {
        if (!_foundStatus) { return process_status(line); }
        return process_option(line);
      }
      bool process_status(std::string line);
      bool process_option(std::string line) { return true; }
      bool process_header(int n, char** start, int& len);

    private:
      int _success;
      bool _processedHeader;
      bool _foundStatus;
      int _status;
      int _state;
      std::string _line;
  };

  /*DB doesn't provide a secondary index for tables, just key/value pairs.  As such we must maintain our
   * index for packing data into a given value and for determining what all the keys are for the table if 
   * we should need to retrieve the complete table.  This is the class for doing that bookeeping.
   *    It's optimized for our specific purpose.  That being:
   *       1) We will never modify a full (key,value) pair.
   *       2) New additions always occur in the last (key,value) pair if it has sufficient space, or a new 
   *          (key,value) otherwise.  We never back fill even if we could fit in an earlier (key,value) that 
   *          still has some space.
   *       3) Keys are a simple monotonically increasing number i.e (first_key=0,1,2,3,...,last_key).  
   *       4) We will keep both first and last key, so that table reduction can be done without modifying the
   *       indexes (i.e. reducing pending table after some entries have been added to leaves).  All keys can be 
   *       generated using these two values since the key are always just the sequential integers between first 
   *       and last.
   *
   *Index is a protobuf message which can be serialized into a string for storage in DataBattery table.  See
   *  proto/ct.proto for DataBatteryIndex for member data.
   */

  class DBIndex {
    public:
      DBIndex() {
        set_first_key(0);
        set_last_key(0);
      }
        
      //Protobuf calls
      bool parse_from_string(std::string data) { return _dbIndex.ParseFromString(data); }
      bool serialize_to_string(std::string* data) const { return _dbIndex.SerializeToString(data); }
      //Simply return all integers as strings between first and last as keys
      void get_all_keys_from_key(uint64_t key, std::vector<std::string>& keys) const {
        if (key < first_key()) { generate_keys(first_key(),last_key(),keys); }
        else { generate_keys(key,last_key(),keys); }
      }
      //Return all integers between first and last as strings with prefix appended
      void get_all_keys(std::string prefix, std::vector<std::string>& keys) const {
        std::string tmp = prefix+std::string("."); generate_keys(tmp,first_key(),last_key(),keys); 
      }
      void get_all_keys_from_zero(std::string prefix, std::vector<std::string>& keys) const {
        std::string tmp = prefix+std::string("."); generate_keys(tmp,0,last_key(),keys);
      }
      //Same as get_all_keys, but starting from a given key instead of first_key
      void get_all_keys_from_key(std::string prefix, uint64_t key, std::vector<std::string>& keys) const {
        std::string tmp = prefix+std::string(".");
        if (key < first_key()) { generate_keys(tmp,first_key(),last_key(),keys); }
        else { generate_keys(tmp, key, last_key(),keys); }
      }
      //Get the last key of the index.  Use existing generate_keys call to do it.
      void get_last_key(std::string& key) const { 
        std::vector<std::string> keys;
        generate_keys(last_key(),last_key(),keys); 
        key = keys.front();
      }
      void get_last_key(std::string prefix, std::string& key) const {
        get_last_key(key);
        key = prefix+std::string(".")+key;
      }
      //Simply update the timestamp with the current time
      inline void update_timestamp() { _dbIndex.set_last_update(util::TimeInMilliseconds()); }
      //Expose get and set methods from protobuf message
      uint64_t last_update() const { return _dbIndex.last_update(); }
      uint64_t last_key() const { return _dbIndex.last_key(); }
      void set_last_key(uint64_t k) { _dbIndex.set_last_key(k); }
      uint64_t first_key() const { return _dbIndex.first_key(); }
      void set_first_key(uint64_t k) { _dbIndex.set_first_key(k); }
      std::string add_key();
      //Used in testing, define an equality operator
      bool operator==(const DBIndex& x) const {
        return (last_update() == x.last_update()) &&
          (last_key() == x.last_key()) &&
          (first_key() == x.first_key());
      }
      const ct::DataBatteryIndex& get_msg() const { return _dbIndex; }

    private:
      //Includes all key between from and to including both from and to
      void generate_keys(uint64_t from, uint64_t to, std::vector<std::string>& keys) const;
      //Same as above, but add prefix to key
      void generate_keys(std::string prefix, uint64_t from, uint64_t to, std::vector<std::string>& keys) const;
      //Just generate a the string representation of key
      std::string generate_key(uint64_t key) const;

    private:
      ct::DataBatteryIndex _dbIndex;
  };

  /* DataBattery class is to encapsulate the low level calls to DataBattery including the underlying ssl 
   * connection, etc.
   *   app:  name of DataBattery app (probably ct)
   *   host: hostname for DB
   *   serv: service or port to contact DB on
   *   cert: cert to use when talking to databattery
   *   key:  private key to use when talking to databattery
   * Using the seperate settings class so that I can pass the same settings into multiple instances of DataBattery
   * and be sure I got them the same.  Easier to have multiple DB instances and rely on openSSL locking, then
   * make all this code be thread safe.
   */
  class DataBattery {
    public:
      struct Settings {
        Settings(std::string app, std::string host, std::string serv, std::string cert, 
            std::string pvkey, uint32_t key_sleep, uint32_t cert_key_check_delay,std::string preface)
          : _app(app) , _host(host) , _serv(serv) , _cert(cert) , _pvkey(pvkey), _preface(preface)
          , _key_sleep(key_sleep), _cert_key_check_delay(cert_key_check_delay)
        {}
        std::string _app, _host, _serv, _cert, _pvkey, _preface;
        uint32_t _key_sleep, _cert_key_check_delay;
      };
    public:
      DataBattery(const Settings& settings);
      ~DataBattery() {
        if (_ctx) { SSL_CTX_free(_ctx); _ctx = NULL; }
      }
      
      //check to see if DataBattery was built properly
      bool is_good() const { return _ctx!=NULL; }

      //Get the index for the given table.  Modifying the index doesn't take effect on the db table until you
      //commit it using putIndex
      bool get_index(std::string table, std::string index_key, DBIndex& index);
      //Commit the given index to the table
      bool put_index(std::string table, std::string index_key, const DBIndex& index);

      //Retrieve entries from a table
      //Return is a vector of values.  
      // Since the key is simply an internal artifact of the table it's not returned as well.
      bool GET_keys_from_table(std::string table,const std::vector<std::string>& keys, uint64_t max_entry_size,
          std::vector<std::string>& data);

      //Get single key data from table
      bool GET_key_from_table(std::string table, std::string key, uint64_t max_entry_size, std::string& data);

      //Basic GET and PUT calls to DB.  Provide table name, key and value.
      virtual bool GET(std::string table, std::string key, std::string& value);
      virtual bool PUT(std::string table, std::string key, std::string value);
      virtual bool DELETE(std::string table, std::string key);
      //Get a limit on table
      virtual bool GETLIMIT(std::string limit, std::string& value);

      int get_error_status() const { return _status; }
      void set_status(int s) { _status = s; }
      
      static int get_maxline() { return _maxline; }

    private:
      bool METHOD(std::string msg, bool returnOnSuccess, std::string& value, uint successCode);
      int tcp_connect();
      SSL* ssl_connect();
      void disconnect(SSL* ssl);
      bool check_context();

    private:
      Settings _settings;
      SSL_CTX* _ctx;
      time_t _last_cert; //Timestamp of last cert read. Used to check if new cert has arrived
      time_t _last_key; //Timestamp of last cert read. Used to check if new cert has arrived
      time_t _last_cert_check; //Last time you checked if cert had changed
      int _status; //Set when an error occurs with a GET or PUT
      static bool _loadlibraries; //Libraries only needed to be loaded once, do so when first DataBattery built
      static int _maxline;
  };

  class Timestamp {
    public:
      Timestamp() 
        : _timestamp(0)
      {
        pthread_mutex_init(&_mutex,NULL);
      }
      void update_time() {
        uint64_t current_time = time(0);
        pthread_mutex_lock(&_mutex);
        _timestamp = current_time;
        pthread_mutex_unlock(&_mutex);
      }
      uint64_t get_timestamp() const {
        uint64_t time;
        pthread_mutex_lock(&_mutex);
        time = _timestamp;
        pthread_mutex_unlock(&_mutex);
        return time;
      }

      mutable pthread_mutex_t _mutex;
    private:
      time_t _timestamp;
  };

  class ConfigData:public Timestamp {
    public:
      ConfigData() {}
      ConfigData(ct::AkamaiConfig& c)
        : Timestamp() 
        , _config(c)
        , _db_limit_max_entry_size(5242880)
      { }
      void gen_key_values(std::vector<std::pair<std::string, std::string> >& kv_pairs) const;
      bool parse_from_string(std::string value) {
        bool ret(false);
        pthread_mutex_lock(&_mutex);
        ret = _config.ParseFromString(value);
        pthread_mutex_unlock(&_mutex);
        return ret;
      }
#define getLockMutex(f,t) \
      t ret; \
      pthread_mutex_lock(&_mutex); \
      ret = f(); \
      pthread_mutex_unlock(&_mutex); \
      return ret
#define setLockMutex(f) \
      pthread_mutex_lock(&_mutex); \
      f; \
      pthread_mutex_unlock(&_mutex)
#define getVLockMutex(f,t) \
      std::vector<t> ret; \
      pthread_mutex_lock(&_mutex); \
      for (int i = 0; i < f ## _size(); ++i) { \
        ret.push_back(f(i)); \
      } \
      pthread_mutex_unlock(&_mutex); \
      return ret

      //db_max_entry_size is more complicated because I want to take the minimum of the config and the db 
      //  specified limit (unless config max is 0, in which case use db max)
      uint64_t db_max_entry_size() const { 
        pthread_mutex_lock(&_mutex);
        uint64_t cnfg_max = _config.db_max_entry_size();
        pthread_mutex_unlock(&_mutex);
        if (cnfg_max == 0 || _db_limit_max_entry_size < cnfg_max) { return _db_limit_max_entry_size; }
        else { return cnfg_max; }
      }
      void set_db_limit_max_entry_size(uint64_t v) { _db_limit_max_entry_size = v; }
      std::string db_leaves() const { getLockMutex(_config.db_leaves,std::string); }
      std::string db_pending() const { getLockMutex(_config.db_pending,std::string); }
      std::string db_root_table() const { getLockMutex(_config.db_root_table,std::string); }
      std::string db_root_key() const { getLockMutex(_config.db_root_key,std::string); }
      uint64_t fixed_peer_delay() const { getLockMutex(_config.fixed_peer_delay,uint64_t); }
      uint64_t random_peer_delay() const { getLockMutex(_config.random_peer_delay,uint64_t); } 
      uint64_t max_peer_age() const { getLockMutex(_config.max_peer_age,uint64_t); } 
      uint64_t heartbeat_freq() const { getLockMutex(_config.heartbeat_freq,uint64_t); } 
      uint64_t leaves_update_freq() const { getLockMutex(_config.leaves_update_freq,uint64_t); } 
      uint64_t cert_min_age() const { getLockMutex(_config.cert_min_age,uint64_t); } 
      uint64_t commit_delay() const { getLockMutex(_config.commit_delay,uint64_t); } 
      uint64_t commit_peer_delay() const { getLockMutex(_config.commit_peer_delay,uint64_t); } 
      uint64_t config_delay() const { getLockMutex(_config.config_delay,uint64_t); }
      uint64_t short_sleep() const { getLockMutex(_config.short_sleep,uint64_t); }
      uint32_t query_freq() const { getLockMutex(_config.query_freq,uint32_t); }
      uint32_t bucket_time() const { getLockMutex(_config.bucket_time,uint32_t); } 
      std::vector<uint32_t> bucket_sets() const { getVLockMutex(_config.bucket_sets,uint32_t); }
      bool publish_cert_info() const { getLockMutex(_config.publish_cert_info,bool); }
      
    private:
      ct::AkamaiConfig _config;
      uint64_t _db_limit_max_entry_size; //Size limit of an entry in DB table as given by table limits
  };

  /*  Peers class is to codify the management of the peers entry in the pending table.  
   *    Each peer is stored with a timestamp that identifys when the peer last updated.  Sufficiently old
   *  timestamps will cause the peer to be removed.
   *    Peers are used to identify all of the virtual pending tables to look at to gather up pending
   *  certs that need to be committed.  Peers are removed periodically simply for efficiency since each
   *  peer represents another lookup that the committer must do to get it's pending certs.
   *
   *  static uint _fixed_peer_delay: A fixed interval in seconds to wait before checking if your update stuck
   *     in the peers in DataBattery
   *  static uint _random_peer_delay: An additional random delay in seconds that is added to the fixed delay to
   *     wait before checking if peers got updated in DataBattery
   *  static uint _max_age: In milliseconds (set converts seconds to milliseconds) before peer is removed.
   *
   *    DataBatteryPeers is a google protobuf.  Look at proto/ct.proto for class definition and member data.
   */

  class Peers {
    public:
      Peers(uint fixed_peer_delay, uint random_peer_delay, uint max_age) 
        : _fixed_peer_delay(fixed_peer_delay)
        , _random_peer_delay(random_peer_delay)
        , _max_age(max_age*1000)
      {}
      //Protobuf calls
      bool parse_from_string(std::string data) { return _peers.ParseFromString(data); }
      bool serialize_to_string(std::string* data) const { return _peers.SerializeToString(data); }
      //Extract out all the ids of the peers and return as set of strings
      void get_peer_set(std::set<std::string>& peers) const;
      void get_removed_peer_set(std::set<std::string>& peers,uint age) const;
      //Remove peers whose timestamp is older then max_age from current time
      void remove_dead_peers(uint64_t max_age);
      //Update the timstamp of the given ID with timestamp, add ID to peers if it isn't present 
      void update_timestamp(std::string id,uint64_t timestamp);
      //Check if the (id,timestamp) is present in the peers
      bool find(std::string id, uint64_t timestamp) const;
      //Find what your order is in the list of peers
      int get_order(std::string id) const;

      //Methods for interacting with DB
      //This is the method for adding a peer or updating it's timestamp in DB.  It also removes dead peers.
      //  The update does add, wait for random interval, check if entry is present, if not loop, else done.
      bool update_peer(std::string id, DataBattery* db, std::string tablename);

      virtual bool GET(DataBattery* db, std::string tablename);
      bool PUT(DataBattery* db, std::string tablename) const;
      //End of methods that actually update DB
      
      const ct::DataBatteryPeers& get_msg() const { return _peers; }
      //Small utility to generate unique peer ids using openssl RAND_pseudo_bytes
      static std::string randByteString(int length);

      //Clear removed peers
      void clear_removed_peers(const std::set<std::string>& removed_peer_set);
    private:
      virtual uint64_t get_time() const { return util::TimeInMilliseconds(); } 
    private:
      ct::DataBatteryPeers _peers;
      uint _fixed_peer_delay; //In seconds 
      uint _random_peer_delay; //In seconds
      uint _max_age; //In milliseconds (set converts seconds to milliseconds)
  };

  //Need to expose when the last successfull heartbeat occured so that we can stop accepting new pending
  //  certs before we might get booted out of peers
  //Protect timestamp with mutex since it can be updated and read from 2 different threads.
  struct HeartBeatData:public Timestamp {
  };

  //Small struct to gather together the last pending value information that needs to be protected by a mutex
  //  and shared between threads.
  //Note that only _pending_index is modified in multiple threads.  _last_pending_value is not and code does
  //  not currently set mutex when accessing.
  struct PendingData {
    PendingData() {
      pthread_mutex_init(&_mutex,NULL);
    }
    ct::LoggedCertificatePBList _last_pending_value;
    DBIndex _pending_index;
    pthread_mutex_t _mutex;
  };

  //Small struct to gather together the DB leaves information that needs to be protected by a mutex and shared
  //  between threads
  class LeavesData:public Timestamp {
    public:
      uint get_leaves_count() const {
        uint count;
        pthread_mutex_lock(&_mutex);
        count = _leaves.logged_certificate_pbs_size();
        pthread_mutex_unlock(&_mutex);
        return count;
      }
      void lock() { pthread_mutex_lock(&_mutex); }
      void unlock() { pthread_mutex_unlock(&_mutex); }
      const ct::LoggedCertificatePBList& get_leaves() const { return _leaves; }

    public:
      std::set<std::string> _leaves_hash; //Kept around so we can check if we've already retrieved a leaf
      ct::LoggedCertificatePBList _leaves;
  };

  /*Class for interacting with leaf and pending table in terms of LoggedCertificatePB(List) 
   *  db:                  DataBattery instance for doing low level communication with DataBattery service
   *  leaves_table_name:   Name of the DB table in which to store committed certs
   *  pending_table_name:  Name of the DB table in which to store pending certs.  Note that this is the 
   *                       DB table name, not the name of the virtual pending tables.
   *  max_entry_size:      The maximum size in bytes that a single key value can have in DB. Note that increasing
   *                       this for already closed (key,value) pairs does not mean we will store more in these
   *                       keys.  All tables are append only.
   *ct::LoggedCertificatePB is the core protobuf class used by google CT to store the cert chains and SCT.
   *ct::LoggedCertificatePBList is a protobuf class that simply contains a list of LoggedCertificatePB that was
   *  added by Akamai to pack a particular (key,value).  
   */
  class CertTables {
    public:
      CertTables(DataBattery* db, std::string my_id, PendingData* pd,
          LeavesData* ld,HeartBeatData* hbd, ConfigData* cnfgd);
      ~CertTables()
      {
        if (_db) { delete _db; _db = NULL; }
      }
      //Retrieve all the committed certs in the leaves table
      //  from_key: only retrieve entries containing from_key or above
      //  table_name: which DB table to retrieve values from
      //  max_entry_size: max size of a DB value.  Lets us pre-size things
      //  lcpbl:  Where to store all the retrieved leafs
      //  last_key: What was the last key that we retrieved, so that next time we know which index to start
      //    retrieving new leaves from
      static bool get_all_leaves(uint64_t from_key, std::string table_name,uint64_t max_entry_size,
          DataBattery* db, ct::LoggedCertificatePBList& lcpbl, uint64_t& last_key);

      //Add a pending cert to the pending table under the virtual table given by _my_id
      bool pending_add(const ct::LoggedCertificatePB* lcpb);

      //Commit the pending certs for all peers (including myself) that are within the desired time min_age
      bool commit_pending(uint64_t min_age, uint64_t commit_delay);

      //Doesn't actually clear the pending table.  It just updates the first_key of each peer index to denote
      //  where to start looking for pending certs.  We could actually delete keys out of the table, but I like
      //  maintaining the append only, never delete property.  
      void clear_pending(const std::set<std::string>& leaves_hash);

      std::string get_leaves_table_name() const { return _cnfgd->db_leaves(); }
      std::string get_pending_table_name() const { return _cnfgd->db_pending(); }
      std::string get_my_id() const { return _my_id; }
      void set_my_id(std::string id) { _my_id = id; }
      //Mutex protected data that we need to access for the get_all_leaves,pending_add,commit_pending and 
      //  clear_pending
      DataBattery* get_db() const { return _db; }
      PendingData* get_pd() const { return _pd; }
      LeavesData* get_ld() const { return _ld; }
      HeartBeatData* get_hdb() const { return _hbd; }
      ConfigData* get_cfngd() const { return _cnfgd; }

      uint64_t get_max_entry_size() const { return _cnfgd->db_max_entry_size(); }
      //Return what order you are in the list of peers
      int get_peer_order();
      //Get the current pending index and the last value in your virtual pending table.  We use this to minimize 
      //  how many DB calls we need to make when doing a pending_add.  If the new data fits in the current 
      //  value, all we have to commit is the value.  No GETs are required.  If the value can't fit and we 
      //  need to add a new key, then we commit both value and index.
      void init_pending_data(PendingData* pd);

    private:
      //Retrieve the peers
      bool get_peers(Peers& p) { return p.GET(get_db(),get_pending_table_name()); }
      //Puts the peers back in the appropriate key and table
      bool put_peers(const Peers& p) { return p.PUT(get_db(),get_pending_table_name()); }
      //Get the pending keys of a particular peer.  I.e. the id.<int> keys
      bool get_pending_peer_keys(std::string peer, std::vector<std::string>& keys);
      //Get the data for a single key (which may be a number of certs)
      bool get_key_data(std::string table, std::string key, ct::LoggedCertificatePBList& lcpbl);
      //Get and put the pending index for a given peer
      bool get_pending_index(std::string id,DBIndex& index); 
      bool put_pending_index(std::string id,const DBIndex& index);
      //Get and put the leaves table index.  Only one index in this table
      bool get_leaves_index(DBIndex& index) { return _db->get_index(get_leaves_table_name(),"index",index); } 
      bool put_leaves_index(DBIndex& index) { return _db->put_index(get_leaves_table_name(),"index",index); }
      //Get the open key, or last key (same thing). 
      bool get_last_leaves(DBIndex& index, ct::LoggedCertificatePBList& list,std::string& last_key);
      //Retrieve the timestamp of the very last committed cert and the sequence id that was assigned to it
      bool get_last_committed(uint64_t& last_committed_timestamp,uint64_t& sequence_id,
          uint64_t& last_updated_timestamp); 
      //Once you've figure out what pending certs to commit, this is the call that actually adds them to the leaves
      //  table
      bool add_leaves(ct::LoggedCertificatePBList& lcpbl, uint commit_delay);

    private:
      DataBattery* _db;
      std::string _my_id;
      PendingData* _pd;
      LeavesData* _ld;
      HeartBeatData* _hbd;
      ConfigData* _cnfgd;
  };

  /* Config thread has  single responsibility to look for new config in DataBattery in the given table+key.
   * It does so ever so often, and then updates the config after having gotten the value from DB.  At the time
   * of update it must lock.
   *   The thread is the only one who can update config.  Everyone else is read only
   */
  struct config_thread_data {
    config_thread_data(DataBattery* db, std::string table, std::string key, ConfigData* cd) 
      : _db(db), _table(table), _key(key), _cd(cd)
    {}
    ~config_thread_data() {
      if (_db) { delete _db; }
    }
    DataBattery* _db;
    std::string _table;
    std::string _key;
    uint64_t _max_entry_size;
    ConfigData* _cd;
  };
  bool create_config_thread(config_thread_data* cnfgtd);

  /* HeartBeat thread has a single responsibility which is to update the peers.  Specifically it will:
   *   1) Update the timestamp for it's id
   *   2) Remove any dead peers
   *
   * Since there may be multiple writers, we will confirm that our entry was successfully adopted by committing
   * our view of the peers, waiting a random amount of time then reading it again.  If our update worked stuck,
   * we can be pretty sure it won't be lost.  
   *
   * We don't need to lock internally since the only thread that may update the peers is this thread.  All others
   * will only read the value, never write.
   */
  struct heartbeat_thread_data {
    heartbeat_thread_data(DataBattery* db, std::string my_id, 
        HeartBeatData* hbd, ConfigData* cnfgd)
      : _db(db), _my_id(my_id), _hbd(hbd), _cnfgd(cnfgd)
    {}
    ~heartbeat_thread_data() {
      if (_db) { delete _db; }
    }
    DataBattery* _db;
    std::string _my_id;
    HeartBeatData* _hbd; //Data that is mutex protected
    ConfigData* _cnfgd;
  };
  bool create_heartbeat_thread(heartbeat_thread_data* hbtd);

  /* Commit thread is responsible for checking if we should commit any pending certs.  If yes, it 
   *   figures out which ones and in what order to commit them.  For more details see comment above
   *   commit_pending in data_battery.cc
   *  _min_age: in seconds.  Minimum age pending cert must be before being committed.
   *  _commit_delay: how long to wait before trying to commit pending certs
   *  _peer_delay: how much to delay commit depending on your peer ordering.  Does not apply to
   *     first commit attempt when restarting.
   */
  struct commit_thread_data:public Timestamp {
    public:
      commit_thread_data(CertTables* ct, ConfigData* cnfgd)
        : _cert_tables(ct), _cnfgd(cnfgd)
      {}
      ~commit_thread_data() {
        if (_cert_tables) { delete _cert_tables; }
      }
      CertTables* _cert_tables;
      uint _min_age; //In seconds
      uint _commit_delay; //In seconds
      uint _peer_delay; //In seconds
      ConfigData* _cnfgd;
  };
  bool create_commit_thread(commit_thread_data* ctd);

  /* Leaves thread is respondible for periodically pulling all the new certs from the leaves
   *   table in DataBattery.  If it has not previously retrieved any, it will just pull all of
   *   them, otherwise it will just get the new ones (plus whatever might be in the key value
   *   shared with new certs
   * The thread does not update the local tree or database.  That is done in the main thread,
   *   this merely keeps a LoggedCertificatePBList up to date which the main thread will use to
   *   sync everything locally.
   */

  struct leaves_thread_data {
    leaves_thread_data(DataBattery* db, LeavesData* ld, ConfigData* cnfgd)
      : _db(db), _last_key(0), _ld(ld), _cnfgd(cnfgd)
    {}
    ~leaves_thread_data() {
      if (_db) { delete _db; }
    } 
    DataBattery* _db;
    uint64_t _last_key; //Last key you retrieved from leaves table
    LeavesData* _ld; //Data that is mutex protected
    uint _last_update; //Last time you updated successfully, can be used to suspend if it's too
                       // long since last time.
    ConfigData* _cnfgd;
  };
  bool create_leaves_thread(leaves_thread_data* ltd);
  enum leaves_helper_enum { SHORT_SLEEP = 0, LONG_SLEEP };
  leaves_helper_enum leaves_helper(leaves_thread_data* ltd);

}


#endif
