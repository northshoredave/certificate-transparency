#include <glog/logging.h>
#include <sstream>
#include "log/data_battery.h" 
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "util/util.h"
#include "log/logged_certificate.h"
#include <algorithm>
#include "log/cert.h"
#include <google/protobuf/descriptor.h>

using namespace Akamai;
using namespace std;
using namespace google::protobuf;

bool DataBattery::_loadlibraries = true;
int DataBattery::_maxline = 4028;

string DBIndex::generate_key(uint64_t key) const {
  stringstream ss;
  ss << key;
  return ss.str();
}

void DBIndex::generate_keys(uint64_t from, uint64_t to, vector<string>& keys) const {
  keys.clear();
  for (uint64_t i = from; i <= to; ++i) {
    keys.push_back(generate_key(i));
  }
}

void DBIndex::generate_keys(string prefix, uint64_t from, uint64_t to, vector<string>& keys) const {
  generate_keys(from,to,keys);
  for (vector<string>::iterator k = keys.begin(); k != keys.end(); ++k) {
    *k = prefix+*k;
  }
}

string DBIndex::add_key() {
  uint64_t new_last_key = _dbIndex.last_key()+1;
  stringstream ss; ss << new_last_key;
  _dbIndex.set_last_key(new_last_key);
  return ss.str();
}

string Peers::randByteString(int length) {
  unsigned char buf[length];
  RAND_pseudo_bytes(buf,length);
  //convert to hex
  char hex[length*2];
  for (int i = 0; i < length; ++i) { sprintf(&hex[2*i],"%02X",buf[i]); }
  return hex;
}

int Peers::get_order(string id) const {
  for (int i = 0; i < _peers.peers_size(); ++i) {
    if (_peers.peers(i).id() == id) { return i; }
  } 
  return -1;
}

bool Peers::find(string id, uint64_t timestamp) const {
  for (int i = 0; i < _peers.peers_size(); ++i) {
    if (_peers.peers(i).id() == id &&
        _peers.peers(i).timestamp() == timestamp) {
      return true;
    }
  }
  return false;
}

void Peers::get_peer_set(set<string>& peers) const {
  peers.clear();
  for (int i = 0; i < _peers.peers_size(); ++i) {
    LOG(INFO) << "CT: got peer " << _peers.peers(i).id();
    peers.insert(_peers.peers(i).id());
  }
}

void Peers::get_removed_peer_set(set<string>& peers,uint age) const {
  peers.clear();
  uint64_t current_time = get_time(); 
  for (int i = 0; i < _peers.removed_peers_size(); ++i) {
    LOG(INFO) << "CT: got removed peer " << _peers.removed_peers(i).id();
    if (_peers.removed_peers(i).timestamp()+age < current_time) {
      peers.insert(_peers.removed_peers(i).id());
    }
  }
}

void Peers::remove_dead_peers(uint64_t max_age) {
  //Don't see a way to delete from a list in protobuf so just build up a new object and copy it over to the
  //  permanent one.
  ct::DataBatteryPeers reduced_peers;
  *reduced_peers.mutable_removed_peers() = _peers.removed_peers();
  uint64_t current_time = get_time();
  for (int i = 0; i < _peers.peers_size(); ++i) {
    const ct::DataBatteryPeers_peer& p = _peers.peers(i);
    //If your timestamp+max_age is still < current_time, then your dead and can be removed
    if (p.timestamp()+max_age < current_time) { 
      LOG(INFO) << "HB: Removing peer " << p.id();
      ct::DataBatteryPeers_peer* new_r_p = reduced_peers.add_removed_peers();
      new_r_p->CopyFrom(p);
      continue; 
    }
    ct::DataBatteryPeers_peer* copied_peer = reduced_peers.add_peers();
    //Your timestamp is good, copy it forward
    copied_peer->CopyFrom(p);
  }
  LOG(INFO) << "HB: reduced peers to " << reduced_peers.peers_size();
  LOG(INFO) << "HB: removed peers size " << reduced_peers.removed_peers_size();
  //Copy local reduced list to permanent one
  _peers.CopyFrom(reduced_peers);
}

void Peers::update_timestamp(string id, uint64_t timestamp) {
  for (int i = 0; i < _peers.peers_size(); ++i) {
    if (_peers.peers(i).id() == id) {
      _peers.mutable_peers(i)->set_timestamp(timestamp);
      LOG(INFO) << "HB: found peer " << id << " set timestamp " << timestamp;
      return;
    }
  }
  //Peer wasn't found, so add it
  ct::DataBatteryPeers::peer* t = _peers.add_peers();
  LOG(INFO) << "HB: add peer " << id << " with timestamp " << timestamp;
  t->set_id(id);
  t->set_timestamp(timestamp);
}

bool Peers::GET(DataBattery* db, string tablename) {
  string data;
  if (!db->GET(tablename,"peers",data)) {
    LOG(INFO) << "PEERS: Failed to retrieve table '" << tablename << "' peers";
    return false;
  }
  if (!parse_from_string(data)) {
    LOG(ERROR) << "PEERS: Failed to parse peers ";
    return false;
  }
  return true;
}

bool Peers::PUT(DataBattery* db, string tablename) const {
  string data;
  if (!serialize_to_string(&data)) {
    LOG(ERROR) << "PEERS: Failed to serialize peers";
    return false;
  }
  if (!db->PUT(tablename,"peers",data)) {
    LOG(ERROR) << "PEERS: Failed to add peers";
    return false;
  }
  return true;
}

static uint randLimit(uint lb, uint ub) {
  if (ub <= lb) { return lb; }
  return lb+static_cast<uint>(rand() * 1.0/RAND_MAX * (ub-lb));
}

bool Peers::update_peer(string id, DataBattery* db, string tablename) {
  LOG(INFO) << "PEERS: update_peer " << id << " to table " << tablename;
  //Try to retrieve peers
  if (!GET(db,tablename)) { 
    //If you got 404, it means the peers entry wasn't in table yet, so you can still proceed
    //  Otherwise something bad happened, so abort out.
    if (db->get_error_status() != 404) { return false; }
  }
    
  //remove any dead peers while your at it
  remove_dead_peers(_max_age);

  uint64_t current_time = get_time();
  //Now go into loop checking if your in peers with correct timestamp, if not, then add/update and wait.
  while (!find(id,current_time)) {
    //Get the most current time
    current_time = get_time();
    //Add id, or just update it's timestamp if it's already there
    update_timestamp(id,current_time);

    //Commit back to table
    if (!PUT(db,tablename)) { return false; }

    //Sleep for some random time
    uint wait_time = randLimit(_fixed_peer_delay,_fixed_peer_delay+_random_peer_delay);
    LOG(INFO) << "PEERS: Wait_time " << wait_time;
    sleep(wait_time);
    //Get the peers again
    if (!GET(db,tablename)) { return false; }
  }

  LOG(INFO) << "PEERS: Added peer " << id << " with current_time " << current_time;
  return true;
}

//I'm going to assume that any table I have has an index by construction.  If it's missing then someone deleted
//my table or something, and that's bad and stop worthy
bool DataBattery::get_index(string table, string index_key, DBIndex& index) {
  string data;
  if (!GET(table,index_key,data)) { 
    //If error is 404, it means table is fine, but index was missing, so add it 
    if (get_error_status() == 404) { return put_index(table,index_key,index); }
    //Otherwise something else went wrong
    LOG(ERROR) << "DB: Failed to retrieve table " << table << " index"; 
    return false;
  }
  if (!index.parse_from_string(data)) {
    LOG(ERROR) << "DB: Failed to parse table " << table << " index";
    return false;
  }
  return true;
}

bool DataBattery::put_index(string table, string index_key, const DBIndex& index) {
  string data;
  if (!index.serialize_to_string(&data)) {
    LOG(ERROR) << "DB: Failed to serialize index for table " << table;
    return false;
  }
  if (!PUT(table,index_key,data)) {
    LOG(ERROR) << "DB: Failed to commit index to table " << table;
    return false;
  }
  return true;
}

DataBattery::DataBattery(const Settings& settings)
        : _settings(settings)
        , _status(-1)
{
  //Load libraries if needed
  if (_loadlibraries) {
    SSL_library_init();
    ERR_load_SSL_strings();
    _loadlibraries = false;
  }

  bool failed(false);
  //Create a new ssl context
  _ctx = SSL_CTX_new(TLSv1_client_method());
  if (!_ctx) {
    LOG(ERROR) << "DB: Failed to create CTX";
    failed = true;
  }
  while (!failed&&SSL_CTX_use_certificate_file(_ctx,_settings._cert.c_str(),SSL_FILETYPE_PEM)!=1) {
    LOG(INFO) << "DB: Couldn't load certificate " << _settings._cert;
    sleep(_settings._key_sleep);
  }
  LOG(INFO) << "DB: Loaded certificate " << _settings._cert;

  while (!failed&&SSL_CTX_use_PrivateKey_file(_ctx,_settings._pvkey.c_str(),SSL_FILETYPE_PEM)!=1) {
    LOG(INFO) << "DB: Couldn't load private key " << _settings._pvkey;
    sleep(_settings._key_sleep);
  } 
  LOG(INFO) << "DB: Loaded private key "<< _settings._pvkey;

  //Verify the key against cert
  if (!failed&&SSL_CTX_check_private_key(_ctx)!=1) {
    LOG(ERROR) << "DB: Private key not compatible with cert.";
    failed = true;
  } else {
    LOG(INFO) << "DB: Private key matches cert";
  }
  if (failed&&_ctx) {
    SSL_CTX_free(_ctx); 
    _ctx = NULL;
  }
}

int DataBattery::tcp_connect() {
  struct addrinfo hints, *res, *ressave;

  bzero(&hints,sizeof(struct addrinfo));
  hints.ai_flags = 0;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  int n = getaddrinfo(_settings._host.c_str(),_settings._serv.c_str(),&hints,&res);
  if ( n != 0) {
    LOG(WARNING) << "DB: tcp_connect error for " << _settings._host << "," << _settings._serv << ":" << gai_strerror(n);
    return -1;
  } 
  ressave = res;
  int sockfd(-1);
  while (res != NULL) {
    sockfd = socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if (sockfd < 0) { res = res->ai_next; continue; } //No good
    if (connect(sockfd,res->ai_addr, res->ai_addrlen) == 0) {
      break;
    }
    close(sockfd);
    res = res->ai_next;
  } 
  if (res == NULL) {
    LOG(WARNING) << "DB: tcp_connect error for " << _settings._host << "," << _settings._serv;
  }
  freeaddrinfo(ressave);
  return sockfd;
}

SSL* DataBattery::ssl_connect() {
  if (!_ctx) { 
    LOG(ERROR) << "DB:ctx not initialized";
    return NULL;
  }
  int fd = tcp_connect(); 
  if (fd == -1) {
    LOG(WARNING) << "DB: Server unavailable";
    return NULL;
  } 
  SSL* ssl = SSL_new(_ctx);
  if (ssl == NULL) {
    LOG(ERROR) << "DB: Failed to create ssl ";
    return NULL;
  } 

  //Creates a BIO implicitly
  if (!SSL_set_fd(ssl, fd)) {
    LOG(ERROR) << "DB: Failed to set fd in SSL";
    return NULL;
  }

  if (SSL_connect(ssl) != 1) {
    LOG(ERROR) << "DB: SSL handshake failed";
    disconnect(ssl);
    return NULL;
  }

  return ssl;
}
  
//Tear down the ssl connection and free up the data structures
void DataBattery::disconnect(SSL* ssl) {
  if (ssl) {
    int fd = SSL_get_fd(ssl);
    if (fd > 0) { 
      LOG(INFO) << "DB: disconnect ssl with fd " << fd;
      close(fd);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
}

bool DataBattery::GET_key_from_table(string table, string key, uint64_t max_entry_size, string& data) {
  data.reserve(max_entry_size);
  if (!GET(table,key,data)) {
    LOG(ERROR) << "DB: Failed to get key " << key << " from table " << table;
    return false;
  }
  return true;
}

bool DataBattery::GET_keys_from_table(string table,const vector<string>& keys, uint64_t max_entry_size,
    vector<string>& data) {
  data.clear();
  data.reserve(keys.size());
  for (vector<string>::const_iterator k = keys.begin(); k != keys.end(); ++k) {
    string value;
    value.reserve(max_entry_size);
    if (!GET(table,*k,value)) {
      LOG(ERROR) << "DB: Failed to get key " << *k << " from table " << table;
      return false;
    }
    data.push_back(value);
  }
  return true;
}

bool DataBattery::PUT(string table, string key, string value) {
  stringstream ssmsg;
  ssmsg << "PUT /v1/apps/" << _settings._app << "/tables/" << table << "/data/" << key << " HTTP/1.0\r\n";
  ssmsg << "Host: " << _settings._host << "\r\n";
  ssmsg << "Content-Type: text/plain\r\n";
  ssmsg << "Content-Length: " << value.size() << "\r\n\r\n";
  ssmsg << value << "\r\n";

  string msg = ssmsg.str();

  string tmp;
  return METHOD(msg,true,tmp,201);
}

bool DataBattery::GET(string table, string key, string& value) {
  value.clear();
  //Create msg to send
  stringstream ssmsg;
  ssmsg << "GET /v1/apps/" << _settings._app << "/tables/" << table << "/data/" << key << " HTTP/1.0\r\n";
  ssmsg << "Host: " << _settings._host << "\r\n\r\n";

  string msg = ssmsg.str();

  return METHOD(msg,false,value,200);
}

bool DataBattery::DELETE(string table, string key) {
  //Create msg to send
  stringstream ssmsg;
  ssmsg << "DELETE /v1/apps/" << _settings._app << "/tables/" << table << "/data/" << key << " HTTP/1.0\r\n";
  ssmsg << "Host: " << _settings._host << "\r\n\r\n";

  string msg = ssmsg.str();

  string value;
  return METHOD(msg,true,value,204);
}

bool DataBattery::GETLIMIT(string limit, string& value) {
  value.clear();
  stringstream ssmsg;
  ssmsg << "GET /v1/apps/" << _settings._app << "/limits/" << limit << " HTTP/1.0\r\n";
  ssmsg << "Host: " << _settings._host << "\r\n\r\n";

  string msg = ssmsg.str();

  return METHOD(msg,false,value,200);
}

bool DataBattery::METHOD(string msg, bool returnOnSuccess, string& value, uint successCode) {
  SSL* ssl = ssl_connect();
  if (!ssl) { 
    LOG(WARNING) << "DB: Failed to establish ssl connection";
    return false; 
  }

  int n = SSL_write(ssl,msg.data(),msg.length());
  if (n <= 0) {
    LOG(WARNING) << "DB: Remote server closed the connection";
    disconnect(ssl);
    return false;
  }

  char recvline[_maxline+1];
  ScanHeader sh(successCode);
  while ( (n = SSL_read(ssl,recvline,_maxline) ) > 0) {
    char* head; int len;
    if (!sh.scan(recvline,n,&head,len)) {
      _status = sh.get_status();
      LOG(WARNING) << "DB: Failed msg on return value: " << msg;
      disconnect(ssl);
      return false;
    }
    if (returnOnSuccess && sh.get_found_status()) { disconnect(ssl); return true; }
    else { value.append(head,len); }
  }
  disconnect(ssl);
  return true;
}

bool CertTables::get_last_leaves(DBIndex& index, ct::LoggedCertificatePBList& leaves,string& last_key) {

  index.get_last_key(last_key);

  string data;
  if (!get_db()->GET_key_from_table(get_leaves_table_name(),last_key,get_max_entry_size(),data)) { 
    if (get_db()->get_error_status() != 404 || last_key != "0") {
      return false; 
    }
  }

  if (!leaves.ParseFromString(data)) {
    LOG(ERROR) << "CT: Parse error from leaves table";
    return false;
  }
  return true;
}

int CertTables::get_peer_order() {
  Peers p(_cnfgd->fixed_peer_delay(),_cnfgd->random_peer_delay(),_cnfgd->max_peer_age());

  if (!get_peers(p)) { return -1; }
  return p.get_order(get_my_id());
}

//The index contains the last_updated timestamp, but it seems safer to retrieve the timestamp of the last
//committed sct and go from there.  Avoids any machine time skew issues.  Also need to get the sequence id
//anyway.
//  Note that the sequence_id returned is actually the last sequence ID + 1.  That way the caller can just use
//it and we don't loose 0 as an index (which CT used, so it's less confusing to keep it).
bool CertTables::get_last_committed(uint64_t& last_committed_timestamp, 
    uint64_t& sequence_id, uint64_t& last_updated_timestamp) {
  LOG(INFO) << "CT: get_last_committed";

  DBIndex index;
  if (!get_leaves_index(index)) { return false; }
  last_updated_timestamp = index.last_update();

  ct::LoggedCertificatePBList last;
  string last_key;
  if (!get_last_leaves(index,last,last_key)) { return false; }
 
  if (last.logged_certificate_pbs_size() == 0) {
    last_committed_timestamp = 0;
    sequence_id = 0;
    LOG(INFO) << "CT: no lcpb yet, seq id is 0"; 
    return true;
  }
  const ct::LoggedCertificatePB& lcpb = last.logged_certificate_pbs(last.logged_certificate_pbs_size()-1); 
  last_committed_timestamp = lcpb.contents().sct().timestamp();
  sequence_id = lcpb.sequence_number()+1;
  LOG(INFO) << "CT: got seqId " << sequence_id;
  return true;
}

bool CertTables::add_leaves(ct::LoggedCertificatePBList& lcpbl, uint commit_delay) {
  LOG(INFO) << "CT:al add_leaves enter with size " << lcpbl.logged_certificate_pbs_size();
  DBIndex index;
  if (!get_leaves_index(index)) { return false; }
  //Check if someone beat you to the update while you were gathering up the pending.  If yes, just
  // bail.  Otherwise continue update
  uint64_t current_time = util::TimeInMilliseconds();
  if (index.last_update()+commit_delay > current_time) { 
    LOG(INFO) << "CT:al not committing because ct:"<<current_time<<" lu:"<<index.last_update()<<" cd:" << commit_delay << " has not expired";
    return true;
  }

  ct::LoggedCertificatePBList last;
  string last_key;
  if (!get_last_leaves(index,last,last_key)) { return false; } 
  LOG(INFO) << "CT:al last leaf list is " << last.logged_certificate_pbs_size();

  int remaining_size = get_max_entry_size()-last.ByteSize();
  for (int i = 0; i < lcpbl.logged_certificate_pbs_size(); ++i) {
    LOG(INFO) << "CT:al add pending leaf to i:" << i;
    const ct::LoggedCertificatePB& lcpb = lcpbl.logged_certificate_pbs(i);
    //Check if you need to commit the key and start a new one
    if (lcpb.ByteSize() > remaining_size) {
      string tmp;
      last.SerializeToString(&tmp);
      if (!get_db()->PUT(get_leaves_table_name(),last_key,tmp)) { return false; }
      last.Clear();
      remaining_size = get_max_entry_size();
      last_key = index.add_key();
      LOG(INFO) << "CT:al PUT leafs in leave table("<<last.logged_certificate_pbs_size() <<"), and get new key:" << last_key;
    }
    ct::LoggedCertificatePB* new_lcpb = last.add_logged_certificate_pbs();
    new_lcpb->CopyFrom(lcpb);
    remaining_size -= lcpb.ByteSize();
  }
  //Commit last key that you added to
  string tmp;
  last.SerializeToString(&tmp);
  LOG(INFO) << "CT:al commit outside loop key:"<<last_key<<" size:" << last.logged_certificate_pbs_size();
  if (!get_db()->PUT(get_leaves_table_name(),last_key,tmp)) { return false; }

  //Update timestamp on index and commit it to complete the update
  index.update_timestamp();
  if (!put_leaves_index(index)) { return false; }
  return true;
}

struct SCTSort {
  inline bool operator()(const ct::LoggedCertificatePB& a, const ct::LoggedCertificatePB& b) {
    const ct::LoggedCertificate* lc_a(reinterpret_cast<const ct::LoggedCertificate*>(&a));
    const ct::LoggedCertificate* lc_b(reinterpret_cast<const ct::LoggedCertificate*>(&b));
    if (lc_a->timestamp() != lc_b->timestamp()) {
      return lc_a->timestamp() < lc_b->timestamp();
    } else {
      //This is expensive, but I would expect it to almost never be used
      return lc_a->Hash() < lc_b->Hash();
    }
  }
};

static bool zero_index(string prefix, string index) {
  if (prefix.length()+1 > index.length()) { return false; }
  string tmp = index.substr(prefix.length()+1);
  return atoi(tmp.c_str()) == 0;
}

CertTables::CertTables(DataBattery* db,  std::string my_id, PendingData* pd, 
    LeavesData* ld, HeartBeatData* hbd,
    ConfigData* cnfgd) 
        : _db(db)
        , _my_id(my_id)
        , _pd(pd)
        , _ld(ld)
        , _hbd(hbd)
        , _cnfgd(cnfgd)
{}

//Any errors just fail out and let it start again since we're only starting up here anyway.
void CertTables::init_pending_data(PendingData* pd) {
  //Get the current pending index so we can just use it as needed later
  CHECK(get_pending_index(get_my_id(),pd->_pending_index)) << "CT: Failed to get, or add, pending index";

  string last_key;
  pd->_pending_index.get_last_key(get_my_id(),last_key);
  //Get the last entry in the pending table
  if (!get_key_data(get_pending_table_name(),last_key,pd->_last_pending_value)) {
    CHECK(get_db()->get_error_status() == 404 && pd->_pending_index.last_key() == 0)<<"CT: Failed to get last pending";
    //No pending list in first key, add one
    ct::LoggedCertificatePBList lcpbl;
    string data;
    lcpbl.SerializeToString(&data);
    LOG(INFO) << "CT: adding to pending key " << last_key;
    CHECK(get_db()->PUT(get_pending_table_name(),last_key,data)) << "CT:Failed to add last pending";
  }
}

/*
 *What we want to do is commit any pending certs that are older then min_age and newer then the 
 * last committed cert. 
 *
 * min_age: how old cert must be before being committed in ms
 * commit_delay: How long since last leaves table update we must be before committing again in ms
 *
 * min_age = 12 hours.  MMD is 24 hours.
 * last_committed is 18 hours.
 *
 * -----------------> timestamp
 * <----------------  age
 * 24  18  12  6   0 
 *
 * 0 == current_time
 * What we want to commit is:
 *    last_commited < sct < current_time - min_age
 *
 *We will attempt to commit pending certs meeting the time window described above every 
 * commit_delay seconds.
 */
bool CertTables::commit_pending(uint64_t min_age, uint64_t commit_delay) {
  Peers p(_cnfgd->fixed_peer_delay(),_cnfgd->random_peer_delay(),_cnfgd->max_peer_age());
  //Get the peers
  if (!get_peers(p)) { return false; }
  set<string> peers;
  p.get_peer_set(peers);

  ct::LoggedCertificatePBList new_lcpbl;
  uint64_t current_time = util::TimeInMilliseconds();
  uint64_t last_committed_timestamp, sequence_id;
  uint64_t last_updated_timestamp;
  get_last_committed(last_committed_timestamp,sequence_id,last_updated_timestamp); 
  //Check if you need to update at all
  if (last_updated_timestamp+commit_delay > current_time) { 
    LOG(INFO) << "CT:cp not committing because ct:"<<current_time<<" lu:"<<last_updated_timestamp<<" cd:" << commit_delay << " has not expired";
    return true;
  }
  //Iterate over peers and get the keys
  for (set<string>::const_iterator pIt = peers.begin(); pIt != peers.end(); ++pIt) {
    LOG(INFO) << "CT:cp peer " << *pIt;
    vector<string> keys;
    if (!get_pending_peer_keys(*pIt,keys)) { return false; }
    //For each key, retrieve the data and copy out the pending certs that meet time min_age
    //By construction, the pending table entries are already sorted by sct per peer
    bool breakOut(false);
    for (vector<string>::const_iterator kIt = keys.begin(); kIt != keys.end(); ++kIt) {
      ct::LoggedCertificatePBList lcpbl;
      if (!get_key_data(get_pending_table_name(),*kIt,lcpbl)) { 
        //This isn't fatal if the key was 0 and missing (might be an empty table)
        if (get_db()->get_error_status() == 404 && zero_index(*pIt,*kIt)) {
          continue;
        } else {
          LOG(ERROR) << "CT:cp couldn't get key " << *kIt;
          return false; 
        }
      }
      LOG(INFO) << "CT:cp peer:" << *pIt << " got key " << *kIt << " and lcpbl size " << lcpbl.logged_certificate_pbs_size();
      //Pick out which guys you can commit
      for (int i = 0; i < lcpbl.logged_certificate_pbs_size(); ++i) {
        const ct::LoggedCertificatePB& lcpb = lcpbl.logged_certificate_pbs(i);
        LOG(INFO) << "CT:cp i: " << i << " sct: " << lcpb.contents().sct().timestamp() << " last_commit: " << last_committed_timestamp;
        if (lcpb.contents().sct().timestamp() > last_committed_timestamp) {
          LOG(INFO) << "CT:cp sct " << lcpb.contents().sct().timestamp() << " min_age " << min_age << " current " << current_time << " ct-min " << current_time-min_age;
          //Check if you have reached the end of the time min_age for committing
          if (lcpb.contents().sct().timestamp() > current_time - min_age) { 
            breakOut = true; break; 
          }
          //Your in the time min_age
          ct::LoggedCertificatePB* new_lcpb = new_lcpbl.add_logged_certificate_pbs();
          new_lcpb->CopyFrom(lcpb);
        }
      }
      if (breakOut) { break; }
    }
  }
  //Check if you've got anything new to commit
  if (new_lcpbl.logged_certificate_pbs_size() == 0) { 
    LOG(INFO) << "CT:cp no pending certs to commit";
    return true;
  }
  //Sort the new_lcpbl by sct timestamp and assign sequenceIds in order
  sort(new_lcpbl.mutable_logged_certificate_pbs()->begin(),
      new_lcpbl.mutable_logged_certificate_pbs()->end(),
      SCTSort());
  for (int i = 0; i < new_lcpbl.logged_certificate_pbs_size(); ++i) {
    new_lcpbl.mutable_logged_certificate_pbs(i)->set_sequence_number(sequence_id++);
  }

  //Now you've got a list of certs that haven't been committed and are in the correct time min_age
  if (!add_leaves(new_lcpbl,commit_delay)) { return false; }

  return true;
}

void CertTables::clear_pending(const set<string>& leaves_hash) { 
  LOG(INFO) << "CT:clrp clear_pending";
  vector<string> keys;
  uint64_t pending_first_key, pending_last_key;
  pthread_mutex_lock(&get_pd()->_mutex);
  get_pd()->_pending_index.get_all_keys(get_my_id(),keys);
  pending_first_key = get_pd()->_pending_index.first_key();
  pending_last_key = get_pd()->_pending_index.last_key();
  pthread_mutex_unlock(&get_pd()->_mutex);

  uint64_t new_first_key = pending_first_key;
  LOG(INFO) << "CT:clrp first_key " << new_first_key;
  for (vector<string>::const_iterator kIt = keys.begin(); kIt != keys.end(); ++kIt, ++new_first_key) {
    ct::LoggedCertificatePBList lcpbl;
    if (!get_key_data(get_pending_table_name(),*kIt,lcpbl)) { break; }
    //Check if the entry your looking at is also the last_key, in which case you can't remove it since more stuff
    //  could be added to it, if it's not full
    if (new_first_key == pending_last_key) { break; }
    //Otherwise, look through them to see if they are all committed
    bool all_committed(true);
    for (int i = 0; i < lcpbl.logged_certificate_pbs_size(); ++i) {
      const ct::LoggedCertificatePB& lcpb = lcpbl.logged_certificate_pbs(i);
      string hash = reinterpret_cast<const ct::LoggedCertificate*>(&lcpb)->Hash();
      if (leaves_hash.find(hash) == leaves_hash.end()) {
        all_committed = false; break;
      }
    }
    if (!all_committed) { break; }
    LOG(INFO) << "CT:clrp safe to remove key " << *kIt << " ind " << new_first_key;
  }
  if (new_first_key != pending_first_key) {
    pthread_mutex_lock(&get_pd()->_mutex);
    LOG(INFO) << "CT:clrp new first_key " << new_first_key << " index " << pending_first_key;
    get_pd()->_pending_index.set_first_key(new_first_key);
    put_pending_index(get_my_id(),get_pd()->_pending_index);
    pthread_mutex_unlock(&get_pd()->_mutex);
  }
}

bool CertTables::get_pending_index(string id, DBIndex& index) {
  string index_key = id+string(".index");
  LOG(INFO) << "CT: get_pending_index key " << index_key;
  if (!get_db()->get_index(get_pending_table_name(),index_key,index)) {
    LOG(ERROR) << "Failed to get index from " << get_pending_table_name();
    return false;
  }
  return true;
}

bool CertTables::put_pending_index(string id, const DBIndex& index) {
  string index_key = id+string(".index");
  if (!get_db()->put_index(get_pending_table_name(),index_key,index)) {
    LOG(ERROR) << "Failed to commit index to " << get_pending_table_name() << " id: " << id;
    return false;
  }
  return true;
}

bool CertTables::get_pending_peer_keys(string peer, vector<string>& keys) {
  DBIndex index;
  if (!get_pending_index(peer,index)) { return false; }
  index.get_all_keys(peer,keys);
  return true;
}

bool CertTables::pending_add(const ct::LoggedCertificatePB* lcpb) {
  LOG(INFO) << "CT:pa pending_add";
  uint64_t current_time = util::TimeInMilliseconds();
  //Comparing in ms, so must convert max_peer_age from seconds
  uint64_t max_hb_age = get_hdb()->get_timestamp()*1000+0.5*_cnfgd->max_peer_age()*1000;
  CHECK_LE(current_time,max_hb_age) 
      << "CT:pa Your heartbeat hasn't updated recently, can't accept pending.";
  //Check if the current last entry can hold the new data, if not get the next key
  string key;
  pthread_mutex_lock(&get_pd()->_mutex);
  get_pd()->_pending_index.get_last_key(get_my_id(),key); 
  pthread_mutex_unlock(&get_pd()->_mutex);
  bool new_key(false);
  if ((uint)(lcpb->ByteSize()+get_pd()->_last_pending_value.ByteSize()) >= get_max_entry_size()) {
    //Modifying a shared data structure, so lock it.  Even though the clear method shouldn't modify the same
    //  attributes.  Only pending_index is accessed in 2 threads.  _last_pending_value is only modified in one
    //  thread.
    pthread_mutex_lock(&get_pd()->_mutex);
    key = get_my_id() + string(".") + get_pd()->_pending_index.add_key();
    pthread_mutex_unlock(&get_pd()->_mutex);
    //Reset the lcpbl (this is just a local copy, not the database)
    get_pd()->_last_pending_value.clear_logged_certificate_pbs();
    new_key = true;
    LOG(INFO) << "CT:pa new key " << key;
  }
  
  ct::LoggedCertificatePB* new_lcpb = get_pd()->_last_pending_value.add_logged_certificate_pbs();
  new_lcpb->CopyFrom(*lcpb);

  //Commit data
  string data;
  get_pd()->_last_pending_value.SerializeToString(&data);
  if (!get_db()->PUT(get_pending_table_name(),key,data)) {
    LOG(ERROR) << "CT:pa Failed to commit pending key " << key;
    return false;
  }
  //Commit index, if you added a new key
  if (new_key) {
    //lock mutex here to make sure that clean up doesn't overwrite my pending index update
    pthread_mutex_lock(&get_pd()->_mutex);
    if (!put_pending_index(get_my_id(),get_pd()->_pending_index)) { 
      pthread_mutex_unlock(&get_pd()->_mutex);
      return false; 
    } 
    pthread_mutex_unlock(&get_pd()->_mutex);
  }

  LOG(INFO) << "CT:pa finished pending_add";

  return true;
}

bool CertTables::get_key_data(string table, string key, ct::LoggedCertificatePBList& lcpbl) {
  string data;
  if (!get_db()->GET_key_from_table(table,key,get_max_entry_size(),data)) { return false; }

  if (!lcpbl.ParseFromString(data)) {
    LOG(ERROR) << "CT: Parse error from table " << table << " for key " << key;
    return false;
  }
  return true;
}

bool CertTables::get_all_leaves(uint64_t from_key, string table_name, uint64_t max_entry_size,
    DataBattery* db, ct::LoggedCertificatePBList& lcpbl, uint64_t& last_key) {
  DBIndex index;
  if (!db->get_index(table_name,"index",index)) {
    LOG(ERROR) << "CT:gal failed to get index for cert table";
    return false;
  }
  last_key = index.last_key();
  vector<string> keys;
  index.get_all_keys_from_key(from_key,keys);
  vector<string> data;
  if (!db->GET_keys_from_table(table_name,keys,max_entry_size,data)) { return false; }

  for (uint i = 0; i < data.size(); ++i) {
    ct::LoggedCertificatePBList tmp;
    if (!tmp.ParseFromString(data[i])) {
      LOG(ERROR) << "CT:gal Parse error from leaves table for entry i " << i;
      return false;
    }
    LOG(INFO) << "CT:gal tmp size:"<<tmp.logged_certificate_pbs_size() 
      << " lcpbl size:" << lcpbl.logged_certificate_pbs_size();
    lcpbl.MergeFrom(tmp);
  }
  return true;
}

/*Each line in the header is terminated with \r\n.  So state machine attempts to process the completed line when
 * it reaches such a combination.  State machine ignores single \r or \n.  Everything else is just gathered up
 * into a single line for processing when the \r\n is reached.
 *The header itself is terminated by \r\n\r\n, so that combination terminates processing of the header.
 */
bool ScanHeader::process_header(int n, char** start, int& len) {
  for (int i = 0; i < n; ++i) {
    switch(_state) {
      case 0:
        if (**start == '\r') { ++_state; }
        break;
      case 1:
        if (**start == '\n') { 
          if (!process_line(_line)) { return false; }
          _line.clear();
          ++_state; 
        }
        else { _state = 0; }
        break;
      case 2:
        if (**start == '\r') { ++_state; }
        else { _state = 0; }
        break;
      case 3:
        if (**start == '\n') { ++_state; }
        else { _state = 0; }
        break;
      default:
        //Should never be in here
        _state = 0;
    }
    _line.append(*start,1);
    ++*start; --len;
    if (_state == 4) { 
      _processedHeader = true;
      return true; 
    }
  }
  return true;
}

/*Each header should return a status line that will be a 'version status' and should be the first line in
 *  the header.  Once you've found it, what remains are the options that get returned (including things like
 *  the size of the returned data).
 */
bool ScanHeader::process_status(string line) {
  char version[100]; 
  if (sscanf(line.c_str(),"%s %d",version,&_status) != 2) { return false; }
  _foundStatus = true;
  if (_status != _success) { LOG(WARNING) << "Got status " << _status; return false; }
  return true;
}

void* ConfigUpdate(void* arg) {
  config_thread_data* cnfgtd = static_cast<config_thread_data*>(arg);
  uint64_t sleep_time = cnfgtd->_cd->config_delay();
  while (1) {
    sleep(sleep_time);
    LOG(INFO) << "ConfigUpdate thread wakeup";
    string value;
    if (!cnfgtd->_db->GET_key_from_table(cnfgtd->_table,cnfgtd->_key,cnfgtd->_cd->db_max_entry_size(),value)) {
      LOG(WARNING) << "Failed to update config";
      sleep_time = cnfgtd->_cd->short_sleep();
    } else {
      cnfgtd->_cd->parse_from_string(value);
      cnfgtd->_cd->update_time();
      sleep_time = cnfgtd->_cd->config_delay();
    }
  }
  return NULL;
}

bool Akamai::create_config_thread(config_thread_data* cnfgtd) {
  //Get it once before starting thread so that you are gauranteed to have it by the time other stuff starts up
  string value;
  if (!cnfgtd->_db->GET_key_from_table(cnfgtd->_table,cnfgtd->_key,cnfgtd->_cd->db_max_entry_size(),value)) {
    LOG(ERROR) << "Failed to get config";
    return false;
  }
  if (!cnfgtd->_cd->parse_from_string(value)) {
    LOG(ERROR) << "Failed to parse config";
    return false;
  }
  //Now create thread
  pthread_t t;
  int res;
  if ((res = pthread_create(&t, NULL, ConfigUpdate, cnfgtd)) != 0) {
    LOG(ERROR) << "Failed to create config thread: " << strerror(errno);
    return false;
  } else {
    LOG(INFO) << "Created config thread";
  }
  return true;
}

//It is expected that update_peer was already called before this thread starts.  So we can sleep immediately.
void* HeartBeat(void* arg) {
  heartbeat_thread_data* hbtd = static_cast<heartbeat_thread_data*>(arg);
  uint64_t sleep_time(hbtd->_cnfgd->heartbeat_freq());
  while (1) {
    sleep(sleep_time);
    LOG(INFO) << "HB: thread wakeup";
    Peers p(hbtd->_cnfgd->fixed_peer_delay(),hbtd->_cnfgd->random_peer_delay(),
        hbtd->_cnfgd->max_peer_age());
    if (!p.update_peer(hbtd->_my_id,hbtd->_db,hbtd->_cnfgd->db_pending())) {
      LOG(WARNING) << "HB: Failed to update peer timestamp for id " << hbtd->_my_id;
      sleep_time = hbtd->_cnfgd->short_sleep(); //Sleep for a short time and try again
    } else {
      //Set timestamp on when you last successfully updated
      hbtd->_hbd->update_time(); 
      LOG(INFO) << "HB: Sleep for " << hbtd->_cnfgd->heartbeat_freq(); 
      sleep_time = hbtd->_cnfgd->heartbeat_freq();
    }
  }
  return NULL;
}

bool Akamai::create_heartbeat_thread(heartbeat_thread_data* hbtd) {
  //Before starting the thread add the peer to list by calling update_peer.  Doing this outside of thread
  //  so that we block on it for the first add.
  Peers p(hbtd->_cnfgd->fixed_peer_delay(),hbtd->_cnfgd->random_peer_delay(),
      hbtd->_cnfgd->max_peer_age());
  if (!p.update_peer(hbtd->_my_id,hbtd->_db,hbtd->_cnfgd->db_pending())) {
    LOG(ERROR) << "HB: Failed to add peer";
    return false;
  } else {
    //Set timestamp on when you last successfully updated
    hbtd->_hbd->update_time(); 
  }


  //Now create thread
  pthread_t t;
  int res;
  if ((res = pthread_create(&t, NULL, HeartBeat, hbtd)) != 0) {
    LOG(ERROR) << "HB: Failed to create heartbeat thread: " << strerror(errno);
    return false;
  } else {
    LOG(INFO) << "HB: Created heartbeat thread";
  }
  return true;
}

void* CommitThread(void* arg) {
  commit_thread_data* ctd = static_cast<commit_thread_data*>(arg);
  while (1) {
    LOG(INFO) << "CmtT: wakeup";
    if (!ctd->_cert_tables->commit_pending(ctd->_cnfgd->cert_min_age()*1000,
          ctd->_cnfgd->commit_delay()*1000)) {
      LOG(WARNING) << "CmtT: Failed to commit " << ctd->_cert_tables->get_my_id();
      sleep(ctd->_cnfgd->short_sleep()); //Sleep for a short time and try again
    } else {
      //Try cleaning up you pending table to reflect the latest committed leaves
      //  The leaves hash is the list of leaves we got from the DB leaves table, i.e. gauranteed to have been
      //committed, so safe to remove from pending.  Lock to make sure we're not updating as we read it.
      pthread_mutex_lock(&ctd->_cert_tables->get_ld()->_mutex);
      //Make a copy so I can release lock
      set<string> leaves_hash = ctd->_cert_tables->get_ld()->_leaves_hash; 
      pthread_mutex_unlock(&ctd->_cert_tables->get_ld()->_mutex);
      //See if you clear anything out of pending
      ctd->_cert_tables->clear_pending(leaves_hash);
      //Figure out your sleep time 
      int order = ctd->_cert_tables->get_peer_order();
      int peer_delay = 0;
      if (order == -1) { 
        LOG(ERROR) << "CmtT: You weren't in peers? Should be impossible!!"; 
      } else {
        LOG(INFO) << "CmtT: peer order " << order << " so extra delay " << order*ctd->_cnfgd->commit_peer_delay();
        peer_delay = order*ctd->_cnfgd->commit_peer_delay();
      }
      LOG(INFO) << "CmtT: Sleep for " << ctd->_cnfgd->commit_delay()+peer_delay; 
      ctd->update_time();
      sleep(ctd->_cnfgd->commit_delay()+peer_delay);
    }
  }
  return NULL;
}

bool Akamai::create_commit_thread(commit_thread_data* ctd) {
  //Now create thread
  pthread_t t;
  int res;
  if ((res = pthread_create(&t, NULL, CommitThread, ctd)) != 0) {
    LOG(ERROR) << "CmtT: Failed to create commit thread: " << strerror(errno);
    return false;
  } else {
    LOG(INFO) << "CmtT: Created commit thread";
  }
  return true;
}

leaves_helper_enum Akamai::leaves_helper(leaves_thread_data* ltd) {
  ct::LoggedCertificatePBList new_lcpbl;
  uint64_t last_key;
  //If you failed to retrieve the leaves, then sleep for a short time and try again.
  if (!CertTables::get_all_leaves(ltd->_last_key,ltd->_cnfgd->db_leaves(), 
        ltd->_cnfgd->db_max_entry_size(),ltd->_db,new_lcpbl,last_key)) {
    LOG(WARNING) << "LT: failed to get_all_leaves";
    return SHORT_SLEEP;
  }
  LOG(INFO) << "LT: in leaves_thread got " << new_lcpbl.logged_certificate_pbs_size() << " leaves from DB";
  pthread_mutex_lock(&ltd->_ld->_mutex);
  for (int i = 0; i < new_lcpbl.logged_certificate_pbs_size(); ++i) {
    const ct::LoggedCertificatePB& lcpb = new_lcpbl.logged_certificate_pbs(i);
    string hash = reinterpret_cast<const ct::LoggedCertificate*>(&lcpb)->Hash();
    if (ltd->_ld->_leaves_hash.find(hash) != ltd->_ld->_leaves_hash.end()) {
      continue; //You've already included this leaf
    }
    ltd->_ld->_leaves_hash.insert(hash);
    ct::LoggedCertificatePB* added_lcpb = ltd->_ld->_leaves.add_logged_certificate_pbs();
    added_lcpb->CopyFrom(lcpb);
  }
  LOG(INFO) << "LT: after grabbing new certs, now have " << ltd->_ld->_leaves.logged_certificate_pbs_size();
  pthread_mutex_unlock(&ltd->_ld->_mutex);
  ltd->_last_key = last_key;
  ltd->_last_update = util::TimeInMilliseconds();
  return LONG_SLEEP;
}

//It is expected that leaves_helper was already successfully called before thread starts, so we can sleep
//  immediately
void* LeavesThread(void *arg) {
  leaves_thread_data* ltd = static_cast<leaves_thread_data*>(arg);
  uint64_t sleep_time = ltd->_cnfgd->leaves_update_freq();
  while (1) {
    sleep(sleep_time);
    LOG(INFO) << "LT: leaves thread wakeup";
    switch (leaves_helper(ltd)) {
      case SHORT_SLEEP:
        sleep_time = ltd->_cnfgd->short_sleep();
        break;
      case LONG_SLEEP:
        ltd->_ld->update_time();
        sleep_time = ltd->_cnfgd->leaves_update_freq();
        break;
      default:
        LOG(ERROR) << "LT: unknown leaves_helper return";
    }
  }
  return NULL;
}

bool Akamai::create_leaves_thread(leaves_thread_data* ltd) {
  //Before you create the thread, try to retrieve all of the leaves so that you can initialize the database
  if (leaves_helper(ltd) != LONG_SLEEP) {
    LOG(ERROR) << "LT: Should have returned succesfully";
    return false;
  }
  //Now create thread
  pthread_t t;
  int res;
  if ((res = pthread_create(&t, NULL, LeavesThread, ltd)) != 0) {
    LOG(ERROR) << "LT: Failed to create leaves thread: " << strerror(errno);
    return false;
  } else {
    LOG(INFO) << "LT: Created leaves thread";
  }
  return true;
}

void ConfigData::gen_key_values(vector<pair<string, string> >& kv_pairs) const {
  kv_pairs.clear();
  pthread_mutex_lock(&_mutex);
  int num_fields = _config.GetDescriptor()->field_count();
  const Reflection* rd = _config.GetReflection();
  for (int i = 0; i < num_fields; ++i) {
    const FieldDescriptor* fd = _config.GetDescriptor()->FindFieldByNumber(i);
    if (fd) {
      if (fd->is_repeated()) {
        for (uint k = 0; k < rd->FieldSize(_config,fd); k++) {
          stringstream value;
          switch(fd->type()) {
            case FieldDescriptor::TYPE_UINT32:
              value << rd->GetRepeatedUInt32(_config,fd,k);
              break;
            default:
              value << "unknown type";
          }
          kv_pairs.push_back(pair<string,string>(fd->full_name(),value.str()));
        }
      } else {
        stringstream value;
        switch(fd->type()) {
          case FieldDescriptor::TYPE_STRING:
            value << rd->GetString(_config,fd);
            break;
          case FieldDescriptor::TYPE_UINT64:
            value << rd->GetUInt64(_config,fd);
            break;
          case FieldDescriptor::TYPE_UINT32:
            value << rd->GetUInt32(_config,fd);
            break;
          case FieldDescriptor::TYPE_BOOL:
            if (rd->GetBool(_config,fd)) { value << "true"; }
            else { value << "false"; }
            break;
          default:
            value << "unknown type";
        }
        kv_pairs.push_back(pair<string,string>(fd->full_name(),value.str()));
      }
    }
  }
  pthread_mutex_unlock(&_mutex);
}
