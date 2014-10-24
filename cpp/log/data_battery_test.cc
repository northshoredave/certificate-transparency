#include <gtest/gtest.h>
#include <stdint.h>
#include <string>

#include "log/file_db.h"
#include "log/log_signer.h"
#include "log/log_verifier.h"
#include "log/sqlite_db.h"
#include "log/test_db.h"
#include "log/test_signer.h"
#include "log/tree_signer.h"
#include "log/akamai-query.h"
#include "merkletree/merkle_verifier.h"
#include "proto/ct.pb.h"
#include "util/testing.h"
#include "util/util.h"
#include "data_battery.h"
#include "test_signer.h"

DEFINE_string(db_hostname,"","Hostname to access DB");

namespace {

using namespace std;
using namespace Akamai;

class ScanHeaderTest : public ::testing::Test {
  protected:
    ScanHeaderTest() {
      _recvline = new char[DataBattery::get_maxline()];
    }
    ~ScanHeaderTest() {
      delete _recvline;
    }
    char *_head;
    int _len;
    char* _recvline;
}; 

TEST_F(ScanHeaderTest,GoodPUTSingleLine) { 
  ScanHeader sh(201);
  //single valid header line
  strcpy(_recvline,"HTTP/1.0 201 OK\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT1402338524102000101470\r\n\r\n");
  ASSERT_TRUE(sh.scan(_recvline,strlen(_recvline),&_head,_len));
  ASSERT_TRUE(sh.get_found_status());
  ASSERT_TRUE(sh.finished_header());
  ASSERT_EQ(sh.get_status(),201);
}

TEST_F(ScanHeaderTest,GoodPUTMultipleLines) { 
  ScanHeader sh(201);
  //Header broken up into different calls
  strcpy(_recvline,"HTTP/1.0 20");
  ASSERT_TRUE(sh.scan(_recvline,11,&_head,_len));
  strcpy(_recvline,"1 OK\r\nContent-Length: 13\r");
  ASSERT_TRUE(sh.scan(_recvline,28,&_head,_len));
  strcpy(_recvline,"\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88a");
  ASSERT_TRUE(sh.scan(_recvline,73,&_head,_len));
  strcpy(_recvline,"f\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT1402338524102000101470\r\n\r\n");
  ASSERT_TRUE(sh.scan(_recvline,84,&_head,_len));
  ASSERT_TRUE(sh.get_found_status());
  ASSERT_EQ(sh.get_status(),201);
  ASSERT_TRUE(sh.finished_header());
}

TEST_F(ScanHeaderTest,BadPUT404) {
  ScanHeader sh(201);
  //Failed return value, but properly formed
  strcpy(_recvline,"HTTP/1.0 404 OK\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT1402338524102000101470\r\n\r\n");
  ASSERT_FALSE(sh.scan(_recvline,strlen(_recvline),&_head,_len));
  ASSERT_EQ(sh.get_status(),404);
}

TEST_F(ScanHeaderTest,BadPUTMissingStatus) {
  ScanHeader sh(201);
  strcpy(_recvline,"HTTP/1.0 OK\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT1402338524102000101470\r\n\r\n");
  ASSERT_FALSE(sh.scan(_recvline,strlen(_recvline),&_head,_len));
  ASSERT_EQ(sh.get_status(),0);
}

TEST_F(ScanHeaderTest,BadPUTMissingHTTP) {
  ScanHeader sh(201);
  strcpy(_recvline,"200 FALSE\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT1402338524102000101470\r\n\r\n");
  ASSERT_FALSE(sh.scan(_recvline,strlen(_recvline),&_head,_len));
  ASSERT_EQ(sh.get_status(),0);
}

TEST_F(ScanHeaderTest,BadPUTUnterminatedHeader) {
  ScanHeader sh(201);
  //Failed return value, but properly formed
  strcpy(_recvline,"HTTP/1.0 201 OK\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT1402338524102000101470\r\n\r");
  ASSERT_TRUE(sh.scan(_recvline,strlen(_recvline),&_head,_len));
  ASSERT_EQ(sh.get_status(),201);
  ASSERT_FALSE(sh.finished_header());
}

TEST_F(ScanHeaderTest,GoodGETSingleLine) { 
  ScanHeader sh(200);
  //Single valid
  strcpy(_recvline,"HTTP/1.0 200 OK\r\nServer: dbattery/1.1\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT14055236907630007\r\n\r\nMySecondEntry");
  ASSERT_TRUE(sh.scan(_recvline,strlen(_recvline),&_head,_len));
  ASSERT_TRUE(sh.get_found_status());
  ASSERT_EQ(sh.get_status(),200);
  ASSERT_TRUE(sh.finished_header());
  ASSERT_STREQ(_head,"MySecondEntry");
}

TEST_F(ScanHeaderTest,RobustTest) { 
  ScanHeader sh(200);
  //Single valid
  strcpy(_recvline,"HTTP/1.0 200 OK\r\nServer: dbattery/1.1\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT14055236907630007\r\n\r\nMySecondEntry");
  for (uint i = 0; i < 1000000; ++i) {
    ScanHeader sh(200);
    ASSERT_TRUE(sh.scan(_recvline,strlen(_recvline),&_head,_len));
  }
  //ASSERT_TRUE(sh.get_found_status());
 // ASSERT_EQ(sh.get_status(),200);
  //ASSERT_TRUE(sh.finished_header());
  //ASSERT_STREQ(_head,"MySecondEntry");
}


TEST_F(ScanHeaderTest,GoodGETMultipleLines) { 
  ScanHeader sh(200);
  //Single valid
  strcpy(_recvline,"HTTP/1.0 200 OK\r\nServer: dbattery/1.1\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT14055236907630007\r\n\r\nMySecondEntry");
  strcpy(_recvline,"HTTP/1.");
  ASSERT_TRUE(sh.scan(_recvline,7,&_head,_len));
  strcpy(_recvline,"0 200 OK");
  ASSERT_TRUE(sh.scan(_recvline,8,&_head,_len));
  strcpy(_recvline,"\r\nServer: dbattery/1.1\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT14055236907630007");
  ASSERT_TRUE(sh.scan(_recvline,192,&_head,_len));
  strcpy(_recvline,"\r\n\r\n");
  ASSERT_TRUE(sh.scan(_recvline,8,&_head,_len));
  strcpy(_recvline,"MySecondEntry");
  ASSERT_TRUE(sh.scan(_recvline,8,&_head,_len));

  ASSERT_TRUE(sh.get_found_status());
  ASSERT_EQ(sh.get_status(),200);
  ASSERT_TRUE(sh.finished_header());
  ASSERT_STREQ(_head,"MySecondEntry");
}

TEST_F(ScanHeaderTest,BadGETNoContent) { 
  ScanHeader sh(200);
  //Single valid
  strcpy(_recvline,"HTTP/1.0 200 OK\r\nServer: dbattery/1.1\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT14055236907630007\r\n\rMySecondEntry");
  ASSERT_TRUE(sh.scan(_recvline,strlen(_recvline),&_head,_len));
  ASSERT_TRUE(sh.get_found_status());
  ASSERT_EQ(sh.get_status(),200);
  ASSERT_FALSE(sh.finished_header());
  ASSERT_STRNE(_head,"MySecondEntry");
}

TEST_F(ScanHeaderTest,BadGETStatus) { 
  ScanHeader sh(200);
  //Single valid
  strcpy(_recvline,"HTTP/1.0 404 OK\r\nServer: dbattery/1.1\r\nContent-Length: 13\r\nETag: \"7650ddb2d4e19847dd323f044604d3625bb7c0672a9083134acef328f50e88af\"\r\nContent-Type: CanBeAnything\r\nSupport-Id: V1GT14055236907630007\r\n\r\nMySecondEntry");
  ASSERT_FALSE(sh.scan(_recvline,strlen(_recvline),&_head,_len));
  ASSERT_TRUE(sh.get_found_status());
  ASSERT_EQ(sh.get_status(),404);
}

class DBIndexTest : public ::testing::Test {
  protected:
    DBIndexTest() {
      _db_index.set_last_key(10);
      _db_index.set_first_key(2);
      _db_index.update_timestamp();
    }
    ~DBIndexTest() {
    }
    DBIndex _db_index;
}; 

TEST_F(DBIndexTest,Serialize) {
  string data;
  _db_index.serialize_to_string(&data);
  DBIndex tmp;
  tmp.parse_from_string(data);
  ASSERT_EQ(_db_index,tmp);
}

TEST_F(DBIndexTest,Keys) {
  vector<string> keys;
  //Check if you go to low, it defaults to first key
  _db_index.get_all_keys_from_key(1,keys);
  ASSERT_EQ((int)keys.size(),9);
  ASSERT_EQ(keys[0],"2");
  ASSERT_EQ(keys[8],"10");
  //Check you get only keys from 3
  _db_index.get_all_keys_from_key(3,keys);
  ASSERT_EQ((int)keys.size(),8);
  ASSERT_EQ(keys[0],"3");
  ASSERT_EQ(keys[7],"10");
  //Check you get all keys
  _db_index.get_all_keys("127.0.0.1",keys);
  ASSERT_EQ((int)keys.size(),9);
  ASSERT_EQ(keys[0],"127.0.0.1.2");
  ASSERT_EQ(keys[8],"127.0.0.1.10");
  //Check you get all keys from 0
  _db_index.get_all_keys_from_zero("127.0.0.1",keys);
  ASSERT_EQ((int)keys.size(),11);
  ASSERT_EQ(keys[0],"127.0.0.1.0");
  ASSERT_EQ(keys[8],"127.0.0.1.8");
  //Check you get all keys from 3
  _db_index.get_all_keys_from_key("127.0.0.1",3,keys);
  ASSERT_EQ((int)keys.size(),8);
  ASSERT_EQ(keys[0],"127.0.0.1.3");
  ASSERT_EQ(keys[7],"127.0.0.1.10");
  //Get last key
  string last_key;
  _db_index.get_last_key(last_key);
  ASSERT_EQ(last_key,"10");
  //Get last key with prefix
  _db_index.get_last_key("127.0.0.1",last_key);
  ASSERT_EQ(last_key,"127.0.0.1.10");
  //Check that new index has only 0 as key
  DBIndex localIndex;
  localIndex.get_all_keys("127.0.0.1",keys);
  ASSERT_EQ((int)keys.size(),1);
  ASSERT_EQ(keys[0],"127.0.0.1.0");
  //Add a key
  ASSERT_EQ(_db_index.first_key(),2);
  ASSERT_EQ(_db_index.last_key(),10);
  string new_key = _db_index.add_key();
  ASSERT_EQ(new_key,"11");
  ASSERT_EQ(_db_index.last_key(),11);
}

//Stub out the GET and PUT methods to just access a local map.  GET/PUT tested above with true
//  databattery calls.  Now I want to test the code that uses them which don't care if they are
//  talking to DataBattery or a local table (which is much,much faster).
class DataBatteryTest: public DataBattery {
  public:
    DataBatteryTest(const DataBattery::Settings& settings,
        map<string,map<string,string> >* table_key_value) 
      : DataBattery(settings)
      , _table_key_value(table_key_value)
    {}
    virtual bool GET(string table, string key, string& value) {
      if (_table_key_value->find(table) == _table_key_value->end()) {
        set_status(404);
        return false;
      }
      if ((*_table_key_value)[table].find(key) == (*_table_key_value)[table].end()) {
        set_status(404);
        return false;
      }
      value = (*_table_key_value)[table][key];
      return true;
    }
    virtual bool PUT(string table, string key, string value) {
      if (_table_key_value->find(table) == _table_key_value->end()) {
        set_status(404);
        return false;
      }
      (*_table_key_value)[table][key] = value;
      return true;
    }
  private:
    //Normally DataBattery would talk to actual DataBattery service, which is shared by all.  To simulate this the
    //  actual map below must be shared across all DataBattery instances in a test.  I can't use static because
    //  I want it to automatically reset for each test.  Thus the table is passed in as a pointer and must be 
    //  stored in the test class (like PeersTest).
    map<string,map<string,string> >* _table_key_value;
};

//Want to control time so create a Peers class that controls time
class PeersForTest: public Peers {
  public:
    PeersForTest()
      : Peers(0,0,6) 
      , _time(0)
      , _first_GET_match(true)
    {}
    virtual uint64_t get_time() const { return _time; }
    //Doing something hacky here to test update_peer.  I'm going to grab the peers when I 
    //  see a given ID and remove it and put in something else one time.  peers should detect
    //  that it wasn't added, and re-add it
    virtual bool GET(DataBattery* db, std::string tablename) {
      bool ret = Peers::GET(db,tablename);
      if (_first_GET_match && get_order("222.222.222.222") != -1) {
        incr_time(2);
        update_timestamp("222.222.222.222",get_time());
        update_timestamp("333.333.333.333",get_time());
        _first_GET_match = false;
      }
      return ret;
    }
    void incr_time(uint64_t t) { _time += t; }
    bool operator==(const PeersForTest& other) const {
      if (get_msg().peers_size() != other.get_msg().peers_size()) { return false; }
      for (int i = 0; i < get_msg().peers_size(); ++i) {
        if (get_msg().peers(i).timestamp() != other.get_msg().peers(i).timestamp() ||
            get_msg().peers(i).id() != other.get_msg().peers(i).id()) { 
          return false;
        }
      }
      return true;
    }

  private:
    uint64_t _time;
    bool _first_GET_match;
};

//Note that although we actually generate random 128bit strings instead of IPs
//as identifiers, it's easier to leave them as IPs in the test. 
class PeersTest : public ::testing::Test {
  protected:
    PeersTest() {
      DataBattery::Settings db_settings("ct",FLAGS_db_hostname,"443",
          "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.crt.pem",
          "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.key.pem", 5,0);
      _db = new DataBatteryTest(db_settings,&_table_key_value);
      _pending_table = "test_pending";
      _table_key_value["test_pending"];
    }
    ~PeersTest() {
      if (_db) { delete _db; }
    }
    void add_a_few_peers() {
      _peers.update_timestamp("127.0.0.1",_peers.get_time()); _peers.incr_time(2);
      _peers.update_timestamp("127.0.0.2",_peers.get_time()); _peers.incr_time(2);
      _peers.update_timestamp("127.0.0.3",_peers.get_time()); _peers.incr_time(2);
      _peers.update_timestamp("127.0.0.4",_peers.get_time()); _peers.incr_time(2);
    }

    DataBatteryTest* _db;
    PeersForTest _peers;
    string _pending_table;
    map<string,map<string,string> > _table_key_value;
};

TEST_F(PeersTest,Serialize) {
  add_a_few_peers();
  string data;
  ASSERT_TRUE(_peers.serialize_to_string(&data));
  PeersForTest local_peers;
  ASSERT_TRUE(local_peers.parse_from_string(data));
  ASSERT_EQ(_peers,local_peers);
}

TEST_F(PeersTest,PeerSet) {
  add_a_few_peers();
  set<string> peers;
  _peers.get_peer_set(peers);
  set<string> expected; 
  expected.insert("127.0.0.1"); expected.insert("127.0.0.2");
  expected.insert("127.0.0.3"); expected.insert("127.0.0.4");
  ASSERT_EQ(peers,expected);
}

TEST_F(PeersTest,RemoveDeadPeers) {
  add_a_few_peers();
  //Should remove all but 2
  _peers.remove_dead_peers(4);
  set<string> peers;
  _peers.get_peer_set(peers);
  set<string> expected;
  expected.insert("127.0.0.3"); expected.insert("127.0.0.4");
  ASSERT_EQ(peers,expected);
  set<string> removed_peers;
  _peers.get_removed_peer_set(removed_peers,1);
  expected.clear(); expected.insert("127.0.0.1"); expected.insert("127.0.0.2");
  ASSERT_EQ(removed_peers,expected);
  _peers.incr_time(4);
  //Should remove all
  _peers.remove_dead_peers(4);
  _peers.get_peer_set(peers);
  ASSERT_TRUE(peers.empty());
  _peers.get_removed_peer_set(removed_peers,1);
  expected.clear(); expected.insert("127.0.0.1"); expected.insert("127.0.0.2");
  expected.insert("127.0.0.3"); expected.insert("127.0.0.4");
  ASSERT_EQ(removed_peers,expected);
  //Try removing some of the removed peers (just 127.0.0.1 and 127.0.0.2)
  set<string> tmp_peers; tmp_peers.insert("127.0.0.1"); tmp_peers.insert("127.0.0.2");
  _peers.clear_removed_peers(tmp_peers);
  _peers.get_removed_peer_set(removed_peers,1);
  expected.clear(); expected.insert("127.0.0.3"); expected.insert("127.0.0.4");
  ASSERT_EQ(removed_peers,expected);
  //Clear out the remaining removed peers
  _peers.clear_removed_peers(expected);
  _peers.get_removed_peer_set(removed_peers,1);
  ASSERT_TRUE(removed_peers.empty());
  add_a_few_peers();
  //Should remove nothing
  _peers.remove_dead_peers(100);
  _peers.get_peer_set(peers);
  expected.insert("127.0.0.1"); expected.insert("127.0.0.2");
  ASSERT_EQ(peers,expected);
  _peers.get_removed_peer_set(removed_peers,1);
  ASSERT_TRUE(removed_peers.empty());
}

TEST_F(PeersTest,Find) {
  add_a_few_peers();
  ASSERT_TRUE(_peers.find("127.0.0.1",0));
  ASSERT_TRUE(_peers.find("127.0.0.2",2));
  ASSERT_FALSE(_peers.find("127.0.0.5",2));
  ASSERT_FALSE(_peers.find("127.0.0.2",4));
}

TEST_F(PeersTest,Order) {
  add_a_few_peers();
  ASSERT_EQ(_peers.get_order("127.0.0.1"),0);
  ASSERT_EQ(_peers.get_order("127.0.0.3"),2);
  ASSERT_EQ(_peers.get_order("127.0.0.5"),-1);
  //Make sure adding some doesn't mess up order
  _peers.update_timestamp("127.0.0.8",10);
  _peers.update_timestamp("127.0.0.5",10);
  ASSERT_EQ(_peers.get_order("127.0.0.3"),2);
  ASSERT_EQ(_peers.get_order("127.0.0.5"),5);
  ASSERT_EQ(_peers.get_order("127.0.0.8"),4);
}

TEST_F(PeersTest,GET_PUT) {
  add_a_few_peers();
  ASSERT_TRUE(_peers.PUT(_db,_pending_table));
  ASSERT_FALSE(_peers.PUT(_db,"bogus_table"));
  PeersForTest local_peers;
  ASSERT_TRUE(local_peers.GET(_db,_pending_table));
  ASSERT_EQ(_peers,local_peers);
}

TEST_F(PeersTest,UpdatePeer) {
  add_a_few_peers();
  //Simple insertion tests
  string new_id("127.0.0.10");
  ASSERT_EQ(_peers.get_order(new_id),-1);
  ASSERT_TRUE(_peers.update_peer("127.0.0.10",_db,_pending_table));
  ASSERT_NE(_peers.get_order(new_id),-1);
  ASSERT_FALSE(_peers.update_peer("127.0.0.11",_db,"bogus_table"));
  //More complicated test to see if it's detected that we didn't get added with the correct
  //  timestamp and someone else got added.  Re-add and then both should be there
  ASSERT_TRUE(_peers.update_peer("222.222.222.222",_db,_pending_table));
  ASSERT_TRUE(_peers.find("222.222.222.222",_peers.get_time()));
  ASSERT_TRUE(_peers.find("333.333.333.333",_peers.get_time()));
  ASSERT_EQ(_peers.get_order("333.333.333.333"),_peers.get_order("222.222.222.222")+1);
}

TEST_F(PeersTest,ID) {
  string id_1 = Peers::randByteString(16);
  string id_2 = Peers::randByteString(16);
  ASSERT_NE(id_1,id_2);
  ASSERT_EQ((int)id_1.length(),32);
}

class QueryTest : public ::testing::Test {
  protected:
    QueryTest() 
      : _query_dir("query.test")
    {
      mkdir(_query_dir.c_str(),S_IRWXU|S_IRWXG|S_IRWXO);
      _myid = Peers::randByteString(16);
      if (!query_interface::instance()) {
        query_interface::init(_query_dir,_myid);
      }
    }
    string read_file(string filename) {
      ifstream ifs(filename.c_str());
      if (ifs.fail()) { return "false"; } 
      string contents;
      while (!ifs.eof()) {
        string tmp; 
        ifs >> tmp;
        contents.append(tmp);
      }
      return contents;
    }

    ~QueryTest() { }
    string _query_dir;
    string _myid;
};

TEST_F(QueryTest,QueryTables) {
  //Fill main data
  ct_main_data_def* data = query_interface::instance()->get_main_data();
  data->_myid = _myid;
  data->_start_time = 500;
  data->_root_hash = "imustbeexactlythirtytwobyteslong";
  //Fill cert_info
  ct_cert_info_data_def::info inf;
  inf._cert_type = "x509";
  inf._subject = "\"C=GB, O=Certificate Transparency, ST=Wales, L=Erw Wen\"";
  inf._issuer = "\"C=GB, O=Certificate Transparency, ST=Wales, L=Erw Wen\"";
  inf._not_before = "Jun  1 00:00:00 2012 GMT";
  inf._not_after = "Jun  1 00:00:00 2022 GMT";
  query_interface::instance()->get_cert_info_data()->_info.push_back(inf);
  inf._cert_type = "pre-cert";
  inf._subject = "\"C=GB, O=Certificate Transparency, ST=Wales, L=Erw Wen\"";
  inf._issuer = "\"C=GB, O=Certificate Transparency, ST=Wales, L=Erw Wen\"";
  inf._not_before = "Jun  1 00:00:00 2012 GMT";
  inf._not_after = "Jun  1 00:00:00 2022 GMT";
  query_interface::instance()->get_cert_info_data()->_info.push_back(inf);
  query_interface::instance()->get_cert_info_data()->_myid = _myid;
  //Fill stats info 
  query_interface::instance()->get_stats_data()->_myid = _myid;
  query_interface::instance()->get_stats_data()->_tree_size = 19;
  query_interface::instance()->get_stats_data()->_leaves_time = 5;
  query_interface::instance()->get_stats_data()->_peers_time = 6;
  query_interface::instance()->get_stats_data()->_commit_time = 7;
  query_interface::instance()->get_stats_data()->_config_time = 8;
  //request hits
  vector<uint32_t> bucket_sets;
  bucket_sets.push_back(1); bucket_sets.push_back(3); bucket_sets.push_back(12);
  query_interface::instance()->req_count_init(_myid,bucket_sets,2);
  query_interface::instance()->process_hit(RequestStats::GETROOTS);
  query_interface::instance()->process_hit(RequestStats::GETROOTS);
  query_interface::instance()->process_hit(RequestStats::GETENTRIES);
  query_interface::instance()->process_hit(RequestStats::GETPRBYHS);
  query_interface::instance()->process_hit(RequestStats::GETSTH);
  query_interface::instance()->process_hit(RequestStats::GETSTHCNS);
  query_interface::instance()->process_hit(RequestStats::ADDCHAIN);
  query_interface::instance()->process_hit(RequestStats::ADDPRECHAIN);
  sleep(3); //Sleep a couple of second to allow rotate to work next time
  query_interface::instance()->process_hit(RequestStats::GETROOTS);

  //Update the tables
  query_interface::instance()->update_tables();

  //Check against gold
  string contents = read_file(_query_dir+string("/appbatt_app_ct_main.csv"));
  ASSERT_NE("false",contents);
  ASSERT_TRUE(contents.find("500,imustbeexactlythirtytwobyteslong")!= string::npos);

  contents = read_file(_query_dir+string("/appbatt_app_ct_cert_info.csv"));
  ASSERT_NE("false",contents);
  ASSERT_TRUE(contents.find(",x509,") != string::npos);
  ASSERT_TRUE(contents.find(",pre-cert,") != string::npos);

  contents = read_file(_query_dir+string("/appbatt_app_ct_stats.csv"));
  ASSERT_NE("false",contents);
  ASSERT_TRUE(contents.find("19,5,6,7,8") != string::npos);

  contents = read_file(_query_dir+string("/appbatt_app_ct_req_count.csv"));
  ASSERT_NE("false",contents);
  ASSERT_TRUE(contents.find("get-roots,2,1,2") != string::npos);
  ASSERT_TRUE(contents.find("get-roots,2,3,2") != string::npos);
  ASSERT_TRUE(contents.find("get-roots,2,12,2") != string::npos);
  ASSERT_TRUE(contents.find("get-sth,2,1,1") != string::npos);
}

class CertTablesTest : public ::testing::Test {
  protected:
    CertTablesTest() 
      : _test_signer()
      , _num_instances(3)
      , _num_certs(5)
    {
      //Common db settings
      DataBattery::Settings db_settings("ct",FLAGS_db_hostname,"443",
          "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.crt.pem",
          "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.key.pem", 5,0);
      //Test config
      ct::AkamaiConfig test_config;
      test_config.set_db_max_entry_size(7000);
      test_config.set_fixed_peer_delay(0);
      test_config.set_random_peer_delay(0);
      test_config.set_max_peer_age(3600000);
      test_config.set_db_leaves("test_leaves");
      test_config.set_db_pending("test_pending");
      test_config.set_leaves_update_freq(0);
      //Initialize tables in local data maps
      _table_key_value["test_pending"];
      _table_key_value["test_leaves"];
      //Create a number of instances of committers
      for (uint i = 1; i < _num_instances+1; ++i) {
        _pdv.push_back(new PendingData());
        _ldv.push_back(new LeavesData());
        _hbdv.push_back(new HeartBeatData());
        _hbdv.back()->update_time();
        _cnfgdv.push_back(new ConfigData(test_config));
        //Create leaves thread data so we can invoke leaves_helper which updates a list of leaves from the DB
        DataBatteryTest* dblt = new DataBatteryTest(db_settings,&_table_key_value);
        _ltdv.push_back(new leaves_thread_data(dblt,_ldv.back(),
              _cnfgdv.back()));
        //Create the actual committer (equivalent to cert_tables instance)
        stringstream ss; ss << "127.0.0." << i;
        DataBatteryTest* db = new DataBatteryTest(db_settings,&_table_key_value);
        _cert_tablesv.push_back(new CertTables(db,ss.str(),_pdv.back(),_ldv.back(),
              _hbdv.back(),_cnfgdv.back()));
        _cert_tablesv.back()->init_pending_data(_pdv.back());
        //Insert new committer into peers
        Peers p(_cnfgdv.back()->fixed_peer_delay(),_cnfgdv.back()->random_peer_delay(),
            _cnfgdv.back()->max_peer_age());
        p.update_peer(_cert_tablesv.back()->get_my_id(),_cert_tablesv.back()->get_db(),
            _cert_tablesv.back()->get_pending_table_name());
      }
    }
    ~CertTablesTest() 
    {
      for (uint i = 0; i < _num_instances; ++i) {
        if (_pdv[i]) { delete _pdv[i]; }
        if (_ldv[i]) { delete _ldv[i]; }
        if (_hbdv[i]) { delete _hbdv[i]; }
        if (_ltdv[i]) { delete _ltdv[i]; }
        if (_cert_tablesv[i]) { delete _cert_tablesv[i]; }
      }
    }

    TestSigner _test_signer;
    vector<leaves_thread_data*> _ltdv;
    vector<PendingData*> _pdv;
    vector<LeavesData*> _ldv;
    vector<HeartBeatData*> _hbdv;
    vector<ConfigData*> _cnfgdv;
    vector<CertTables*> _cert_tablesv;
    uint _num_instances;
    uint _num_certs;
    map<string,map<string,string> > _table_key_value;
};

/* This is kind of a mondo test, that exercises not only the PendingAdd, but also the commit and 
 * get_all_leaves.  The reason for covering so much in a single test is that it's hard to check just the 
 * individual pieces.  By doing both I can check what i'm adding to pending, and what comes out from the leaves
 * when we commit everything.  They should match.
 *   We have multiple IDs (_num_instances) and a low enough data size that it's split across multiple keys in
 * each sub-pending table.
 */
TEST_F(CertTablesTest, FullTest) {
  set<string> pending_hashes;
  for (int k = 0; k < 10; ++k) {
    //Add pending through each committer
    for (uint i = 0; i < _num_instances; ++i) {
      LOG(ERROR) << "id:"<<_cert_tablesv[i]->get_my_id() << " i:"<<i<<" order:"<<_cert_tablesv[i]->get_peer_order();
      ASSERT_EQ(_cert_tablesv[i]->get_peer_order(),(int)i);
      cert_trans::LoggedCertificate logged_cert;
      for (uint j = 0; j < _num_certs; ++j) {
        _test_signer.CreateUnique(&logged_cert);
        ASSERT_TRUE(_cert_tablesv[i]->pending_add(&logged_cert));
        pending_hashes.insert(logged_cert.Hash());
      }
    }
    //Which committer
    uint commitIndex = k%_num_instances;
    //Commit pending 
    ASSERT_TRUE(_cert_tablesv[commitIndex]->commit_pending(0,0));
    //Get the leaves table (i.e. what was committed)
    ASSERT_EQ(leaves_helper(_ltdv[commitIndex]),LONG_SLEEP); 
    for (int i = 0; i < _ltdv[commitIndex]->_ld->_leaves.logged_certificate_pbs_size(); ++i) {
      const ct::LoggedCertificatePB& lcpb = _ltdv[commitIndex]->_ld->_leaves.logged_certificate_pbs(i);
      //Check that the leaves have sequential id's starting from 0
      ASSERT_EQ(lcpb.sequence_number(),(uint)i);
    }
    //Check that all the pending certs got committed as leaves
    ASSERT_EQ(_ltdv[commitIndex]->_ld->_leaves_hash.size(),pending_hashes.size());
    ASSERT_EQ(_ltdv[commitIndex]->_ld->_leaves_hash,pending_hashes);
    for (uint i = 0; i < _num_instances; ++i) {
      uint last_key = _cert_tablesv[i]->get_pd()->_pending_index.last_key();
      _cert_tablesv[i]->clear_pending(_ltdv[commitIndex]->_ld->_leaves_hash);
      //Check that you removed all the committed keys except the last one
      ASSERT_EQ(_cert_tablesv[i]->get_pd()->_pending_index.first_key(),last_key);
    }
  }
}

class DBTest : public ::testing::Test {
  protected:
    DBTest() {
      DataBattery::Settings db_settings("ct",FLAGS_db_hostname,"443",
          "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.crt.pem",
          "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.key.pem", 5,0);
      _db = new DataBattery(db_settings);
      _leaves_table = "test_leaves";
      _pending_table = "test_pending";
      _index = "index";
      _max_entry_size = 7000; 
    }
    ~DBTest() {
      delete _db;
    }
    uint randLimit(uint lb, uint ub) {
      if (ub <= lb) { return lb; }
      return lb+static_cast<uint>(rand() * 1.0/RAND_MAX * (ub-lb));
    }
    DataBattery* _db;
    string _leaves_table;
    string _pending_table;
    string _index;
    uint _max_entry_size;
}; 

TEST_F(DBTest,Index) {
  DBIndex index;
  index.set_first_key(randLimit(1,6));
  index.set_last_key(randLimit(9,12));
  ASSERT_TRUE(_db->put_index(_leaves_table,_index,index));
  DBIndex read_index;
  ASSERT_TRUE(_db->get_index(_leaves_table,_index,read_index));
  ASSERT_EQ(index,read_index);
}

TEST_F(DBTest,PUT_GET) {
  uint randVal = randLimit(1,1000);
  stringstream ss;
  ss << "value." << randVal;
  string value = ss.str();
  ASSERT_TRUE(_db->PUT(_leaves_table,"0",value));
  string get_val;
  ASSERT_TRUE(_db->GET(_leaves_table,"0",get_val));
  ASSERT_EQ(value,get_val);
  //Add another key so I can test get_keys_from_table
  ASSERT_TRUE(_db->PUT(_leaves_table,"1",value));
  vector<string> keys;
  keys.push_back("0"); keys.push_back("1");
  vector<string> data;
  ASSERT_TRUE(_db->GET_keys_from_table(_leaves_table,keys,_max_entry_size,data));
  ASSERT_EQ(data[0],value);
  ASSERT_EQ(data[1],value);
  string tmp;
  ASSERT_TRUE(_db->GET_key_from_table(_leaves_table,"0",_max_entry_size,tmp));
  ASSERT_EQ(tmp,value);
  //Try getting the DB request_bytes limit
  ASSERT_TRUE(_db->GETLIMIT("request_bytes",tmp));
  ASSERT_EQ("5242880",tmp);

  //Try to put into a non-existant table
  ASSERT_FALSE(_db->PUT("BogusTable","0",value));
  ASSERT_EQ(_db->get_error_status(),404);
  //Try getting from a non-existant table
  ASSERT_FALSE(_db->GET("BogusTable","BogusKey",value));
  ASSERT_EQ(_db->get_error_status(),404);
  ASSERT_FALSE(_db->GET(_leaves_table,"BogusKey",value));
  ASSERT_EQ(_db->get_error_status(),404);
}

TEST_F(DBTest,DBSetup) {
  //Incorrect app, so data battery returns 404
  DataBattery::Settings db_settings("foo",FLAGS_db_hostname,"443",
      "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.crt.pem",
      "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.key.pem", 5,0);
  DataBattery* local_db = new DataBattery(db_settings);
  string value("Blank");
  ASSERT_FALSE(local_db->GET(_leaves_table,"0",value));
  ASSERT_EQ(local_db->get_error_status(),404);
  delete local_db;
  //Incorrect hostname
  DataBattery::Settings db_settings2("ct","broken.hostname.com","443",
      "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.crt.pem",
      "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.key.pem", 5,0);
  local_db = new DataBattery(db_settings2);
  ASSERT_FALSE(local_db->GET(_leaves_table,"0",value));
  ASSERT_EQ(local_db->get_error_status(),-1);
  delete local_db;
  //Wrong port
  DataBattery::Settings db_settings3("ct",FLAGS_db_hostname,"445",
      "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.crt.pem",
      "../../test/akamai_testdata/dcurrie_testnet_kdc_ca.key.pem", 5,0);
  local_db = new DataBattery(db_settings3);
  ASSERT_FALSE(local_db->GET(_leaves_table,"0",value));
  ASSERT_EQ(local_db->get_error_status(),-1);
  delete local_db;
  //Bad key location
  DataBattery::Settings db_settings4("ct",FLAGS_db_hostname,"443",
      "../../test/akamai_testdat/dcurrie_testnet_kdc_ca.crt.pem",
      "../../test/akamai_testdat/dcurrie_testnet_kdc_ca.key.pem", 0,0);
  local_db = new DataBattery(db_settings4);
  ASSERT_FALSE(local_db->is_good());
  delete local_db;
  //Wrong user 
  DataBattery::Settings db_settings5("ct",FLAGS_db_hostname,"443",
      "../../test/akamai_testdata/bogus_testnet_kdc_ca.crt.pem",
      "../../test/akamai_testdata/bogus_testnet_kdc_ca.key.pem", 5,0);
  local_db = new DataBattery(db_settings5);
  ASSERT_FALSE(local_db->GET(_leaves_table,"0",value));
  ASSERT_EQ(local_db->get_error_status(),403);
  delete local_db;
  //Key signed by the wrong CA, not accepted by DataBattery
  DataBattery::Settings db_settings6("ct",FLAGS_db_hostname,"443",
      "../../test/akamai_testdata/bogus2_testnet_kdc_ca.crt.pem",
      "../../test/akamai_testdata/bogus2_testnet_kdc_ca.key.pem", 5,0);
  local_db = new DataBattery(db_settings6);
  ASSERT_FALSE(local_db->GET(_leaves_table,"0",value));
  ASSERT_EQ(local_db->get_error_status(),-1);
  delete local_db;
}

} //namespace
    
int main(int argc, char **argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}

