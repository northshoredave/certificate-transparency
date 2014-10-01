#include "log/akamai-query.h"
#include <glog/logging.h>

using namespace std;
using namespace Akamai;

typedef void (*ct_query_callback)(ofstream& ofs, const void* user_arg);

/******** Main Table ************/
static q2_column_description ct_main_columns[] = {
  {"myid",     "ct instance id", Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"now",      "current time",  Q2_TIME,   Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"start",    "start time",    Q2_TIME,   Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"root_hash","root hash",Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  Q2_END_COLUMN
};

static struct ct_main_data_def ct_main_data;

void query_interface::update_main(const ct_main_data_def* d) {
  pthread_mutex_lock(&_mutex);
  ct_main_data = *d;
  pthread_mutex_unlock(&_mutex);
}

void main_callback(std::ofstream& ofs,const void* user_arg) {
  LOG(INFO) << "Main callback";
  const ct_main_data_def* args = (const ct_main_data_def *)user_arg;
  time_t current_time = time(0);

  ofs << args->_myid << ","
      << current_time << ","
      << args->_start_time << ","
      << args->_root_hash << endl;
}

/******* End Main Table *********/

/******* Cert Info table ***********/
static q2_column_description ct_cert_info_columns[] = {
  {"myid",     "ct instance id", Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"now",      "current time",  Q2_TIME,   Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"cert_type", "x509 or pre-cert", Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"subject", "subject", Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"issuer", "issuer", Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"not_before","not before field",Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"not_after","not after field",Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  Q2_END_COLUMN
};

static struct ct_cert_info_data_def ct_cert_info_data;

void query_interface::update_cert_info(const ct_cert_info_data_def* d) {
  pthread_mutex_lock(&_mutex);
  ct_cert_info_data = *d;
  pthread_mutex_unlock(&_mutex);
}

void cert_info_callback(std::ofstream& ofs,const void* user_arg) {
  LOG(INFO) << "Cert info callback";
  const ct_cert_info_data_def* args = (const ct_cert_info_data_def*)user_arg;
  time_t current_time = time(0);

  for (vector<ct_cert_info_data_def::info>::const_iterator i = args->_info.begin(); 
      i != args->_info.end(); ++i) {
  ofs << args->_myid << ","
      << current_time << ","
      << i->_cert_type << ","
      << "\"" << i->_subject << "\","
      << "\"" << i->_issuer << "\","
      << i->_not_before << ","
      << i->_not_after << endl;
  }
}

/******* Request Counts Tables ***********/
static q2_column_description ct_req_count_columns[] = {
  {"myid",     "ct instance id", Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"now",      "current time",  Q2_TIME,   Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"req_type", "request type", Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"bucket_time", "period of time for a bucket", Q2_INT, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"num_buckets", "Num of buckets in the given set", Q2_INT, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"hits", "Num of hits in this bucket set", Q2_INT, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  Q2_END_COLUMN
};

static struct ct_req_count_data_def ct_req_count_data;

void query_interface::update_req_count() {
  ct_req_count_data_def tmp;
  _req_counts.extract_data(tmp);
  pthread_mutex_lock(&_mutex);
  ct_req_count_data = tmp;
  pthread_mutex_unlock(&_mutex);
}

void req_count_callback(std::ofstream& ofs,const void* user_arg) {
  LOG(INFO) << "req_count_callback";
  const ct_req_count_data_def* args = (const ct_req_count_data_def *)user_arg;
  time_t current_time = time(0);

  for (map<string,vector<uint> >::const_iterator i = args->_request_to_counts.begin();
      i != args->_request_to_counts.end(); ++i) {
    vector<uint32_t>::const_iterator bsIt = args->_bucket_sets.begin();
    LOG(INFO) << " _bucket_sets.size " << args->_bucket_sets.size() << " h count " << i->second.size();
    for (vector<uint>::const_iterator hIt = i->second.begin(); 
        hIt != i->second.end(); ++hIt, ++bsIt) {
      ofs << args->_myid << ","
          << current_time << ","
          << i->first << ","
          << args->_bucket_time << ","
          << *bsIt << ","
          << *hIt << endl;
    }
  }
}

/******* End Request Counts Table ********/

/******* Stats Table **********/
static q2_column_description ct_stats_columns[] = {
  {"myid",   "ct_instance_id", Q2_STRING, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NULL_MERGING},
  {"now",    "current_time", Q2_TIME,   Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"tree_size", "number of certs committed", Q2_INT, Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"leaves_t","time that leaves were update from dB", Q2_TIME,   Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"heartbeat_t", "time that hearbeat/peers were updated", Q2_TIME,   Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"commit_t",    "time that we last commited", Q2_TIME,   Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  {"config_t",    "time that config was updated", Q2_TIME,   Q2_AGGREGATION_NONE, Q2_NOT_NULLABLE, Q2_NO_MERGING},
  Q2_END_COLUMN
};

static struct ct_stats_data_def ct_stats_data;

void query_interface::update_stats(const ct_stats_data_def* d) {
  pthread_mutex_lock(&_mutex);
  ct_stats_data = *d;
  pthread_mutex_unlock(&_mutex);
}

void stats_callback(ofstream& ofs, const void* user_arg) {
  const ct_stats_data_def *args = (const ct_stats_data_def *)user_arg;
  time_t current_time = time(0);

  ofs << args->_myid << ","
      << current_time << ","
      << args->_tree_size << ","
      << args->_leaves_time << ","
      << args->_peers_time << ","
      << args->_commit_time << ","
      << args->_config_time << endl; 
}
/********* End stats table *********/

/************* END OF TABLE SPECIFIC METHODS/DATA *****************/

//Generic methods and data structures
query_interface* query_interface::_instance = NULL;

query_interface* query_interface::instance() {
  return _instance;
}

void query_interface::init(string tableprov_directory,string myid) {
  _instance = new query_interface(tableprov_directory,myid);
}

struct table_schema {
  q2_table_schema _q2_schema;
  void* _data;
  ct_query_callback _callback;
};

static struct table_schema tables[] = {
  { {"ct_main", "Important instance details",ct_main_columns}, &ct_main_data, main_callback },
  { {"ct_cert_info", "Commited cert info",ct_cert_info_columns}, &ct_cert_info_data, cert_info_callback },
  { {"ct_stats","General run statistics",ct_stats_columns}, &ct_stats_data, stats_callback },
  { {"ct_req_count","How many hits each request type get over different time periods", ct_req_count_columns}, &ct_req_count_data, req_count_callback },
  { { 0 } }
};

void query_interface::update_table_data() {
  //Update table data before attempting to write them out
  update_req_count();
  update_stats(_stats_data);
  update_main(_main_data);
  update_cert_info(_cert_info_data);
}

bool query_interface::update_tables_on_disk() const {
  //Now write them to file
  table_schema* table_ptr = tables;
  while (table_ptr->_data) {
    LOG(INFO) << "Printing table " << table_ptr->_q2_schema.tablename;
    string source = _tableprov_directory + string("/") + string(table_ptr->_q2_schema.tablename) + string(".tmp");
    string dest = _tableprov_directory + string("/") + string(table_ptr->_q2_schema.tablename) + string(".csv");
    ofstream ofs(source.c_str());
    if (ofs.fail()) { 
      LOG(ERROR) << "Failed to write table " << table_ptr->_q2_schema.tablename;
      return false; 
    }

    print_schema(ofs,table_ptr->_q2_schema);
    pthread_mutex_lock(&_mutex);
    table_ptr->_callback(ofs,table_ptr->_data);
    pthread_mutex_unlock(&_mutex);
    ofs.close();
    rename(source.c_str(),dest.c_str());
    ++table_ptr;
  }
  return true;
}

void query_interface::print_schema(ofstream& ofs, const q2_table_schema& schema) const {
  //1. Version
  ofs << _version << endl; 
  //2. Table description
  ofs << schema.description << endl;
  //3. Column names
  const q2_column_description* start = schema.columns;
  if (start) { LOG(INFO) << "Columns not empty for " << schema.tablename; }
  else { LOG(INFO) << "Columns empty for " << schema.tablename; }
  while (start->name) {
    ofs << start->name;
    ++start;
    if (start->name) { ofs << ","; }
  }
  ofs << endl;
  //4. Column types
  start = schema.columns;
  while (start->name) {
    ofs << column_type_to_str(start->type);
    ++start;
    if (start->name) { ofs << ","; }
  }
  ofs << endl;
  //5. Column descriptions
  start = schema.columns;
  while (start->name) {
    ofs << start->description;
    ++start;
    if (start->name) { ofs << ","; }
  }
  ofs << endl;
}

string query_interface::column_type_to_str(q2_data_type t) const {
  switch (t) {
    case Q2_INT:
      return "int";
    case Q2_IPv4:
      return "ip";
    case Q2_TIME:
      return "time";
    case Q2_FLOAT:
      return "float";
    case Q2_IPv6:
      return "ip";
    case Q2_STRING:
      return "string";
    default:
      return "error";
  }
}

void HitCount::rotate() {
  _buckets.push_back(_cur_bucket);
  _cur_bucket = 0;
  if (_num_buckets_filled < _num_buckets) {
    ++_num_buckets_filled;
  } else {
    _buckets.pop_front();
  }
}

uint HitCount::count(uint num_buckets) const {
  uint tally(0);
  list<uint>::const_reverse_iterator rIt = _buckets.rbegin();
  for (uint i = 0; i < num_buckets && rIt != _buckets.rend(); ++i, ++rIt) {
    tally += *rIt;
  }
  return tally;
}

void RequestStats::rotate() {
  time_t current_time = time(0);
  //You need to rotate all buckets that exceed time from _last_rotate, not just the last one
  time_t tmp_last_rotate = _last_rotate;
  //Don't rotate more then the max num buckets, won't do anything more after that.
  uint32_t max_num_buckets = _bucket_sets.back();
  for (uint i = 0; i < max_num_buckets; ++i) {
    //Break out when you've rotated out enough or your bucket is current enough
    if (tmp_last_rotate >= current_time ||
        difftime(current_time,tmp_last_rotate) <= _bucket_time) {
      break;
    }
    for (vector<HitCount>::iterator i = _hit_counts.begin(); i != _hit_counts.end(); ++i) {
      i->rotate();
    }
    tmp_last_rotate += _bucket_time;
  }
  _last_rotate = tmp_last_rotate;
}

RequestStats::request_type RequestStats::str_to_request_type(string r) const {
  if (r == "/ct/v1/get-entries") {
    return GETENTRIES;
  } else if (r == "/ct/v1/get-roots") {
    return GETROOTS;
  } else if (r == "/ct/v1/get-proof-by-hash") {
    return GETPRBYHS;
  } else if (r == "/ct/v1/get-sth") {
    return GETSTH;
  } else if (r == "/ct/v1/get-sth-consistency") {
    return GETSTHCNS;
  } else if (r == "/ct/v1/add-chain") {
    return ADDCHAIN;
  } else if (r == "/ct/v1/add-pre-chain") {
    return ADDPRECHAIN;
  } else { 
    return LAST;
  }
  return LAST;
}

string RequestStats::request_type_to_str(RequestStats::request_type t) const {
  switch (t) {
    case GETENTRIES:
      return "get-entries";
    case GETROOTS:
      return "get-roots";
    case GETPRBYHS:
      return "get-proof-by-hash";
    case GETSTH:
      return "get-sth";
    case GETSTHCNS:
      return "get-sth-consistency";
    case ADDCHAIN:
      return "add-chain";
    case ADDPRECHAIN:
      return "add-pre-chain";
    default:
      return "unknown";
  }
  return "unknown";
}

void RequestStats::extract_data(ct_req_count_data_def& d) {
  rotate();
  d._myid = _myid;
  d._bucket_time = _bucket_time;
  d._request_to_counts.clear();
  d._bucket_sets = _bucket_sets;
  //Iterate over the different request types
  for (uint i = 0; i < LAST; ++i) {
    request_type r = static_cast<request_type>(i);
    string req_str = request_type_to_str(r);
    //Count up the hits for each bucket size
    for (vector<uint32_t>::const_iterator bsIt = _bucket_sets.begin();
        bsIt != _bucket_sets.end(); ++bsIt) {
      d._request_to_counts[req_str].push_back(get_count(r,*bsIt));
    }
  }
}
