#ifndef AKAMAI_QUERY_H
#define AKAMAI_QUERY_H
#include <query/q2lib.h>
#include <iostream>
#include <glog/logging.h>
#include <fstream>
#include <string>
#include <map>
#include <list>
#include <vector>

namespace Akamai {
  class HitCount {
    public:
      HitCount(uint num_buckets)
        : _num_buckets(num_buckets)
          , _cur_bucket(0)
          , _num_buckets_filled(0)
    {}
      void incr() { ++_cur_bucket; } 
      void rotate();
      uint count(uint num_buckets) const;

    private:
      uint _num_buckets; //How many window entries to keep
      uint _cur_bucket;
      std::list<uint> _buckets; //Hit count 
      uint _num_buckets_filled;
  };

  struct ct_req_count_data_def {
    ct_req_count_data_def() 
      : _myid("")
    {}

    std::string _myid;
    uint32_t _bucket_time;
    std::vector<uint32_t> _bucket_sets;
    std::map<std::string,std::vector<uint> > _request_to_counts;
  };

  class RequestStats {
    public:
      typedef enum { GETENTRIES=0, GETROOTS, GETPRBYHS, GETSTH, GETSTHCNS, ADDCHAIN, ADDPRECHAIN, LAST } request_type; 
      void init(std::string myid, const std::vector<uint>& bucket_sets, uint bucket_time) {
        _myid = myid;
        _bucket_time = bucket_time;
        _bucket_sets = bucket_sets; 
        if (bucket_sets.empty()) { 
          _hit_counts.resize(LAST,HitCount(1));
        } else {
          _hit_counts.resize(LAST,HitCount(bucket_sets.back()));
        }
        _last_rotate = time(0);
      }
      uint get_count(request_type r, uint num_buckets) const { 
        return _hit_counts[r].count(num_buckets); 
      }
      void process_hit(request_type r) { rotate(); process_hit_helper(r); }
      void extract_data(ct_req_count_data_def& d);

    private:
      void process_hit_helper(request_type r) { _hit_counts[r].incr(); }
      void rotate();
      request_type str_to_request_type(std::string r) const;
      std::string request_type_to_str(request_type t) const;
    private:
      std::string _myid;
      uint _bucket_time;
      time_t _last_rotate;
      std::vector<uint32_t> _bucket_sets;
      std::vector<HitCount> _hit_counts;
  };

  struct ct_main_data_def {
    ct_main_data_def()
      : _myid(""), _start_time(0)
    {}
    std::string _myid;
    time_t _start_time;
    std::string _root_hash;
  };

  struct ct_stats_data_def {
    ct_stats_data_def()
      : _myid("")
      , _tree_size(0)
      , _leaves_time(0)
      , _peers_time(0)
      , _commit_time(0)
      , _config_time(0)
    {}
    std::string _myid;
    uint64_t _tree_size;
    time_t _leaves_time;
    time_t _peers_time;
    time_t _commit_time;
    time_t _config_time;
  };

  struct ct_cert_info_data_def {
    struct info {
      std::string _cert_type;
      std::string _subject;
      std::string _issuer;
      std::string _not_before;
      std::string _not_after;
    };

    std::string _myid;
    std::vector<info> _info;
  };

  //Meant to capture all things akamai query.  For now I'm going to got the tableprov route which means I write out
  //a index and tables in .csv file and register with tableprov via the hostsetup script to read and publish those
  //tables.  However, I'm going to use the query2 structs so that I can easily switch to the programmatic interface
  //if I want to in the future.
  class query_interface {
    public:
      void update_main(const ct_main_data_def* d);
      void update_stats(const ct_stats_data_def* d);
      void update_req_count();
      void update_cert_info(const ct_cert_info_data_def* d);
      bool update_tables() { update_table_data(); return update_tables_on_disk(); } 
      //Make query interface a singleton so I can get at if from deep in ct code to update stats, etc
      static query_interface* instance();
      static void init(std::string tableprov_directory,std::string myid);

      //To minimize code change in google ct code, I'm keeping the query data here
      void req_count_init(std::string myid,const std::vector<uint32_t>& bucket_sets, 
          uint bucket_time) {
        _req_counts.init(myid,bucket_sets,bucket_time);
      }
      void process_hit(RequestStats::request_type r) { _req_counts.process_hit(r); } 
      ct_main_data_def* get_main_data() { return _main_data; }
      ct_stats_data_def* get_stats_data() { return _stats_data; }
      ct_cert_info_data_def* get_cert_info_data() { return _cert_info_data; }

    private:
      query_interface(std::string tableprov_directory,std::string myid) 
        : _version("1.0")
        , _myid(myid)
        , _tableprov_directory(tableprov_directory)
      {
        pthread_mutex_init(&_mutex,NULL);
        _stats_data = new ct_stats_data_def;
        _stats_data->_myid = _myid;
        _main_data = new ct_main_data_def;
        _main_data->_myid = _myid;
        _cert_info_data = new ct_cert_info_data_def;
        _cert_info_data->_myid = _myid;
      }
      ~query_interface() {
        if (_stats_data) { delete _stats_data; }
        if (_main_data) { delete _main_data; }
      }
      std::string column_type_to_str(q2_data_type t) const;
      bool write_table(std::string table) const;
      void print_schema(std::ofstream& ofs, const q2_table_schema& schema) const;
      void update_table_data();
      bool update_tables_on_disk() const;
       
    private:
      static query_interface* _instance;
      std::string _version;
      std::string _myid;
      std::string _tableprov_directory;
      RequestStats _req_counts;
      ct_main_data_def* _main_data;
      ct_stats_data_def* _stats_data;
      ct_cert_info_data_def* _cert_info_data;
      mutable pthread_mutex_t _mutex;
  };

}

#endif
