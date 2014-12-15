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
  //Used to keep track of number of requests of a given type.  Each type has it's own HitCount.
  //The way this works is that you have a list were the last one is the most current time slice.
  //So imagine you have a time slice of 1 min.  Then each bucket records hits for a minute.  If
  //you are allowing 15 buckets, then you are keeping 15 minutes worth of hits spread over 15 
  //buckets/slices.
  //      15min old -> 14 min old -> ... -> 1 min old
  //Once the list is filled and you cross over into a new minute, pop the 15 min old slice and 
  //everyone is effectively moved forward.
  class HitCount {
    public:
      HitCount(uint num_buckets)
        : _num_buckets(num_buckets)
          , _cur_bucket(0)
          , _num_buckets_filled(0)
    {}
      void incr() { ++_cur_bucket; } //Add a hit 
      //Rotate means your moving the current time slices (buckets) forward and adding a new bucket.
      //  If you've reach the max number of slices, then you can pop the front of the list, it's
      //  too old.
      void rotate(); 
      uint count(uint num_buckets) const;

    private:
      uint _num_buckets; //How many time slices to keep
      uint _cur_bucket; //The hit count in the current bucket
      std::list<uint> _buckets; //hit counts.  Each bucket is a time slice, last is most current.
      uint _num_buckets_filled; //How many time slices you have
  };

  //Data struct to just tally up the buckets.  So if your bucket_time is 1 min, and you want stats
  //  for 1, 5 and 15 minutes (given by the bucket_sets) then you return the 1 min bucket, 
  //  1 min +..+ 5 min and 1 min +...+ 15 min buckets.
  struct ct_req_count_data_def {
    ct_req_count_data_def() 
      : _myid("")
    {}

    std::string _myid;
    uint32_t _bucket_time;
    std::vector<uint32_t> _bucket_sets;
    std::map<std::string,std::vector<uint> > _request_to_counts;
  };

  //Class to record hit counts of the various ct lookups given by the enum.  Uses hit counts class
  //for each type and simply increments the appropriate hitCount.  
  //  To add a new type, just add to the enum and update the str_to_req and req_to_str methods. 
  //Query table will automatically get the new type.
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
      void extract_data(ct_req_count_data_def& d); //Add up the buckets 

    private:
      void process_hit_helper(request_type r) { _hit_counts[r].incr(); }
      void rotate();
      request_type str_to_request_type(std::string r) const;
      std::string request_type_to_str(request_type t) const;
    private:
      std::string _myid;
      uint _bucket_time; //What time slice each bucket represents.
      time_t _last_rotate; //When you last rotated.
      std::vector<uint32_t> _bucket_sets; //How you want to accumulate the buckets.
      std::vector<HitCount> _hit_counts; //Actual hit counts
  };

  struct ct_main_data_def {
    ct_main_data_def()
      : _myid(""), _start_time(0), _is_main_ok("ok")
    {}
    std::string _myid;
    time_t _start_time;
    std::string _root_hash;
    std::string _is_main_ok;
  };

  struct ct_config_data_def {
    ct_config_data_def()
      : _myid("")
    {}
    std::string _myid;
    std::vector<std::pair<std::string,std::string> > _config_key_value;
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

  //Meant to capture all things akamai query.  For now I'm going to go the tableprov route which means I write out
  //an index and tables in .csv file.  AppBattery will pick them up and publishes via tableprov.
  //However, I'm going to use the query2 structs so that I can easily switch to the programmatic 
  //interface if we ever move off AppBattery and want to us it in the future.
  class query_interface {
    public:
      query_interface()
        : _is_main_ok(false)
      {}
      //Update a main table that has basic stats on ct instance
      void update_main(const ct_main_data_def* d);
      //Whats in the config (stored in DataBattery)
      void update_config(const ct_config_data_def* d);
      //Update timestamps one when things have last happened (commit,leaves update, peer updated...)
      void update_stats(const ct_stats_data_def* d);
      //Update hit counts
      void update_req_count();
      //Publish some data on all the certs in CT.  Can be disabled by config.
      void update_cert_info(const ct_cert_info_data_def* d);
      //Update the tables
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
      ct_config_data_def* get_config_data() { return _config_data; }
      ct_stats_data_def* get_stats_data() { return _stats_data; }
      ct_cert_info_data_def* get_cert_info_data() { return _cert_info_data; }

      bool is_main_ok() const { return _b_main_ok; }
      void set_is_main_ok(std::string c) { 
        _b_main_ok = false;
        if (c == "ok") { _b_main_ok = true; } 
        _main_data->_is_main_ok = c; 
      }

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
        _config_data = new ct_config_data_def;
        _config_data->_myid = _myid;
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
      //Why _b_main_ok?  Because i didn't want to put a string compare into the event handler.  We check
      //  this value before returning responses to get-sth, etc...  So I just do it once when health check
      //  update happens.
      bool _b_main_ok;
      ct_config_data_def* _config_data;
      ct_stats_data_def* _stats_data;
      ct_cert_info_data_def* _cert_info_data;
      mutable pthread_mutex_t _mutex;
  };

}

#endif
