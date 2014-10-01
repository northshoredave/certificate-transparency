/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef DATABATTERY_DB_H
#define DATABATTERY_DB_H
#include <string>

#include "log/sqlite_db.h"
#include "log/data_battery.h"

namespace Akamai {

template <class Logged,class LoggedList> class DataBatteryDB : public SQLiteDB<Logged> {
 public:
  explicit DataBatteryDB(const std::string &dbfile,Akamai::CertTables* cert_tables)
    : SQLiteDB<Logged>(dbfile)
    , _cert_tables(cert_tables)
  {
    SQLiteDB<Logged>::ClearTables(); //Clear sqlite tables to be refilled from DataBattery tables
    update_from_data_battery(0);
  }

  typedef typename Database<Logged>::WriteResult WriteResult;
  typedef typename Database<Logged>::LookupResult LookupResult;

  virtual WriteResult CreatePendingEntry_(const Logged &logged);

  int update_from_data_battery(uint tree_size);

  Akamai::CertTables* get_cert_tables() { return _cert_tables; }

 private:
  Akamai::CertTables *_cert_tables;
};

}

#endif
