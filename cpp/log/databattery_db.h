/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef DATABATTERY_DB_H
#define DATABATTERY_DB_H
#include <string>

#include "log/sqlite_db.h"
#include "log/data_battery.h"

namespace Akamai {

/*   Constructor must clear local sql database since we always sync to DataBattery on startup.
 *   We also need to override one database method and add a method.
 *
 *   Akamai CT now creates this database instead of the normal sqliteDB.
 *    
 *   1) CreatePendingEntry:
 *       Before we can accept a new cert into pending locally we must first attempt to add it 
 *    to DataBattery.  If add to DataBattery succceeds then we proceed with the normal CT updated.
 *
 *   2) update_from_data_battery 
 *       There is a thread which periodically retrrieves any new leaves that have been created in
 *     data_battery (i.e. pending certs that have been committed).
 *       This new method goes over the list of leaves and extracts any leaves which haven't been
 *     added locally yet.  It then does a mass add to the local sql database
 *       (i.e. open transaction, add all new leaves, commit transaction).
 */

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
