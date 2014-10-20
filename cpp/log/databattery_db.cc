/* -*- indent-tabs-mode: nil -*- */

#include <glog/logging.h>
#include <sqlite3.h>

#include "log/databattery_db.h"
#include "log/data_battery.h"
#include "util/util.h"
#include "log/sqlite_statement.h"
#include <sstream>

using std::string;
using namespace Akamai;

template <class Logged,class LoggedList> typename Database<Logged>::WriteResult
DataBatteryDB<Logged,LoggedList>::CreatePendingEntry_(const Logged &logged) {
  LOG(INFO) << "SQL pending_add call";
  if (!_cert_tables->pending_add(&logged)) {
    LOG(ERROR) << "Failed to add entry to pending";
    return this->DATABATTERY_FAILURE;
  } else {
    LOG(INFO) << "Success adding entry to pending";
  }
  return SQLiteDB<Logged>::CreatePendingEntry_(logged);
}

template <class Logged, class LoggedList> int
DataBatteryDB<Logged,LoggedList>::update_from_data_battery(uint tree_size) {
  LOG(INFO) << "update_from_data_battery call from tree_size " << tree_size;
  //Lock the mutex to make sure leaves thread doesn't update
  LeavesData* ld = _cert_tables->get_ld();
  pthread_mutex_lock(&ld->_mutex);
  int max_seq_id(-1);
  std::vector<leaf_entry> new_leaves;
  for (int i = tree_size; i < ld->_leaves.logged_certificate_pbs_size(); ++i) {
    const Logged* lcpb = reinterpret_cast<const Logged*>(&ld->_leaves.logged_certificate_pbs(i));
    CHECK_EQ(i,(int)lcpb->sequence_number()) << "Sequence id didn't match tree size " << i << ":" << lcpb->sequence_number();
    string hash = lcpb->Hash();
    Logged result;
    LookupResult res = LookupByHash(hash,&result);
    //Check if your already in the local database
    if (res == Database<Logged>::LOOKUP_OK) {
      //Yes, check your sequence matches if you have one, otherwise set it
      if (result.has_sequence_number()) {
        CHECK_EQ(result.sequence_number(),lcpb->sequence_number());
      } else {
        AssignSequenceNumber(hash,lcpb->sequence_number());
      }
    } else {
      LOG(INFO) << "UFDB: not in local db, adding and setting seq id " << lcpb->sequence_number();
      leaf_entry lfe;
      lfe._hash = lcpb->Hash();
      lcpb->SerializeForDatabase(&lfe._data);
      lfe._seqid = lcpb->sequence_number();
      new_leaves.push_back(lfe);
    }
    max_seq_id = lcpb->sequence_number();
  }
  if (!new_leaves.empty()) {
    this->CreateNewEntry(new_leaves);
  }
  pthread_mutex_unlock(&ld->_mutex);
  LOG(INFO) << "update_from_data_battery finished with max_seq_id " << max_seq_id;
  return max_seq_id;
}
