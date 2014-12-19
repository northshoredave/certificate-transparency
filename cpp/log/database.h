/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef DATABASE_H
#define DATABASE_H

#include <glog/logging.h>
#include <set>

#include "base/macros.h"
#include "proto/ct.pb.h"

// The |Logged| class needs to provide this interface:
// class Logged {
//  public:
//   // construct an empty instance
//   LoggedBlob();
//
//   // The key used for storage/retrieval in the database, calculated
//   // from the content.
//   std::string Hash() const;
//
//   // The tree signer assigns a sequence number.
//   void clear_sequence_number();
//   void set_sequence_number(uint64_t sequence);
//   bool has_sequence_number() const;
//   uint64_t sequence_number() const;
//
//   // If the data has a timestamp associated with it, return it: any
//   // STH including this item will have a later timestamp. Return 0 if
//   // there is no timestamp.
//   uint64_t timestamp() const;
//
//   // Serialization of contents (i.e. excluding sequence number and
//   // hash) for storage/retrieval from the database
//   bool SerializeForDatabase(std::string *dst) const;
//   bool ParseFromDatabase(const std::string &src);
//
//   // Serialization for inclusion in the tree (i.e. this is what
//   // clients would hash over).
//   bool SerializeForLeaf(std::string *dst) const;
//
//   // Debugging.
//   std::string DebugString() const;
//
//   // Fill with random content data for testing (no sequence number).
//   void RandomForTest();
// };

namespace Akamai {
      class CertTables;
}

struct leaf_entry {
  std::string _hash;
  std::string _data;
  uint64_t _seqid;
};

// NOTE: This is a database interface for the log server.
// Monitors/auditors shouldn't assume that log entries are keyed
// uniquely by certificate hash -- it is an artefact of this
// implementation, not a requirement of the I-D.
template <class Logged>
class Database {
 public:

  enum WriteResult {
    OK,
    //Failed to add entry to DataBattery
    DATABATTERY_FAILURE,
    // Create failed, certificate hash is primary key and must exist.
    MISSING_CERTIFICATE_HASH,
    // Create failed, an entry with this hash already exists.
    DUPLICATE_CERTIFICATE_HASH,
    // Update failed, entry already has a sequence number.
    ENTRY_ALREADY_LOGGED,
    // Update failed, entry does not exist.
    ENTRY_NOT_FOUND,
    // Another entry has this sequence number already.
    // We only report this if the entry is pending (i.e., ENTRY_NOT_FOUND
    // and ENTRY_ALREADY_LOGGED did not happen).
    SEQUENCE_NUMBER_ALREADY_IN_USE,
    // Timestamp is primary key, it must exist and be unique,
    DUPLICATE_TREE_HEAD_TIMESTAMP,
    MISSING_TREE_HEAD_TIMESTAMP,
  };

  enum LookupResult {
    LOOKUP_OK,
    NOT_FOUND,
  };

  virtual ~Database() {
  }

  virtual bool Transactional() const {
    return false;
  }

  virtual void BeginTransaction() {
    DLOG(FATAL) << "Transactions not supported";
  }

  virtual void EndTransaction() {
    DLOG(FATAL) << "Transactions not supported";
  }

  // Attempt to create a new entry. Fail if an entry with this hash
  // already exists.  The entry remains PENDING until a sequence
  // number has been assigned, after which its status changes to
  // LOGGED.
  WriteResult CreatePendingEntry(const Logged& logged) {
    CHECK(!logged.has_sequence_number());
    return CreatePendingEntry_(logged);
  }
  virtual WriteResult CreatePendingEntry_(const Logged& logged) = 0;

  //Akamai: needed so I can wrap up the startup commits to the sql database from DB into a single 
  //  transaction.  Doing 1 transaction at a time for each leaf is 100x slower. 
  virtual WriteResult CreateNewEntry(const std::vector<leaf_entry>& new_leaves) { return OK; }

  // Attempt to add a sequence number to the Logged, thereby removing
  // it from the list of pending entries.  Fail if the entry does not
  // exist, already has a sequence number, or an entry with this
  // sequence number already exists (i.e., |sequence_number| is a
  // secondary key.
  virtual WriteResult AssignSequenceNumber(const std::string& pending_hash,
                                           uint64_t sequence_number) = 0;

  // Look up by hash.
  virtual LookupResult LookupByHash(const std::string& hash) const = 0;

  // Look up by hash. If the entry exists write the result. If the
  // entry is not logged return NOT_FOUND.
  virtual LookupResult LookupByHash(const std::string& hash,
                                    Logged* result) const = 0;

  // Look up by sequence number.
  virtual LookupResult LookupByIndex(uint64_t sequence_number,
                                     Logged* result) const = 0;

  // List the hashes of all pending entries, i.e. all entries without a
  // sequence number.
  virtual std::set<std::string> PendingHashes() const = 0;

  // Attempt to write a tree head. Fails only if a tree head with this
  // timestamp
  // already exists (i.e., |timestamp| is primary key). Does not check that
  // the timestamp is newer than previous entries.
  WriteResult WriteTreeHead(const ct::SignedTreeHead& sth) {
    if (!sth.has_timestamp())
      return MISSING_TREE_HEAD_TIMESTAMP;
    return WriteTreeHead_(sth);
  }
  virtual WriteResult WriteTreeHead_(const ct::SignedTreeHead& sth) = 0;

  virtual int update_from_data_battery(uint tree_size) { return -1; }
  // Return the tree head with the freshest timestamp.
  virtual LookupResult LatestTreeHead(ct::SignedTreeHead* result) const = 0;

 protected:
  Database() {
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(Database);
};

#endif  // ndef DATABASE_H
