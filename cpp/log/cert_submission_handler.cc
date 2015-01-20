#include "log/cert_submission_handler.h"

#include <glog/logging.h>
#include <string>

#include "log/cert.h"
#include "log/cert_checker.h"
#include "log/ct_extensions.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"

using cert_trans::Cert;
using cert_trans::CertChain;
using cert_trans::CertChecker;
using cert_trans::PreCertChain;
using cert_trans::TbsCertificate;
using ct::LogEntry;
using ct::PrecertChainEntry;
using ct::X509ChainEntry;
using std::string;

// TODO(ekasper): handle Cert errors consistently and log some errors here
// if they fail.
CertSubmissionHandler::CertSubmissionHandler(CertChecker* cert_checker,
    CertChecker* all_roots_cert_checker)
    : cert_checker_(cert_checker) 
    , all_roots_cert_checker_(all_roots_cert_checker) {
}

// static
bool CertSubmissionHandler::X509ChainToEntry(const CertChain& chain,
                                             LogEntry* entry) {
  if (!chain.IsLoaded())
    return false;

  Cert::Status status = chain.LeafCert()->HasExtension(
      cert_trans::NID_ctEmbeddedSignedCertificateTimestampList);
  if (status != Cert::TRUE && status != Cert::FALSE) {
    LOG(ERROR) << "Failed to check embedded SCT extension.";
    return false;
  }

  if (status == Cert::TRUE) {
    if (chain.Length() < 2) {
      // need issuer
      return false;
    }

    entry->set_type(ct::PRECERT_ENTRY);
    string key_hash;
    if (chain.CertAt(1)->SPKISha256Digest(&key_hash) != Cert::TRUE)
      return false;

    entry->mutable_precert_entry()->mutable_pre_cert()->set_issuer_key_hash(
        key_hash);

    string tbs;
    if (!SerializedTbs(*chain.LeafCert(), &tbs))
      return false;

    entry->mutable_precert_entry()->mutable_pre_cert()->set_tbs_certificate(
        tbs);
    return true;
  } else {
    entry->set_type(ct::X509_ENTRY);
    string der_cert;
    if (chain.LeafCert()->DerEncoding(&der_cert) != Cert::TRUE)
      return false;

    entry->mutable_x509_entry()->set_leaf_certificate(der_cert);
    return true;
  }
}

CertSubmissionHandler::SubmitResult
CertSubmissionHandler::ProcessX509Submission(CertChain* chain,
                                             LogEntry* entry,
                                             string allroots) {
  if (!chain->IsLoaded())
    return EMPTY_SUBMISSION;

  CertChecker::CertVerifyResult result = CertChecker::OK;
  if (allroots != "empty") {
    result = all_roots_cert_checker_->CheckCertChain(chain);
  } else {
    result = cert_checker_->CheckCertChain(chain);
  }
  if (result != CertChecker::OK)
    return GetVerifyError(result);

  // We have a valid chain; make the entry.
  string der_cert;
  // Nothing should fail anymore as we have validated the chain.
  if (chain->LeafCert()->DerEncoding(&der_cert) != Cert::TRUE)
    return INTERNAL_ERROR;

  X509ChainEntry* x509_entry = entry->mutable_x509_entry();
  x509_entry->set_leaf_certificate(der_cert);
  for (size_t i = 1; i < chain->Length(); ++i) {
    if (chain->CertAt(i)->DerEncoding(&der_cert) != Cert::TRUE)
      return INTERNAL_ERROR;
    x509_entry->add_certificate_chain(der_cert);
  }
  entry->set_type(ct::X509_ENTRY);
  return OK;
}

CertSubmissionHandler::SubmitResult
CertSubmissionHandler::ProcessPreCertSubmission(PreCertChain* chain,
                                                LogEntry* entry, string allroots) {
  PrecertChainEntry* precert_entry = entry->mutable_precert_entry();
  CertChecker::CertVerifyResult result = CertChecker::OK;
  if (allroots != "empty") { 
    result = all_roots_cert_checker_->CheckPreCertChain(
      chain, precert_entry->mutable_pre_cert()->mutable_issuer_key_hash(),
      precert_entry->mutable_pre_cert()->mutable_tbs_certificate());
  } else {
    result = cert_checker_->CheckPreCertChain(
      chain, precert_entry->mutable_pre_cert()->mutable_issuer_key_hash(),
      precert_entry->mutable_pre_cert()->mutable_tbs_certificate());
  }

  if (result != CertChecker::OK)
    return GetVerifyError(result);

  // We have a valid chain; make the entry.
  string der_cert;
  // Nothing should fail anymore as we have validated the chain.
  if (chain->LeafCert()->DerEncoding(&der_cert) != Cert::TRUE)
    return INTERNAL_ERROR;
  precert_entry->set_pre_certificate(der_cert);
  for (size_t i = 1; i < chain->Length(); ++i) {
    if (chain->CertAt(i)->DerEncoding(&der_cert) != Cert::TRUE)
      return INTERNAL_ERROR;
    precert_entry->add_precertificate_chain(der_cert);
  }
  entry->set_type(ct::PRECERT_ENTRY);
  return OK;
}

// static
bool CertSubmissionHandler::SerializedTbs(const Cert& cert, string* result) {
  if (!cert.IsLoaded())
    return false;

  Cert::Status status = cert.HasExtension(
      cert_trans::NID_ctEmbeddedSignedCertificateTimestampList);
  if (status != Cert::TRUE && status != Cert::FALSE)
    return false;

  // Delete the embedded proof.
  TbsCertificate tbs(cert);
  if (!tbs.IsLoaded())
    return false;

  if (status == Cert::TRUE &&
      tbs.DeleteExtension(
          cert_trans::NID_ctEmbeddedSignedCertificateTimestampList) !=
          Cert::TRUE)
    return false;

  string der_tbs;
  if (tbs.DerEncoding(&der_tbs) != Cert::TRUE)
    return false;
  result->assign(der_tbs);
  return true;
}

// static
CertSubmissionHandler::SubmitResult CertSubmissionHandler::GetVerifyError(
    CertChecker::CertVerifyResult result) {
  SubmitResult submit_result;
  switch (result) {
    case CertChecker::INVALID_CERTIFICATE_CHAIN:
    case CertChecker::PRECERT_EXTENSION_IN_CERT_CHAIN:
    case CertChecker::UNSUPPORTED_ALGORITHM_IN_CERT_CHAIN:
      submit_result = INVALID_CERTIFICATE_CHAIN;
      break;
    case CertChecker::PRECERT_CHAIN_NOT_WELL_FORMED:
      submit_result = PRECERT_CHAIN_NOT_WELL_FORMED;
      break;
    case CertChecker::ROOT_NOT_IN_LOCAL_STORE:
      submit_result = UNKNOWN_ROOT;
      break;
    case CertChecker::INTERNAL_ERROR:
      submit_result = INTERNAL_ERROR;
      break;
    default:
      LOG(FATAL) << "Unknown CertChecker error " << result;
  }
  return submit_result;
}
