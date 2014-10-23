#include "databattery_db.cc"

#include "log/logged_certificate.h"
#include "proto/ct.pb.h"

template class DataBatteryDB<cert_trans::LoggedCertificate,ct::LoggedCertificatePBList>;
