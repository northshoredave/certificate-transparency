#include "databattery_db.cc"

#include "log/logged_certificate.h"
#include "proto/ct.pb.h"

template class DataBatteryDB<ct::LoggedCertificate,ct::LoggedCertificatePBList>;
