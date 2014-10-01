#ifndef OPENSSL_THREAD_LOCKS_H
#define OPENSSL_THREAD_LOCKS_H
#include <cstdio>

namespace Akamai {
  void thread_setup(void);
  void thread_cleanup(void);
}

#endif
