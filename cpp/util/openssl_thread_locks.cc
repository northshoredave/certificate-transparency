#include <pthread.h>
#include <openssl/lhash.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "util/openssl_thread_locks.h"

void pthreads_locking_callback(int mode,int type,const char *file,int line);
unsigned long pthreads_thread_id(void );

static pthread_mutex_t *lock_cs;
static long *lock_count;

void Akamai::thread_setup(void)
{ 
  lock_cs = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
  lock_count = (long*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
  for (int i = 0; i < CRYPTO_num_locks(); ++i) {
    lock_count[i] = 0;
    pthread_mutex_init(&(lock_cs[i]),NULL);
  }
  CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
  CRYPTO_set_locking_callback((void (*)(int,int,const char*,int))pthreads_locking_callback);
}

void Akamai::thread_cleanup(void)
{
  CRYPTO_set_locking_callback(NULL);
  for (int i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_destroy(&(lock_cs[i]));
  }
  OPENSSL_free(lock_cs);
  OPENSSL_free(lock_count);
}

void pthreads_locking_callback(int mode, int type, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
  {
    pthread_mutex_lock(&(lock_cs[type]));
    lock_count[type]++;
  }
  else
  {
    pthread_mutex_unlock(&(lock_cs[type]));
  }
}

unsigned long pthreads_thread_id(void) {
	unsigned long ret;

	ret=(unsigned long)pthread_self();
	return(ret);
}

