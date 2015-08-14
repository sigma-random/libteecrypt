#ifndef CTRYPT_ENGINE_H
#define CTRYPT_ENGINE_H

#define	USE_LIBTOMCRYPT


#ifdef  USE_LIBTOMCRYPT
#include "./engine/tee_tomcrypt_engine.h"
#elif	USE_OPENSSL
#include "./engine/tee_openssl_engine.h"
#endif

#endif