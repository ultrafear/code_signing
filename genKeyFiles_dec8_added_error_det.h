/********* Includes *********/
#include <stdio.h>

#include "user_settings.h"          /* wolfSSL settings must be present when building app */

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>

/********* These macros can be changed *********/
#define EN_KEYS_GEN
#define EN_CODE_SIGNING

/********* Global Prototypes *********/
/* Key pair generation */
extern void print_formatted_data
(
    const void* buffer,
    word32      len,
    byte        cols
);

#ifndef NO_CERT_CHECK
extern int rsa_load_der_file
(   
    const char* derFile,
    RsaKey*     key
);
#endif

/* Key pair Generation & Code signing */
extern int rsa_sign
(
    enum wc_HashType        hash_type,
    enum wc_SignatureType   sig_type,
    byte*   fileBuf,
    int     fileLen
);

/* Download file to buffer */
extern int download_file_to_buffer
(
    char*       fileName,
    byte**      fileBuff,
    int*        fileLen
);
/* End of functions declarations */
