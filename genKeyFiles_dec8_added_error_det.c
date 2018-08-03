/********* Includes *********/
/* TODO: Rename project, src, and header to 'codeSigning' */
#include "genKeyFiles.h"

/********* These macros must not be changed *********/

/* (n,e): Signer's 2048-bit RSA key w/ exponent e = 65537 */
#define RSA_KEY_SIZE     2048   /* def[001_plt_des_095] */
#define EXP              65537  /* def[001_plt_des_095] */

#define FILE_BUFFER_SIZE 2048   /* max DER size */
#define EXIT_FAIL     1      /* Exit failure breaking rc */

/*
 *****************************************************************************
 *  Purpose:  Print formatted display of hex data
 *  Outputs:  Prints formated data
 *  Returns:  -
 *  Notes:    -
 *****************************************************************************
 */
void print_formatted_data
(
    const void*     buffer,
    unsigned int    len,
    unsigned char   cols
)
{
   unsigned int i;

   /* Creating row per length of data and columns specified */
   for(i = 0; i < len + ((len % cols) ? (cols - len % cols) : 0); i++)
   {
      /* print hex data */
      if(i < len) {
         printf("%02X ", ((byte*)buffer)[i] & 0xFF);
      }

      if(i % cols == (cols - 1)) {
         printf("\n");
      }
   }

   printf("\n");
}

/*****************************************************************************
 *  Purpose:  Load file in DER format 
 *  Outputs:  -
 *  Returns:  Return code [0 = PASS, !0 = FAIL]
 *  Notes:    Only used to check wolfSSL cert
 *****************************************************************************
 */
#ifdef EN_CERT_CHECK
int rsa_load_der_file
(   
    const char* derFile,
    RsaKey*     key
)
{
    FILE*   loadedFile;
    byte*   dataBuffer   = NULL;
    word32  dataBytes    = 0;
    word32  idx          = 0;
    int     rc           = EXIT_FAIL;

    loadedFile = fopen(derFile, "rb");
    if(NULL != loadedFile)
    {
        dataBuffer = FILE_BUFFER_SIZE;
        dataBytes = fread(dataBuffer, 1, FILE_BUFFER_SIZE, loadedFile);
        fclose(loadedFile);
    }

    if((NULL != dataBuffer) && (dataBytes > 0))
    {
        rc = wc_RsaPrivateKeyDecode(dataBuffer, &idx, key, dataBytes);
    }

    return rc;
}
#endif


/*****************************************************************************
 *  Purpose:  Generator of RSA key pairs and signature of given file
 *  Outputs:  Various console data about and confirming both generators.
              Also, this function outputs three files:
              - private_key.txt
              - public_key.txt
              - signature.txt
 *  Returns:  Return code [0 = PASS, !0 = FAIL]
 *  Notes:    Download_file_to_buffer() needs to be called first to dump file
 *            contents to the buffer,
 *****************************************************************************
 */
int rsa_sign
(
    enum wc_HashType        hashType,
    enum wc_SignatureType   signatureType,
    byte*   fileBuff,
    int     fileLen
)
{
    int     rc;
    RsaKey  keyStruct;
    RNG     rng;
#ifdef EN_KEYS_GEN
    byte*   rsaPrivateKeyBuff;
    byte*   rsaPublicKeyBuff;
    word32  rsaPrivateKeyLen;
    word32  rsaPublicKeyLen;
    FILE*   filePrivKey;
    FILE*   filePublKey;
#endif /* End EN_KEYS_GEN */
#ifdef EN_CODE_SIGNING
    byte*   signatureBuff = NULL;
    word32  signatureLen;
    FILE*   fileSignature;
#endif /* End EN_CODE_SIGNING */

#ifdef EN_KEYS_GEN
    printf("------- Key Pair Generation -------\n");

    /****** Init random number generator ******/
    rc = wc_InitRng(&rng);
    if (0 != rc)
    {
        printf("Init RNG failure %d\n", rc);
        rc = EXIT_FAIL;
        goto exit;
    }

    /****** Init RSA key pair gererator ******/
    rc = wc_InitRsaKey(&keyStruct, NULL);
    if (0 != rc)
    {
        printf("Init RSA key failure %d\n", rc);
        rc = EXIT_FAIL;
        goto exit;
    }

    printf("RSA Key Size %d\n", RSA_KEY_SIZE);

    /* Generate key */
    rc = wc_MakeRsaKey(&keyStruct, RSA_KEY_SIZE, EXP, &rng);
    if (0 != rc)
    {
        printf("Make RSA key failure %d\n", rc);
        rc = EXIT_FAIL;
        goto exit;
    }

    /****** Private Key Gen ******/
    /* Export private key to buffer */
    rsaPrivateKeyLen = FILE_BUFFER_SIZE;
    rsaPrivateKeyBuff = malloc(rsaPrivateKeyLen);
    rc = wc_RsaKeyToDer(&keyStruct, rsaPrivateKeyBuff, rsaPrivateKeyLen);
    if (rc <= 0)
    {
        printf("RSA private key DER export failure %d\n", rc);
        rc = EXIT_FAIL;
        goto exit;
    }

    /* Display private key data in console */
    rsaPrivateKeyLen = rc;
    printf("RSA Private Key: Len %d bytes\n", rsaPrivateKeyLen);
    print_formatted_data(rsaPrivateKeyBuff, rsaPrivateKeyLen, 16);

    /* Write buffer contents to file */
    filePrivKey = fopen("private_key.txt", "wb");
    (void)fwrite(rsaPrivateKeyBuff, 1, rsaPrivateKeyLen, filePrivKey);

    /****** Public Key Gen ******/
    /* Export public key to file */
    rsaPublicKeyLen = FILE_BUFFER_SIZE;
    rsaPublicKeyBuff = malloc(rsaPublicKeyLen);
    rc = wc_RsaKeyToPublicDer(&keyStruct, rsaPublicKeyBuff, rsaPublicKeyLen);
    if (rc <= 0)
    {
        printf("RSA public key DER export failure %d\n", rc);
        rc = EXIT_FAIL;
        goto exit;
    }

    /* Display public key data in console */
    rsaPublicKeyLen = rc;
    printf("RSA Public Key: Len %d bytes\n", rsaPublicKeyLen);
    print_formatted_data(rsaPublicKeyBuff, rsaPublicKeyLen, 16);

    /* Write buffer contents to file */
    filePublKey = fopen("public_key.txt", "wb");
    (void)fwrite(rsaPublicKeyBuff, 1, rsaPublicKeyLen, filePublKey);

    printf("------- End Key Pair Generation -------\n\n");
#endif /* End EN_KEYS_GEN */

#ifdef EN_CERT_CHECK
    /* Load certificate from file client-key.der */
    rsa_load_der_file("../wolfssl-3.12.2/certs/client-key.der", &keyStruct);
#endif /* End EN_CERT_CHECK */

    /****** Code Signing ******/
#ifdef EN_CODE_SIGNING
    printf("------- Signature Generation -------\n");

    /* Signature length and allocate buffer */
    signatureLen = wc_SignatureGetSize(signatureType, &keyStruct, sizeof(keyStruct));
    if(signatureLen <= 0)
    {
        printf("RSA signature size check failure %d\n", signatureLen);
        rc = EXIT_FAIL;
        goto exit;
    }
    signatureBuff = malloc(signatureLen);
    printf("RSA Signature Length: %d\n", signatureLen);

    /* Perform hash and RSA sign */
    rc = wc_SignatureGenerate(  hashType, signatureType, fileBuff,
                                fileLen, signatureBuff, &signatureLen,
                                &keyStruct, sizeof(keyStruct), &rng);
    if (0 == rc)    /* Successful generation of signature */
    {
        printf("RSA Signature Generation: SUCCESSFUL\n");

        /* Print signature data */
        printf("RSA Signature Data:\n");
        print_formatted_data(signatureBuff, signatureLen, 16);

        /* Write buffer contents to file */
        fileSignature = fopen("signature.txt", "wb");
        (void)fwrite(signatureBuff, 1, signatureLen, fileSignature);
        printf("------- End Signature Generation -------\n");
    }
    else            /* Error when creating signature */
    {
        printf("RSA Signature Generation: FAILURE\n");
        goto exit;
    }

/* Todo? Remove to free key and signature buffers */
#if 0
    /* Free key buffers */
    if (NULL != rsaPrivateKeyBuff)
    {
        free(rsaPrivateKeyBuff);
    }
    if (NULL != rsaPublicKeyBuff)
    {
        free(rsaPublicKeyBuff);
    }
    if (NULL != signatureBuff)
    {
        free(signatureBuff);
    }
#endif
#endif /* End EN_CODE_SIGNING */
exit:
    return rc;
}

/*****************************************************************************
 *  Purpose:  Load file into stored buffer
 *  Outputs:  -
 *  Returns:  Return code [0 = PASS, !0 = FAIL]
 *  Notes:    -
 *****************************************************************************
 */
#ifdef EN_CODE_SIGNING
int download_file_to_buffer
(
    char*   fileName,
    byte**  fileBuff,
    int*    fileLen
)
{
    int     rc   = 0;
    FILE*   file = NULL;

    /* Note: The file to be signed MUST be in the dir as the executable...
        $(SolutionDir)Release
     */
    /* Opening file to sign */
    file = fopen(fileName, "rb");
    if (NULL == file)
    {
        perror("Error loading file");
        rc = EXIT_FAIL;
        goto exit;
    }

    /* Calculate length of file */
    fseek(file, 0, SEEK_END);
    *fileLen = (int)ftell(file);   /* Current file position */
    fseek(file, 0, SEEK_SET);
    printf("File %s: %d bytes\n", fileName, *fileLen);

    /* Allocate buffer for file */
    *fileBuff = malloc(*fileLen);
    if(!*fileBuff)
    {
        perror("Error");
        rc = EXIT_FAIL;
        goto exit;
    }

    /* Load file into buffer */
    rc = (int)fread(*fileBuff, 1, *fileLen, file);
    if(rc != *fileLen)
    {
        perror("Error");
        rc = EXIT_FAIL;
        goto exit;
    }

exit:
    if(file)
    {
        fclose(file);
    }

    return rc;
}
#endif /* End EN_CODE_SIGNING */

/*****************************************************************************
 *  Purpose:  main calling sequence for code signing application
 *  Outputs:  
 *  Returns:  Return code [0 = PASS, !0 = FAIL]
 *  Notes:    This is where you specify the name of the file to be signed
              under local var fileName. This file MUST be in the same dir as
              the .exe <$(SolutionDir)Release>.
 *****************************************************************************
 */
int main
(
    void
)
{
    int     rc          = 0;
    char*   fileName                = "CMMa_WithCal.s37";
    byte*   fileBuffer  = NULL;
    int     fileLen     = 0;
    enum wc_HashType hashType       = WC_HASH_TYPE_SHA256;
    enum wc_SignatureType sigType   = WC_SIGNATURE_TYPE_RSA;

#ifdef EN_CODE_SIGNING
    printf("Signature Structure: Sig=RSA2048, Hash=SHA256\n");

    rc = download_file_to_buffer(fileName, &fileBuffer, &fileLen);
    if (rc < 0)
    {
        goto exit;
    }
#endif /* End EN_CODE_SIGNING */
    rc = rsa_sign(hashType, sigType, fileBuffer, fileLen);

exit:
    return rc;
}
