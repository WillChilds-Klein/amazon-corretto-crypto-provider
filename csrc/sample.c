/gcc -Wall -o out_test main.c -I./aws-lc-install/include/ -L./aws-lc-install/lib/ -lcrypto -DENABLE_DILITHIUM=1
#include <openssl/evp.h>
#include <stdio.h>

// Generate a key-pair for the desired PQDSA algorithm.
int generate_key_pair(/* OUT */ EVP_PKEY **key,
                      /* IN  */ int pqdsa_nid) {

    EVP_PKEY_CTX *ctx = NULL;

    // Create the PQDSA contex.
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_PQDSA, NULL);
    if (!ctx ||
        !EVP_PKEY_CTX_pqdsa_set_params(ctx, pqdsa_nid) ||
        !EVP_PKEY_keygen_init(ctx) ||
        !EVP_PKEY_keygen(ctx, key)) {
        EVP_PKEY_free(*key);
        EVP_PKEY_CTX_free(ctx);
        return 0;
        }
    // Note: a single context can be used to generate many keys.
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

// Takes an input PKEY and extracts the public key to |pub_key| and the
// length to |pub_key_len|
int get_raw_public_key(/* IN  */ EVP_PKEY *key,
                       /* OUT */ uint8_t **pub_key,
                       /* OUT */ size_t *pub_key_len) {

    // We call the function with NULL as the |out| argument
    // to get the required buffer length.
    if (!EVP_PKEY_get_raw_public_key(key, NULL, pub_key_len)) {
        *pub_key_len = 0;
        return 0;
    }

    // Allocate memory for the output buffer.
    *pub_key = (uint8_t*) OPENSSL_malloc(*pub_key_len);
    if (pub_key == NULL) {
        *pub_key_len = 0;
        return 0;
    }

    // Get the raw public key in the output buffer.
    if (!EVP_PKEY_get_raw_public_key(key, *pub_key, pub_key_len)) {
        OPENSSL_free(*pub_key);
        *pub_key_len = 0;
        return 0;
    }

    return 1;
}

// Takes an input PKEY and extracts the public key to |pub_key| and the
// length to |pub_key_len|
int get_raw_private_key(/* IN  */ EVP_PKEY *key,
                       /* OUT */ uint8_t **priv_key,
                       /* OUT */ size_t *priv_key_len) {

    // We call the function with NULL as the |out| argument
    // to get the required buffer length.
    if (!EVP_PKEY_get_raw_private_key(key, NULL, priv_key_len)) {
        *priv_key_len = 0;
        return 0;
    }

    // Allocate memory for the output buffer.
    *priv_key = (uint8_t*) OPENSSL_malloc(*priv_key_len);
    if (priv_key == NULL) {
        *priv_key_len = 0;
        return 0;
    }

    // Get the raw private key in the output buffer.
    if (!EVP_PKEY_get_raw_private_key(key, *priv_key, priv_key_len)) {
        OPENSSL_free(*priv_key);
        *priv_key_len = 0;
        return 0;
    }

    return 1;
}

// Encodes the input public key in |key| to DER encoding |der| of length |der_len|
int marshal_public_key(/* IN */ EVP_PKEY *key,
                       /* OUT */ uint8_t **der,
                       /* OUT */ size_t *der_len) {
    CBB cbb;
    if (!CBB_init(&cbb, 0) ||
        !EVP_marshal_public_key(&cbb, key) ||
        !CBB_finish(&cbb, der, der_len)) {
      return 0;
    }

    return 1;
 }

// Encodes the input private key in |key| to DER encoding |der| of length |der_len|
int marshal_private_key(/* IN */ EVP_PKEY *key,
                        /* OUT */ uint8_t **der,
                        /* OUT */ size_t *der_len) {
    CBB cbb;
    if (!CBB_init(&cbb, 0) ||
        !EVP_marshal_private_key(&cbb, key) ||
        !CBB_finish(&cbb, der, der_len)) {
        return 0;
        }

    return 1;
}

// Decodes the input |der| encoding of length |der_len| into PKEY structure |key|
int parse_public_key(/* IN */  uint8_t **der,
                     /* IN */  size_t *der_len,
                     /* OUT */ EVP_PKEY *key) {
    CBS cbs;
    CBS_init(&cbs, *der, *der_len);
    if (!EVP_parse_public_key(&cbs)) {
     return 0;
    }

    return 1;
 }

// prints bytes
void printbytes(uint8_t *der, size_t der_len) {
    size_t truncate = der_len;
    for (size_t i = 0; i < truncate; i++) {
        printf(" 0x%02X,", der[i]);
    }
    printf("\n");
}

int main(void)
{
    printf("ML-DSA DEMO\n");
    printf("\n");

    // genegerate ML-DSA key
    EVP_PKEY *key = NULL;
    if (!generate_key_pair(&key, NID_MLDSA65)) {
        return 0;
    }
// ------------- Sign/Verify functions ------------- //

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    EVP_MD_CTX md_ctx, md_ctx_verify;
    static const uint8_t kMsg[] = {1, 2, 3, 4};
    static const uint8_t kMsg_different[] = {1, 2, 3, 5};

    // set up context
    EVP_MD_CTX_init(&md_ctx);
    EVP_MD_CTX_init(&md_ctx_verify);

    // To sign, we first need to allocate memory for the signature. We call
    // digestSign with sig = NULL to indicate that we are doing a size check
    // on the signatre size. The variable |sig_len| will be returned with the
    // correct signature size, so we can allocate memory.
    if (key == NULL ||
    !EVP_DigestSignInit(&md_ctx, NULL, NULL, NULL, key) ||
    !EVP_DigestSign(&md_ctx, sig, &sig_len, kMsg, sizeof(kMsg))) {
        goto out;
    }
    // assign memory to store the signature
    sig = (uint8_t *) malloc(sig_len);

    // check that the returned signature length is of the expected size
    if (sig_len != EVP_PKEY_size(key)) {
        fprintf(stderr, "sig_len mismatch\n");
        goto out;
    }

    // actually sign
    if (!EVP_DigestSign(&md_ctx, sig, &sig_len, kMsg, sizeof(kMsg))) {
        goto out;
    }

    // verify message
    if (!EVP_DigestVerifyInit(&md_ctx_verify, NULL, NULL, NULL, key) ||
        !EVP_DigestVerify(&md_ctx_verify, sig, sig_len, kMsg, sizeof(kMsg))) {
        goto out;
    }

    // verify should fail on bad message
    if (EVP_DigestVerify(&md_ctx_verify, sig, sig_len, kMsg_different, sizeof(kMsg))) {
        goto out;
    }
    printf("Signature:\n");
    printbytes( sig, sig_len);
    printf("\n");

// ------------- Public Key functions ------------- //

    // Extract public key from the PKEY
    uint8_t *pub_key;
    size_t pub_key_len;

    if (!get_raw_public_key(key, &pub_key, &pub_key_len)) {
        goto out;
    }

    printf("Successfully extracted public key of length: %zu bytes\n", pub_key_len);

    // Encode/Marshal the public key in |key| to DER encoding |public_der|
    // of length |public_der_len|
    uint8_t *public_der;
    size_t public_der_len;

    if (!marshal_public_key(key, &public_der, &public_der_len)) {
        goto out;
    }

    printf("DER encoded public key:\n");
    printbytes(public_der, public_der_len);

    // Decode/Parse the input |public_der| encoding of length |public_der_len|
    // into PKEY structure |pkey_public_new|
    EVP_PKEY *pkey_public_new = NULL;
    if (!parse_public_key(&public_der, &public_der_len, pkey_public_new)) {
        goto out;
    }

    printf("\n");
// ------------- Private Key functions ------------- //

    // Extract private key from the PKEY
    uint8_t *priv_key;
    size_t priv_key_len;

    if (get_raw_private_key(key, &priv_key, &priv_key_len) != 1) {
        goto out;
    }

    printf("Successfully extracted private key of length: %zu bytes\n", priv_key_len);

    uint8_t *private_der;
    size_t private_der_len;

    // Encode/Marshal the private key in |key| to DER encoding |private_der|
    // of length |private_der_len|
    if (marshal_private_key(key, &private_der, &private_der_len) != 1) {
        goto out;
    }

    printf("DER encoded private key:\n");
    printbytes(private_der, private_der_len);

    // Decode/Parse the input |private_der| encoding of length |public_der_len| into
    // PKEY structure |pkey_private_new|
    EVP_PKEY *pkey_private_new = NULL;
    if (!parse_public_key(&private_der, &private_der_len, pkey_private_new)) {
        goto out;
    }
out:
    EVP_PKEY_free(key);
    EVP_MD_CTX_cleanup(&md_ctx);
    EVP_MD_CTX_cleanup(&md_ctx_verify);
    return 0;
}
