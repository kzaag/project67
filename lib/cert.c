
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <string.h>

#include <p67/cert.h>
#include <p67/net.h>
#include <p67/log.h>

/*
    generate cert from pre existing key
*/
p67_err
p67_cert_create_from_key(const char * path, const char * address)
{
    if(path == NULL || strlen(path) == 0) return p67_err_einval;

    X509 * x = NULL;
    EVP_PKEY * priv = NULL, * pub = NULL;
    BIO * privb = NULL, * pubb = NULL;
    FILE * keypr = NULL, * keypub = NULL, * cert = NULL;
    X509_NAME * name;
    size_t pathl = strlen(path);
    size_t extpl = pathl + 6;
    p67_err err;
    char * extp;

    p67_err_mask_all(err);

    if((extp = malloc(extpl)) == NULL) goto end;

    if(memcpy(extp, path, pathl) == NULL) goto end;

    if((keypr = fopen(extp, "w")) == NULL) goto end;

    if((privb = BIO_new_fp(keypr, BIO_NOCLOSE)) == NULL) goto end;

    if((PEM_read_bio_PrivateKey(privb, &priv, NULL, NULL)) == NULL) goto end;

    sprintf(extp+pathl, ".pub");
    if((keypub = fopen(extp, "w")) == NULL) goto end;

    if((pubb = BIO_new_fp(keypub, BIO_NOCLOSE)) == NULL) goto end;

    if((PEM_read_bio_PUBKEY(pubb, &pub, NULL, NULL)) == NULL) goto end;
    
    if((x = X509_new()) == NULL) goto end;

    X509_set_version(x, 2);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x), 30 * 24 * 60 * 60);
	X509_set_pubkey(x,pub);

    name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, (const unsigned char *)address, -1, -1, 0);
	X509_set_issuer_name(x,name);

    if(X509_sign(x, priv, EVP_sha256()) <= 0) goto end;

    sprintf(extp+pathl, ".cert");
    if((cert = fopen(extp, "w")) == NULL) goto end;

    if(PEM_write_X509(cert, x) != 1) goto end;

    err = 0;

end:
    BIO_free_all(privb);
    BIO_free_all(pubb);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    X509_free(x);
    if(keypr != NULL)
        fclose(keypr);
    if(keypub != NULL)
        fclose(keypub);
    if(cert != NULL)
        fclose(cert);
    if(extp != NULL)
        free(extp);

    return err;
}

/*
    generate key pair
*/
p67_err
p67_cert_new_key(char * path) 
{
    if(path == NULL || strlen(path) == 0) return p67_err_einval;

    EVP_PKEY * keystor = NULL;
    EC_KEY * key = NULL;
    BIO * fbio = NULL;
    FILE * keypr = NULL, * keypub = NULL;
    size_t pathl = strlen(path);
    size_t extpl = pathl + 6;
    char * extp = malloc(extpl);
    p67_err err;

    p67_err_mask_all(err);

    if(extp == NULL) goto end;

    bzero(extp, extpl);

    if(memcpy(extp, path, pathl) == NULL) goto end;

    if((keystor = EVP_PKEY_new()) == NULL) goto end;

    if((key = EC_KEY_new_by_curve_name(NID_secp384r1)) == NULL) goto end;

    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    if(EC_KEY_generate_key(key) != 1) goto end;

    if(EVP_PKEY_assign_EC_KEY(keystor, key) != 1) goto end;

    if((keypr = fopen(extp, "w")) == NULL) goto end;

    if((fbio = BIO_new_fp(keypr, BIO_NOCLOSE)) == NULL) goto end;

    if(PEM_write_bio_PrivateKey(
            fbio, keystor, NULL, NULL, 0, 0, NULL) != 1) goto end;

    sprintf(extp+pathl, ".pub");
    if((keypub = fopen(extp, "w")) == NULL) goto end;

    if(BIO_set_fp(fbio, keypub, BIO_NOCLOSE) != 1) goto end;

    if(PEM_write_bio_PUBKEY(fbio, keystor) != 1) goto end;

    err = 0;

end:
    BIO_free_all(fbio);
    EVP_PKEY_free(keystor);
    if(keypr != NULL)
        fclose(keypr);
    if(keypub != NULL)
        fclose(keypub);
    if(extp != NULL)
        free(extp);

    return err;
}


/*
    generate certificate along with its key.
    address is null terminated public ip of the host
*/
p67_err
p67_cert_new_cert(const char * path, const char * address)
{
    if(path == NULL || strlen(path) == 0) return p67_err_einval;

    X509 * x = NULL;
    EVP_PKEY * keystor = NULL;
    EC_KEY * key = NULL;
    BIO * fbio = NULL;
    FILE * keypr = NULL, * keypub = NULL, * cert = NULL;
    X509_NAME * name;
    size_t pathl = strlen(path);
    size_t extpl = pathl + 6;
    char * extp = malloc(extpl);
    p67_err err;

    p67_err_mask_all(err);

    if(extp == NULL) goto end;
    
    bzero(extp, extpl);
    
    if(memcpy(extp, path, pathl) == NULL) goto end;

    if((keystor = EVP_PKEY_new()) == NULL) goto end;

    if((key = EC_KEY_new_by_curve_name(NID_secp384r1)) == NULL) goto end;

    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    if(EC_KEY_generate_key(key) != 1) goto end;

    if(EVP_PKEY_assign_EC_KEY(keystor, key) != 1) goto end;

    if((keypr = fopen(extp, "w")) == NULL) goto end;

    if((fbio = BIO_new_fp(keypr, BIO_NOCLOSE)) == NULL) goto end;

    if(PEM_write_bio_PrivateKey(fbio, keystor, NULL, NULL, 0, 0, NULL) != 1) goto end;

    sprintf(extp+pathl, ".pub");
    if((keypub = fopen(extp, "w")) == NULL) goto end;

    if(BIO_set_fp(fbio, keypub, BIO_NOCLOSE) != 1) goto end;

    if(PEM_write_bio_PUBKEY(fbio, keystor) != 1) goto end;

    if((x = X509_new()) == NULL) goto end;

    X509_set_version(x, 2);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x), 30 * 24 * 60 * 60);
	X509_set_pubkey(x,keystor);

    name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, (const unsigned char *)address, -1, -1, 0);
	X509_set_issuer_name(x,name);

    if(X509_sign(x, keystor, EVP_sha256()) <= 0) goto end;

    sprintf(extp+pathl, ".cert");
    if((cert = fopen(extp, "w")) == NULL) goto end;

    if(PEM_write_X509(cert, x) != 1) goto end;

    err = 0;

end:
    BIO_free_all(fbio);
    EVP_PKEY_free(keystor);
    X509_free(x);
    if(keypr != NULL)
        fclose(keypr);
    if(keypub != NULL)
        fclose(keypub);
    if(cert != NULL)
        fclose(cert);
    if(extp != NULL)
        free(extp);

    return err;
}

p67_err
p67_cert_trust_address(p67_addr_t * addr, const char * path)
{
    BIO * rbio, * mbio;
    STACK_OF(X509_INFO) * certificates;
    X509_INFO * cert;
    X509_PUBKEY * xpubk = NULL;
    EVP_PKEY * pubk = NULL;
    int i, max, wrote;
    char * bptr;

    if(!(rbio = BIO_new(BIO_s_file()))) {
        return p67_err_eerrno | p67_err_essl;
    }

#undef freeblock
#define freeblock { BIO_free(rbio); }

    if(!(mbio = BIO_new(BIO_s_mem()))) {
        freeblock
        return p67_err_eerrno | p67_err_essl;
    }

#undef freeblock
#define freeblock { BIO_free(rbio); BIO_free(mbio); }

    if(BIO_read_filename(rbio, path) <= 0) {
        freeblock
        return p67_err_eerrno | p67_err_essl;
    }

    certificates = PEM_X509_INFO_read_bio(rbio, NULL, NULL, NULL);
    if(!certificates) {
        freeblock
        return p67_err_eerrno | p67_err_essl;
    }

#undef freeblock
#define freeblock { \
            BIO_free(rbio); \
            BIO_free(mbio); \
            sk_X509_INFO_pop_free(certificates, X509_INFO_free); \
        }

    max = sk_X509_INFO_num(certificates);

    if(max > 1) {
        p67_log(
            "In p67_cert_trust_address_certificaes:"\
            " user provided path with more than 1 certs,"\
            " but only the first one will be trusted.\n");
    }

    for(i = 0; i < max; i++) {
        cert = sk_X509_INFO_value(certificates, i);

        if((xpubk = X509_get_X509_PUBKEY(cert->x509)) == NULL) {
            freeblock
            return p67_err_eerrno | p67_err_essl;
        }

        if((pubk = X509_PUBKEY_get(xpubk)) == NULL) {
            freeblock
            return p67_err_eerrno | p67_err_essl;
        }

        if(PEM_write_bio_PUBKEY(mbio, pubk) <= 0) {
            freeblock
            EVP_PKEY_free(pubk);
            return p67_err_eerrno | p67_err_essl;
        }

        wrote = BIO_number_written(mbio);
        BIO_get_mem_data(mbio, &bptr);
        
        if(!p67_node_insert(addr, bptr, wrote, P67_NODE_STATE_NODE)) {
            freeblock;
            EVP_PKEY_free(pubk);
            return p67_err_eaconn;
        }

        EVP_PKEY_free(pubk);
        break;
    }

    freeblock;
    return 0;
}
