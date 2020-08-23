// Copyright 2020 zelbrium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <unistd.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define SEC_PER_HOUR (60 * 60)

#define err(f,r) ERR_PUT_error(ERR_LIB_USER,(f),(r),"gen-ca-cert.c",__LINE__)
#define USER_F_CFPKD 1
#define USER_F_CFPK 2
#define USER_F_GRS 3

static ASN1_INTEGER * generate_random_serial(void)
{
	unsigned char data[20] = {0};
	if (!RAND_bytes(data, sizeof(data))) {
		err(USER_F_GRS, 10);
		return NULL;
	}

	// Make data be non-negative, suggested by X509 spec
	data[0] &= 0x7F;

	BIGNUM *bn = BN_bin2bn(data, sizeof(data), NULL);
	if (bn == NULL) {
		err(USER_F_GRS, 20);
		return NULL;
	}
	
	ASN1_INTEGER *serial = BN_to_ASN1_INTEGER(bn, NULL);

	BN_free(bn);
	return serial;
}

// https://www.opensource.apple.com/source/OpenSSL/OpenSSL-22/openssl/demos/x509/mkcert.c
static int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}

static X509 * cacert_from_priv_key(
	RSA *privKey, // privKey is consumed by this function
	const char *commonName,
	const char *organization,
	const char *countryCode,
	int hoursBefore,
	int hoursAfter
) {
	if (privKey == NULL
	|| commonName == NULL
	|| organization == NULL
	|| countryCode == NULL) {
		err(USER_F_CFPK, 10);
		RSA_free(privKey);
		return NULL;
	}

	EVP_PKEY *pk = EVP_PKEY_new();
	if (pk == NULL) {
		err(USER_F_CFPK, 20);
		RSA_free(privKey);
		return NULL;
	}

	if (!EVP_PKEY_assign_RSA(pk, privKey)) {
		err(USER_F_CFPK, 30);
		EVP_PKEY_free(pk);
		RSA_free(privKey);
		return NULL;
	}
	privKey = NULL; // pkey consumes rsa reference

	X509 *x = X509_new();
	if (x == NULL) {
		err(USER_F_CFPK, 40);
		goto fail;
	}

	if (!X509_set_version(x, 2)) { // version 3
		err(USER_F_CFPK, 50);
		goto fail;
	}

	ASN1_INTEGER *serial = generate_random_serial();
	if (serial == NULL) {
		err(USER_F_CFPK, 60);
		goto fail;
	}
	if (!X509_set_serialNumber(x, serial)) {
		err(USER_F_CFPK, 70);
		ASN1_INTEGER_free(serial);
		goto fail;
	}

	if (X509_gmtime_adj(X509_get_notBefore(x), -hoursBefore * SEC_PER_HOUR) == NULL) {
		err(USER_F_CFPK, 80);
		goto fail;
	}
	if (X509_gmtime_adj(X509_get_notAfter(x), hoursAfter * SEC_PER_HOUR) == NULL) {
		err(USER_F_CFPK, 90);
		goto fail;
	}

	if (!X509_set_pubkey(x, pk)) {
		err(USER_F_CFPK, 100);
		goto fail;
	}

	X509_NAME *name = X509_get_subject_name(x);

	if (!X509_NAME_add_entry_by_txt(name,
		"C", MBSTRING_UTF8, (unsigned char *)countryCode, -1, -1, 0)) {
		err(USER_F_CFPK, 110);
		goto fail;
	}
	if (!X509_NAME_add_entry_by_txt(name,
		"O", MBSTRING_UTF8, (unsigned char *)organization, -1, -1, 0)) {
		err(USER_F_CFPK, 120);
		goto fail;
	}
	if (!X509_NAME_add_entry_by_txt(name,
		"CN", MBSTRING_UTF8, (unsigned char *)commonName, -1, -1, 0)) {
		err(USER_F_CFPK, 130);
		goto fail;
	}

	X509_set_issuer_name(x, name); // Same as subject because self-signed

	if (!add_ext(x, NID_basic_constraints, "critical,CA:TRUE")) {
		err(USER_F_CFPK, 140);
		goto fail;
	}
	if (!add_ext(x, NID_key_usage, "critical,digitalSignature,keyEncipherment,keyCertSign")) {
		err(USER_F_CFPK, 150);
		goto fail;
	}
	if (!add_ext(x, NID_ext_key_usage, "serverAuth")) {
		err(USER_F_CFPK, 160);
		goto fail;
	}
	if (!add_ext(x, NID_subject_key_identifier, "hash")) {
		err(USER_F_CFPK, 170);
		goto fail;
	}

	char *altName = NULL;
	asprintf(&altName, "DNS:%s", commonName);
	if (altName == NULL) {
		err(USER_F_CFPK, 180);
		goto fail;
	}
	if (!add_ext(x, NID_subject_alt_name, altName)) {
		err(USER_F_CFPK, 190);
		free(altName);
		goto fail;
	}
	free(altName);

	if (!X509_sign(x, pk, EVP_sha256())) {
		err(USER_F_CFPK, 200);
		goto fail;
	}

	EVP_PKEY_free(pk);
	return x;

fail:
	if (x == NULL) {
		X509_free(x);
	}
	if (pk == NULL) {
		EVP_PKEY_free(pk);
	}
	return NULL;
}

static int _cacert_from_priv_key_DER(
	uint8_t *rsaPrivKeyDER,
	size_t rsaPrivKeyDERLen,
	const char *commonName,
	const char *organization,
	const char *countryCode,
	int hoursBefore,
	int hoursAfter,
	uint8_t **certDEROut,
	size_t *certDERLenOut
) {
	uint8_t *p = rsaPrivKeyDER;
	RSA *privKey = d2i_RSAPrivateKey(NULL, (unsigned const char **)&p, (long)rsaPrivKeyDERLen);
	if (privKey == NULL) {
		err(USER_F_CFPKD, 10);
		return 0;
	}

	X509 *cert = cacert_from_priv_key(
		privKey, // reference consumed
		commonName,
		organization,
		countryCode,
		hoursBefore,
		hoursAfter);
	if (cert == NULL) {
		return 0;
	}

	int cerDERLen = i2d_X509(cert, certDEROut);
	X509_free(cert);

	if (cerDERLen <= 0) {
		err(USER_F_CFPKD, 20);
		OPENSSL_free(*certDEROut);
		*certDEROut = NULL;
		return 0;
	}

	*certDERLenOut = cerDERLen;
	return 1;
}

int cacert_from_priv_key_DER(
	uint8_t *rsaPrivKeyDER,
	size_t rsaPrivKeyDERLen,
	const char *commonName,
	const char *organization,
	const char *countryCode,
	int hoursBefore,
	int hoursAfter,
	uint8_t **certDEROut,
	size_t *certDERLenOut,
	char **errStrOut
) {
	uint8_t *certDER = NULL;
	size_t certDERLen = 0;
	int ret = _cacert_from_priv_key_DER(
		rsaPrivKeyDER,
		rsaPrivKeyDERLen,
		commonName,
		organization,
		countryCode,
		hoursBefore,
		hoursAfter,
		&certDER,
		&certDERLen);

	if (ret) {
		*certDERLenOut = certDERLen;
		*certDEROut = malloc(certDERLen);
		memcpy(*certDEROut, certDER, certDERLen);
		OPENSSL_free(certDER);
		certDER = NULL;
	} else {
		if (certDERLenOut) {
			*certDERLenOut = 0;
		}
		if (certDEROut) {
			*certDEROut = NULL;
		}
	}

	if (errStrOut != NULL) {
		*errStrOut = NULL;
		if (!ret) {
			BIO *mem = BIO_new(BIO_s_mem());
			if (mem != NULL) {
				ERR_print_errors(mem);
				BIO_get_mem_data(mem, errStrOut);
			}
		}
	}

	return ret;
}
