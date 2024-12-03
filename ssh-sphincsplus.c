/* $OpenBSD: $ */
/*
 * Copyright (c) 2013 Markus Friedl <markus@openbsd.org> - ssh-ed25519.c
 * Copyright (c) 2024 Simon Josefsson <simon@josefsson.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <limits.h>

#include "crypto_api.h"

#include <string.h>
#include <stdarg.h>

#include "log.h"
#include "sshbuf.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "ssherr.h"
#include "ssh.h"

static void
ssh_sphincsplus_cleanup(struct sshkey *k)
{
	freezero(k->sphincsplus_pk, SPHINCSPLUS_PK_SZ);
	freezero(k->sphincsplus_sk, SPHINCSPLUS_SK_SZ);
	k->sphincsplus_pk = NULL;
	k->sphincsplus_sk = NULL;
}

static int
ssh_sphincsplus_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a->sphincsplus_pk == NULL || b->sphincsplus_pk == NULL)
		return 0;
	if (memcmp(a->sphincsplus_pk, b->sphincsplus_pk, SPHINCSPLUS_PK_SZ) != 0)
		return 0;
	return 1;
}

static int
ssh_sphincsplus_serialize_public(const struct sshkey *key, struct sshbuf *b,
			      enum sshkey_serialize_rep opts)
{
	int r;

	if (key->sphincsplus_pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshbuf_put_string(b, key->sphincsplus_pk, SPHINCSPLUS_PK_SZ)) != 0)
		return r;

	return 0;
}

static int
ssh_sphincsplus_serialize_private(const struct sshkey *key, struct sshbuf *b,
			       enum sshkey_serialize_rep opts)
{
	int r;

	if ((r = sshbuf_put_string(b, key->sphincsplus_pk, SPHINCSPLUS_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, key->sphincsplus_sk, SPHINCSPLUS_SK_SZ)) != 0)
		return r;

	return 0;
}

static int
ssh_sphincsplus_generate(struct sshkey *k, int bits)
{
	if ((k->sphincsplus_pk = malloc(SPHINCSPLUS_PK_SZ)) == NULL ||
	    (k->sphincsplus_sk = malloc(SPHINCSPLUS_SK_SZ)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	crypto_sign_sphincsplus_keypair(k->sphincsplus_pk, k->sphincsplus_sk);
	return 0;
}

static int
ssh_sphincsplus_copy_public(const struct sshkey *from, struct sshkey *to)
{
	if (from->sphincsplus_pk == NULL)
		return 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	if ((to->sphincsplus_pk = malloc(SPHINCSPLUS_PK_SZ)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	memcpy(to->sphincsplus_pk, from->sphincsplus_pk, SPHINCSPLUS_PK_SZ);
	return 0;
}

static int
ssh_sphincsplus_deserialize_public(const char *ktype, struct sshbuf *b,
				struct sshkey *key)
{
	u_char *pk = NULL;
	size_t len = 0;
	int r;

	if ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		return r;
	if (len != SPHINCSPLUS_PK_SZ) {
		freezero(pk, len);
		return SSH_ERR_INVALID_FORMAT;
	}
	key->sphincsplus_pk = pk;
	return 0;
}

static int
ssh_sphincsplus_deserialize_private(const char *ktype, struct sshbuf *b,
				 struct sshkey *key)
{
	int r;
	size_t sklen = 0;
	u_char *sphincsplus_sk = NULL;

	if ((r = ssh_sphincsplus_deserialize_public(NULL, b, key)) != 0)
		goto out;
	if ((r = sshbuf_get_string(b, &sphincsplus_sk, &sklen)) != 0)
		goto out;
	if (sklen != SPHINCSPLUS_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	key->sphincsplus_sk = sphincsplus_sk;
	sphincsplus_sk = NULL; /* transferred */
	/* success */
	r = 0;
out:
	freezero(sphincsplus_sk, sklen);
	return r;
}

static int
ssh_sphincsplus_sign(struct sshkey *key,
		  u_char **sigp, size_t *lenp,
		  const u_char *data, size_t datalen,
		  const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	u_char *sig = NULL;
	size_t slen = 0, len;
	unsigned long long smlen;
	int r, ret;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_SPHINCSPLUS ||
	    key->sphincsplus_sk == NULL ||
	    datalen >= INT_MAX - crypto_sign_sphincsplus_BYTES)
		return SSH_ERR_INVALID_ARGUMENT;
	smlen = slen = datalen + crypto_sign_sphincsplus_BYTES;
	if ((sig = malloc(slen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((ret = crypto_sign_sphincsplus(sig, &smlen, data, datalen,
					key->sphincsplus_sk)) != 0 || smlen <= datalen) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		goto out;
	}
	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_cstring(b, "ssh-sphincsplus@openssh.com")) != 0 ||
	    (r = sshbuf_put_string(b, sig, smlen - datalen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	/* success */
	r = 0;
out:
	sshbuf_free(b);
	if (sig != NULL)
		freezero(sig, slen);

	return r;
}

static int
ssh_sphincsplus_verify(const struct sshkey *key,
		    const u_char *sig, size_t siglen,
		    const u_char *data, size_t dlen, const char *alg, u_int compat,
		    struct sshkey_sig_details **detailsp)
{
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	const u_char *sigblob;
	u_char *sm = NULL, *m = NULL;
	size_t len;
	unsigned long long smlen = 0, mlen = 0;
	int r, ret;

	if (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_SPHINCSPLUS ||
	    key->sphincsplus_pk == NULL ||
	    dlen >= INT_MAX - crypto_sign_sphincsplus_BYTES ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		goto out;
	if (strcmp("ssh-sphincsplus@openssh.com", ktype) != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if (len > crypto_sign_sphincsplus_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (dlen >= SIZE_MAX - len) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	smlen = len + dlen;
	mlen = smlen;
	if ((sm = malloc(smlen)) == NULL || (m = malloc(mlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(sm, sigblob, len);
	memcpy(sm+len, data, dlen);
	if ((ret = crypto_sign_sphincsplus_open(m, &mlen, sm, smlen,
					     key->sphincsplus_pk)) != 0) {
		debug2_f("crypto_sign_sphincsplus_open failed: %d", ret);
	}
	if (ret != 0 || mlen != dlen) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	/* XXX compare 'm' and 'data' ? */
	/* success */
	r = 0;
out:
	if (sm != NULL)
		freezero(sm, smlen);
	if (m != NULL)
		freezero(m, smlen); /* NB mlen may be invalid if r != 0 */
	sshbuf_free(b);
	free(ktype);
	return r;
}

/* NB. not static; used by SPHINCSPLUS-SK */
const struct sshkey_impl_funcs sshkey_sphincsplus_funcs = {
	/* .size = */		NULL,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_sphincsplus_cleanup,
	/* .equal = */		ssh_sphincsplus_equal,
	/* .ssh_serialize_public = */ ssh_sphincsplus_serialize_public,
	/* .ssh_deserialize_public = */ ssh_sphincsplus_deserialize_public,
	/* .ssh_serialize_private = */ ssh_sphincsplus_serialize_private,
	/* .ssh_deserialize_private = */ ssh_sphincsplus_deserialize_private,
	/* .generate = */	ssh_sphincsplus_generate,
	/* .copy_public = */	ssh_sphincsplus_copy_public,
	/* .sign = */		ssh_sphincsplus_sign,
	/* .verify = */		ssh_sphincsplus_verify,
};

const struct sshkey_impl sshkey_sphincsplus_impl = {
	/* .name = */		"ssh-sphincsplus@openssh.com",
	/* .shortname = */	"SPHINCSPLUS",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_SPHINCSPLUS,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_sphincsplus_funcs,
};

const struct sshkey_impl sshkey_sphincsplus_cert_impl = {
	/* .name = */		"ssh-sphincsplus-cert-v01@openssh.com",
	/* .shortname = */	"SPHINCSPLUS-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_SPHINCSPLUS_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_sphincsplus_funcs,
};
