/*
 * Lazy ECP keypair materialization for PSA-backed PK contexts (mbedTLS v4).
 *
 * mbedTLS v4 stores EC private keys in PSA slots; legacy code expects a
 * transparent mbedtls_ecp_keypair from mbedtls_pk_ec(). We materialize one
 * on demand and cache it by pk_context pointer until mbedtls_pk_free().
 */

#define MBEDTLS_V3_SHIM_INTERNAL

#include <string.h>

#include "mbedtls/build_info.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "psa/crypto.h"

#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

#include "mbedtls/pk.h"
#include "mbedtls/private/pk_private.h"
#include "mbedtls/private/ecp.h"

#include "mbedtls_v3_shim/pk_ec.h"

typedef struct mbedtls_v3_shim_pk_ec_entry {
    mbedtls_pk_context *pk;
    mbedtls_ecp_keypair *ec;
    struct mbedtls_v3_shim_pk_ec_entry *next;
} mbedtls_v3_shim_pk_ec_entry;

static mbedtls_v3_shim_pk_ec_entry *s_pk_ec_cache;

/* Internal helpers still built into libmbedcrypto. */
mbedtls_ecp_group_id mbedtls_ecc_group_from_psa(psa_ecc_family_t family,
                                                size_t bits);

static mbedtls_v3_shim_pk_ec_entry *cache_find(mbedtls_pk_context *pk)
{
    mbedtls_v3_shim_pk_ec_entry *entry;

    for (entry = s_pk_ec_cache; entry != NULL; entry = entry->next) {
        if (entry->pk == pk) {
            return entry;
        }
    }

    return NULL;
}

void mbedtls_v3_shim_pk_ec_cache_release(mbedtls_pk_context *pk)
{
    mbedtls_v3_shim_pk_ec_entry **cursor = &s_pk_ec_cache;

    while (*cursor != NULL) {
        if ((*cursor)->pk == pk) {
            mbedtls_v3_shim_pk_ec_entry *dead = *cursor;

            *cursor = dead->next;
            if (dead->ec != NULL) {
                mbedtls_ecp_keypair_free(dead->ec);
                mbedtls_free(dead->ec);
            }
            mbedtls_free(dead);
            return;
        }
        cursor = &(*cursor)->next;
    }
}

static int cache_insert(mbedtls_pk_context *pk, mbedtls_ecp_keypair *ec)
{
    mbedtls_v3_shim_pk_ec_entry *entry =
        mbedtls_calloc(1, sizeof(*entry));

    if (entry == NULL) {
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    entry->pk = pk;
    entry->ec = ec;
    entry->next = s_pk_ec_cache;
    s_pk_ec_cache = entry;

    return 0;
}

static int pk_is_ec(const mbedtls_pk_context *pk)
{
    switch (mbedtls_pk_get_type(pk)) {
        case MBEDTLS_PK_ECKEY:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECDSA:
            return 1;
        default:
            return 0;
    }
}

static mbedtls_ecp_keypair *alloc_empty_ec(void)
{
    mbedtls_ecp_keypair *ec =
        mbedtls_calloc(1, sizeof(*ec));

    if (ec == NULL) {
        return NULL;
    }

    mbedtls_ecp_keypair_init(ec);
    return ec;
}

static mbedtls_ecp_group_id pk_ec_group_id(const mbedtls_pk_context *pk)
{
#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
    return mbedtls_ecc_group_from_psa(pk->MBEDTLS_PRIVATE(ec_family),
                                      pk->MBEDTLS_PRIVATE(bits));
#else
    (void) pk;
    return MBEDTLS_ECP_DP_NONE;
#endif
}

static int load_public_point(mbedtls_ecp_keypair *ec,
                             const mbedtls_pk_context *pk)
{
    if (pk->MBEDTLS_PRIVATE(pub_raw_len) == 0) {
        return 0;
    }

    return mbedtls_ecp_point_read_binary(&ec->grp,
                                         &ec->Q,
                                         pk->MBEDTLS_PRIVATE(pub_raw),
                                         pk->MBEDTLS_PRIVATE(pub_raw_len));
}

#if defined(MBEDTLS_PSA_CRYPTO_C)
static mbedtls_ecp_keypair *materialize_ec_from_psa(
    const mbedtls_pk_context *pk)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    size_t export_size;
    size_t export_len;
    unsigned char *export_buf = NULL;
    mbedtls_ecp_keypair *ec = NULL;
    mbedtls_ecp_group_id grp_id;
    int rc;

    grp_id = pk_ec_group_id(pk);
    if (grp_id == MBEDTLS_ECP_DP_NONE) {
        return NULL;
    }

    ec = alloc_empty_ec();
    if (ec == NULL) {
        return NULL;
    }

    if (!mbedtls_svc_key_id_is_null(pk->MBEDTLS_PRIVATE(priv_id))) {
        status = psa_get_key_attributes(pk->MBEDTLS_PRIVATE(priv_id),
                                        &attributes);
        if (status != PSA_SUCCESS) {
            goto fail;
        }

        export_size = PSA_EXPORT_KEY_OUTPUT_SIZE(
            psa_get_key_type(&attributes),
            psa_get_key_bits(&attributes));
        psa_reset_key_attributes(&attributes);

        if (export_size == 0) {
            goto fail;
        }

        export_buf = mbedtls_calloc(1, export_size);
        if (export_buf == NULL) {
            goto fail;
        }

        status = psa_export_key(pk->MBEDTLS_PRIVATE(priv_id),
                                export_buf,
                                export_size,
                                &export_len);
        if (status != PSA_SUCCESS) {
            goto fail;
        }

        rc = mbedtls_ecp_read_key(grp_id, ec, export_buf, export_len);
        if (rc != 0) {
            goto fail;
        }
    } else {
        rc = mbedtls_ecp_group_load(&ec->grp, grp_id);
        if (rc != 0) {
            goto fail;
        }
    }

    rc = load_public_point(ec, pk);
    if (rc != 0) {
        goto fail;
    }

    mbedtls_free(export_buf);
    return ec;

fail:
    mbedtls_free(export_buf);
    if (ec != NULL) {
        mbedtls_ecp_keypair_free(ec);
        mbedtls_free(ec);
    }
    return NULL;
}
#endif /* MBEDTLS_PSA_CRYPTO_C */

static mbedtls_ecp_keypair *materialize_ec(mbedtls_pk_context *pk)
{
#if defined(MBEDTLS_PSA_CRYPTO_C)
    if (!mbedtls_svc_key_id_is_null(pk->MBEDTLS_PRIVATE(priv_id)) ||
        pk->MBEDTLS_PRIVATE(pub_raw_len) > 0) {
        mbedtls_ecp_keypair *ec = materialize_ec_from_psa(pk);

        if (ec != NULL) {
            return ec;
        }
    }
#endif /* MBEDTLS_PSA_CRYPTO_C */

    return alloc_empty_ec();
}

mbedtls_ecp_keypair *mbedtls_v3_shim_pk_ec(mbedtls_pk_context *pk)
{
    mbedtls_v3_shim_pk_ec_entry *entry;
    mbedtls_ecp_keypair *ec;
    int rc;

    if (pk == NULL || !pk_is_ec(pk)) {
        return NULL;
    }

    entry = cache_find(pk);
    if (entry != NULL) {
        return entry->ec;
    }

    ec = materialize_ec(pk);
    if (ec == NULL) {
        return NULL;
    }

    rc = cache_insert(pk, ec);
    if (rc != 0) {
        mbedtls_ecp_keypair_free(ec);
        mbedtls_free(ec);
        return NULL;
    }

    return ec;
}
