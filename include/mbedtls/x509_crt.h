/*
 * Compatibility wrapper header for mbedTLS v4 X.509 writing APIs.
 *
 * mbedtls_x509write_crt_der()/_pem() lost their trailing f_rng/p_rng arguments in v4;
 * randomness now comes from the PSA RNG.
 */
#pragma once

#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

#include "mbedtls/build_info.h"

#include_next "mbedtls/x509_crt.h"

#if defined(MBEDTLS_X509_CRT_WRITE_C)

#ifdef __cplusplus
extern "C" {
#endif

static inline int mbedtls_x509write_crt_der_v4_real(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size)
{
    return mbedtls_x509write_crt_der(ctx, buf, size);
}

#if defined(MBEDTLS_PEM_WRITE_C)
static inline int mbedtls_x509write_crt_pem_v4_real(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size)
{
    return mbedtls_x509write_crt_pem(ctx, buf, size);
}
#endif /* MBEDTLS_PEM_WRITE_C */

#ifdef __cplusplus
}
#endif

#define mbedtls_x509write_crt_der(ctx, buf, size, f_rng, p_rng) \
    mbedtls_x509write_crt_der_v4_real(ctx, buf, size)

#if defined(MBEDTLS_PEM_WRITE_C)
#define mbedtls_x509write_crt_pem(ctx, buf, size, f_rng, p_rng) \
    mbedtls_x509write_crt_pem_v4_real(ctx, buf, size)
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_X509_CRT_WRITE_C */
