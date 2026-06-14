/*
 * Legacy mbedtls_ecdh_compute_shared() for mbedTLS v4.
 *
 * The ECDH module was removed; this helper is implemented on top of the
 * still-available ECP primitives (SEC1 3.3.1).
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_ECP_C)

#include "mbedtls/error.h"
#include "mbedtls/ecdh.h"

int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point P;

    mbedtls_ecp_point_init(&P);

    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_restartable(grp, &P, d, Q,
                                                f_rng, p_rng, NULL));

    if (mbedtls_ecp_is_zero(&P)) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(z, &P.X));

cleanup:
    mbedtls_ecp_point_free(&P);
    return ret;
}

#endif /* MBEDTLS_ECP_C */
