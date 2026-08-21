/* v3 compatibility: mbedTLS v4 moved this builtin module under mbedtls/private/. */
#pragma once

#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif

#include "mbedtls/build_info.h"
#include "mbedtls/private/sha256.h"
