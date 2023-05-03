/* SPDX-License-Identifier: MIT */

/*
 * Attestation report requirement. SNP_GUEST_REQUEST messages have to be
 * encrypted using AES_GCM, which is accessible using the EVP interface.
 */
#include <openssl/evp.h>
