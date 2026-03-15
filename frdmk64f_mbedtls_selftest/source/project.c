/*
 *  Proyecto Final Cripto - Opción 2
 *  Marlene Cobian
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_debug_console.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t use_len;
    int rnd;

    if( rng_state != NULL )
        rng_state  = NULL;

    while( len > 0 )
    {
        use_len = len;
        if( use_len > sizeof(int) )
            use_len = sizeof(int);

        rnd = rand();
        memcpy( output, &rnd, use_len );
        output += use_len;
        len -= use_len;
    }

    return( 0 );
}

int main(void) {

	/* HW init */
	BOARD_InitBootPins();
	BOARD_InitBootClocks();
	BOARD_InitDebugConsole();

	PRINTF("--- Final Project ---\r\n\n");

	/* AES 256 */
	unsigned char key[32] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	};

	/* initializing vector */
	unsigned char iv[16] = "init_vector_aes_";
	unsigned char iv_copy[16];
	memcpy(iv_copy, iv, 16);

	/* Message to encrypt */
	unsigned char plain_text[32] = "Proyecto final - Marlene Cobian";
	unsigned char encrypted_message[32];
	unsigned char decrypted_message[32];

	/* mbedTLS context */
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);

	/* Encrypt */
	mbedtls_aes_setkey_enc(&aes, key, 256);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 32, iv_copy, plain_text, encrypted_message);

	PRINTF("Encrypted message:\r\n");
	for(int i=0; i<32; i++) {
		PRINTF("%02x ", encrypted_message[i]);
	}
	PRINTF("\r\n\n");

	/* Decrypt */
	memcpy(iv_copy, iv, 16);
	mbedtls_aes_setkey_dec(&aes, key, 256);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 32, iv_copy, encrypted_message, decrypted_message);

	decrypted_message[31] = '\0';
	PRINTF("Decrypted message:\r\n%s", decrypted_message);
	PRINTF("\r\n\n");

	/* Free */
	mbedtls_aes_free(&aes);

	/* SHA-256 */
	unsigned char output_hash[32];

	/* mbedTLS context */
	mbedtls_sha256_context sha;
	mbedtls_sha256_init(&sha);

	/* Process and give plain text */
	mbedtls_sha256_starts_ret(&sha, 0);
	mbedtls_sha256_update_ret(&sha, encrypted_message, 32);

	/* Output hash */
	mbedtls_sha256_finish_ret(&sha, output_hash);

	/* Show hash */
	PRINTF("SHA-256 Hash:\r\n");
	for(int i=0; i < 32; i++) {
		PRINTF("%02x", output_hash[i]);
	}
	PRINTF("\r\n\n");

	/* Free */
	mbedtls_sha256_free(&sha);

	/* ECDSA */
	mbedtls_ecdsa_context ecdsa;
	unsigned char sig[100];
	size_t sig_len;

	/* Initialize ECDSA */
	mbedtls_ecdsa_init(&ecdsa);

	/* Seed */
	srand(24568);

	/* Generate key */
	int ret;
	ret = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256R1, myrand, NULL);
	if(ret != 0) { PRINTF("Genkey error: %d\r\n", ret); return 1; }

	/* Signing */
	ret = mbedtls_ecdsa_write_signature( &ecdsa, MBEDTLS_MD_SHA256,
									output_hash, 32,
										 sig, &sig_len,
										 myrand, NULL);
	if(ret != 0) { PRINTF("Error: %d\n", ret); return 1; }
	PRINTF("Signed Successfully! Size: %u bytes\r\n", (unsigned int)sig_len);

	PRINTF("ECDSA Signature (Hex):\r\n");
	for(int i = 0; i < (int)sig_len; i++) {
		PRINTF("%02x ", sig[i]);

		if((i + 1) % 16 == 0) {
			PRINTF("\r\n");
		}
	}
	PRINTF("\r\n\n");

	PRINTF("Verifying signature\r\n");
	ret = mbedtls_ecdsa_read_signature( &ecdsa, output_hash, 32, sig, sig_len);

	if(ret == 0) {
		PRINTF("Successful signature verification!\r\n");
	} else {
		PRINTF("Invalid signature: %d\r\n", ret);
	}

	mbedtls_ecdsa_free(&ecdsa);

	while (1) {
	}
}
