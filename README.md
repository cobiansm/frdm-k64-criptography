# Embedded Cryptography Suite 

## Overview
This repository contains a comprehensive suite of cryptographic algorithms implemented on the NXP FRDM-K64F microcontroller using the mbedTLS library. The project is organized into specific branches to demonstrate the implementation, benchmarking, and testing of different security primitives.

| Branch                         | Algorithm        | Description                                                                 |
|--------------------------------|------------------|-----------------------------------------------------------------------------|
| cripto-final-project           | Full Workflow    | Integration of AES + SHA-256 + ECDSA.                                      |
| aes-cipher                     | AES-256 CBC      | Symmetric encryption for data confidentiality using 256-bit keys and IVs.  |
| hash-sha-256                   | SHA-256          | Secure hashing to generate 32-byte message digests for integrity checks.   |
| chacha20-cipher                | ChaCha20         | High-performance stream cipher implementation, often faster than AES in software. |
| pseudorandom-number-generator  | Custom PRNG      | Pseudo-random number generator using a custom `myrand()` source for embedded entropy. |
