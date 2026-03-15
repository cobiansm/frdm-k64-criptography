# Final project on FRDM-K64

## Overview

This project implements a complete cryptographic security workflow on an embedded system (FRDM-K64F) using the mbedTLS library. The primary objective is to guarantee the confidentiality, integrity, and authenticity of a message through three fundamental stages: **Encryption, Hashing, and Digital Signature**.

## Workflow
- **Encryption**: Plaintext message is encrypted using AES-256 in CBC (Cipher Block Chaining) mode. An Initialization Vector (IV) is utilized to ensure a robust and non-deterministic ciphertext.
- **Hashing**: A unique "digital fingerprint" of the ciphertext is generated using the SHA-256 algorithm. This ensures that any unauthorized modification to the encrypted data can be immediately detected.
- **Digital Signature**: The resulting hash is digitally signed using ECDSA (Elliptic Curve Digital Signature Algorithm). This proves the origin of the message and provides non-repudiation.
