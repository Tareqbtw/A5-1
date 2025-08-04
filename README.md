This project implements a brute-force attack on the A5/1 stream cipher to recover the internal state of the cipher using a known plaintext attack.

Project Description
The A5/1 cipher is a stream cipher used in GSM mobile communications. This project demonstrates how a known plaintext can be used to recover the internal state of the cipher by brute-forcing one of the registers 
(Y-register) when the other two (X and Z) are known.

Features:
Implements the A5/1 keystream generation algorithm
Performs a brute-force attack on the Y-register state
Recovers full plaintext from ciphertext once the internal state is known
Handles bit-level operations for encryption/decryption
Includes progress tracking using tqdm

This project is also aiming to help you understanding the basics of cryptography.

