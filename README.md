# AES
AES-128 Encryption Implementation in C 

Overview :
This project implements the AES (Advanced Encryption Standard) algorithm in C, using: 
128-bit key and 128-bit block size 
Focus on encryption phase and round key generation over 10 rounds 
Operates in a basic mode equivalent to ECB (Electronic Codebook) 
Additionally, a custom AES variant is included with a modified S-box (row swaps) to explore the effect of small structural changes on encryption. 

Features : 
Original AES-128 encryption with round-by-round output 
Custom S-box variant for experimentation 
Key expansion for standard and modified AES 
Easy to modify plaintext and key for testing 

Usage : 
The program will display round-by-round encryption output for both Original AES and Modified AES with swapped S-box rows  

Code Structure :
main() – Entry point; sets up S-box, plaintext, key, performs encryption 
print_metadata() – Prints project info 
init_modified_s_box(A, B) – Creates modified S-box by swapping rows A and B 
key_expansion() / modified_key_expansion() – Generates round keys 
aes_encrypt() – Performs AES encryption on a 4x4 state 
memcpy_to_state() – Converts linear array into AES state matrix  

Notes :
The modified AES variant is educational for analyzing structural sensitivity. 
ECB mode is not secure for multiple-block data; this project is for single-block demonstration and analysis.
If its for your college project, I recommend you first try own your own.
Future extensions may include other modes (CBC, CFB, OFB, CTR), decryption, and performance evaluation. 
