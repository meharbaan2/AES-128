#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Function prototype declarations
void print_state(uint8_t state[4][4], const char* label);

void print_metadata() {
    printf("  Software Implementation of AES and Its Modified Version\n");
    printf("-----------------------------------------------------------\n");
    printf("Row Swap Code (A,B) = (6,9)\n");
    printf("Assigned Plaintext and Key:\n");
    printf("    0000 0000 0000 0000 0000 0000 0000 abf2 (plaintext)\n");
    printf("    1a0c 24f2 8754 95bc b708 0e43 920f 56a2 (key)\n\n");
    printf("Language: C (Legacy MSVC)\n");
    printf("Compiler: MSVC 19.42.34435 (VS 2022)\n");
    printf("The program was written in C for Windows 11 operating system\n\n");
}

// Original S-Box (16x16)
const uint8_t s_box[16][16] =
{
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

// Modified S-Box (swap rows A and B)
uint8_t modified_s_box[16][16];

// Rijndael RCON table (for key expansion)
const uint8_t rcon[10] =
{
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Original Key Expansion (AES-128)
void key_expansion(const uint8_t* key, uint8_t* round_keys)
{
    uint8_t temp[4];

    // First 16 bytes are the original key
    for (int i = 0; i < 16; i++)
    {
        round_keys[i] = key[i];
    }

    // Generate the remaining round keys
    for (int i = 4; i < 44; i++)
    {
        // Read previous word
        for (int j = 0; j < 4; j++)
        {
            temp[j] = round_keys[(i - 1) * 4 + j];
        }

        // Perform key schedule core for each 4th word
        if (i % 4 == 0)
        {
            // Rotate word
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord (using modified S-Box)
            for (int j = 0; j < 4; j++)
            {
                temp[j] = s_box[temp[j] >> 4][temp[j] & 0x0F];
            }

            // XOR with RCON
            temp[0] ^= rcon[i / 4 - 1];
        }

        // XOR with the word 4 positions back
        for (int j = 0; j < 4; j++)
        {
            round_keys[i * 4 + j] = round_keys[(i - 4) * 4 + j] ^ temp[j];
        }
    }
    // Printing round keys after each result
    printf("-----------------------------------------------------------\n");
    printf("Key Rounds with standard AES:\n");
    printf("-----------------------------------------------------------\n");
    for (int round = 0; round <= 10; round++)
    {
        printf("Round %d:\n", round);
        printf("      Key: ");
        for (int i = 0; i < 16; i++)
        {
            printf("%02x ", round_keys[round * 16 + i]);
        }
        printf("\n");
    }
    printf("\n");
}

// Swap rows A and B in the S-Box
void swap_s_box_rows(int row_a, int row_b)
{
    for (int i = 0; i < 16; i++) {
        uint8_t temp = modified_s_box[row_a][i];
        modified_s_box[row_a][i] = modified_s_box[row_b][i];
        modified_s_box[row_b][i] = temp;
    }
}

// Initialize modified S-Box
void init_modified_s_box(int row_a, int row_b)
{
    memcpy(modified_s_box, s_box, sizeof(s_box));
    swap_s_box_rows(row_a, row_b);
}

// Modified Key Expansion (AES-128)
void modified_key_expansion(const uint8_t* key, uint8_t* round_keys)
{
    uint8_t temp[4];

    // First 16 bytes are the original key
    for (int i = 0; i < 16; i++)
    {
        round_keys[i] = key[i];
    }

    // Generate the remaining round keys
    for (int i = 4; i < 44; i++)
    {
        // Read previous word
        for (int j = 0; j < 4; j++)
        {
            temp[j] = round_keys[(i - 1) * 4 + j];
        }

        // Perform key schedule core for each 4th word
        if (i % 4 == 0)
        {
            // Rotate word
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord (using modified S-Box)
            for (int j = 0; j < 4; j++)
            {
                temp[j] = modified_s_box[temp[j] >> 4][temp[j] & 0x0F];
            }

            // XOR with RCON
            temp[0] ^= rcon[i / 4 - 1];
        }

        // XOR with the word 4 positions back
        for (int j = 0; j < 4; j++)
        {
            round_keys[i * 4 + j] = round_keys[(i - 4) * 4 + j] ^ temp[j];
        }
    }
    // Printing round keys after each result
    printf("-----------------------------------------------------------\n");
    printf("Key Rounds with modified AES:\n");
    printf("-----------------------------------------------------------\n");
    for (int round = 0; round <= 10; round++)
    {
        printf("Round %d:\n", round);
        printf("      Key: ");
        for (int i = 0; i < 16; i++)
        {
            printf("%02x ", round_keys[round * 16 + i]);
        }
        printf("\n");
    }
    printf("\n");
}

// SubBytes transformation
void sub_bytes(uint8_t state[4][4], const uint8_t sbox[16][16])
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            state[i][j] = sbox[state[i][j] >> 4][state[i][j] & 0x0F];
        }
    }
}

// ShiftRows transformation
void shift_rows(uint8_t state[4][4])
{
    uint8_t temp;

    // Row 1: Rotate left by 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Row 2: Rotate left by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: Rotate left by 3 (or right by 1)
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

// Galois Field Multiplication (used in MixColumns)
uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1) p ^= a;
        uint8_t carry = a & 0x80;
        a <<= 1;
        if (carry) a ^= 0x1b;  // XOR with irreducible polynomial
        b >>= 1;
    }
    return p;
}

// MixColumns transformation
void mix_columns(uint8_t state[4][4])
{
    for (int i = 0; i < 4; i++)
    {
        uint8_t a[4], b[4];
        for (int j = 0; j < 4; j++)
        {
            a[j] = state[j][i];
        }
        b[0] = gmul(0x02, a[0]) ^ gmul(0x03, a[1]) ^ a[2] ^ a[3];
        b[1] = a[0] ^ gmul(0x02, a[1]) ^ gmul(0x03, a[2]) ^ a[3];
        b[2] = a[0] ^ a[1] ^ gmul(0x02, a[2]) ^ gmul(0x03, a[3]);
        b[3] = gmul(0x03, a[0]) ^ a[1] ^ a[2] ^ gmul(0x02, a[3]);
        for (int j = 0; j < 4; j++)
        {
            state[j][i] = b[j];
        }
    }
}

// AddRoundKey transformation
void add_round_key(uint8_t state[4][4], const uint8_t* round_key)
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            state[i][j] ^= round_key[i + 4 * j];
        }
    }
}

// AES Encryption (10 rounds for 128-bit key)
void aes_encrypt(uint8_t state[4][4], const uint8_t* round_keys, const uint8_t sbox[16][16], const char* mode) {

    // Print initial state
    printf("Round 0:\n");
    printf("-----Start: ");
    print_state(state, "");  // Single line output

    // Initial round (Round 0)
    add_round_key(state, round_keys);
    printf("----Output: ");
    print_state(state, "");

    // Main rounds (1-9)
    for (int round = 1; round <= 9; round++) {
        printf("Round %d:\n", round);

        sub_bytes(state, sbox);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * 16);

        printf("----Output: ");
        print_state(state, "");
    }

    // Final round (Round 10 no MixColumns)
    printf("Round 10:\n");
    sub_bytes(state, sbox);
    shift_rows(state);
    add_round_key(state, round_keys + 10 * 16);
    printf("----Output: ");
    print_state(state, "");
}

// Print state matrix
void print_state(uint8_t state[4][4], const char* label) {
    if (strlen(label) > 0) {
        printf("%s\n", label);  // Only print label if it's not empty
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);  // Column-major order
        }
    }
    printf("\n");
}

void print_sbox(const uint8_t sbox[16][16], const char* label) {
    printf("%s:\n", label);
    for (int i = 0; i < 16; i++) {
        printf("Row %02x: ", i);
        for (int j = 0; j < 16; j++) {
            printf("%02x ", sbox[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

// Helper function to properly initialize state
void memcpy_to_state(const uint8_t* src, uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = src[i * 4 + j];  // Column-major order
        }
    }
}

int main() {
    // Print info for report
    print_metadata();

    // Group code (A, B) = (6, 9)
    int A = 6, B = 9;

    /*printf("=== Original S-Box ===\n");
    print_sbox(s_box, "Original S-Box");*/

    // Initialize modified S-Box
    init_modified_s_box(A, B);

    // Print modified S-Box
    /*printf("=== Modified S-Box (Rows %d and %d swapped) ===\n", A, B);
    print_sbox(modified_s_box, "Modified S-Box");*/

    // Plaintext and key
    uint8_t plaintext[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xf2 };
    uint8_t key[16] = { 0x1a, 0x0c, 0x24, 0xf2, 0x87, 0x54, 0x95, 0xbc, 0xb7, 0x08, 0x0e, 0x43, 0x92, 0x0f, 0x56, 0xa2 };

    /*uint8_t plaintext[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };*/

    // Key expansion
    uint8_t round_keys[176];  // 11 round keys (16 bytes each)
    uint8_t modi_round_keys[176];  // 11 round keys (16 bytes each)
    key_expansion(key, round_keys);
    modified_key_expansion(key, modi_round_keys);

    // Encrypt with original AES
    uint8_t state_orig[4][4];
    memcpy_to_state(plaintext, state_orig);
    printf("-----------------------------------------------------------\n");
    printf("Output Rounds with original AES:\n");
    printf("-----------------------------------------------------------\n");
    aes_encrypt(state_orig, round_keys, s_box, "Original AES");
    printf("\n");

    // Encrypt with modified AES
    uint8_t state_mod[4][4];
    memcpy_to_state(plaintext, state_mod);  // Same initial state
    printf("-----------------------------------------------------------\n");
    printf("Output Rounds with modified AES:\n");
    printf("-----------------------------------------------------------\n");
    aes_encrypt(state_mod, modi_round_keys, modified_s_box, "Modified AES");
    printf("-----------------------------------------------------------\n");

    return 0;
}
