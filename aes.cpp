#include <iostream>

extern int sbox_f[256];
extern int rcon[256];

extern unsigned char* encrypt(unsigned char[16], unsigned char*);
extern unsigned char* decrypt(unsigned char[16], unsigned char*);

void keyExpansionCore(unsigned char[4], unsigned char);
void keyExpansion(const unsigned char[16], unsigned char[176]);

// Takes plaintext, a 16-byte key, and boolean value. Returns encrypted text if
// isEncryption is true, or decrypted text if false.
unsigned char* aes(const unsigned char* plaintext, const unsigned char* key,
                   bool isEncryption) {
  // expand keys
  unsigned char expandedKeys[176];
  keyExpansion(key, expandedKeys);

  // calculate size of plaintext after padding
  unsigned int lengthPlaintext = strlen((const char*)plaintext);
  unsigned int lengthPadded;
  if (lengthPlaintext % 16 != 0) {
    // round up to the nearest multiple of 16 and store in lengthPadded
    lengthPadded = (lengthPlaintext / 16 + 1) * 16;
  } else {
    lengthPadded = lengthPlaintext;
  }

  // initialise ciphertext with plaintext, padded with 0s to reach a multiple of
  // 16 bytes
  unsigned char* ciphertext = new unsigned char[lengthPadded];
  for (int i = 0; i < lengthPadded; i++) {
    if (i >= lengthPlaintext)
      ciphertext[i] = 0;
    else
      ciphertext[i] = plaintext[i];
  }

  // perform encryptCore on ciphertext 16 bytes at a time
  if (isEncryption) {
    for (int i = 0; i < lengthPadded; i += 16) {
      encrypt(&ciphertext[i], expandedKeys);
    }
  } else {
    for (int i = 0; i < lengthPadded; i += 16) {
      decrypt(&ciphertext[i], expandedKeys);
    }
  }

  return ciphertext;
}

// Generates the first four bytes of each round key.
void keyExpansionCore(unsigned char in[4], unsigned char i) {
  // rotate bytes left
  unsigned char t = in[0];
  in[0] = in[1];
  in[1] = in[2];
  in[2] = in[3];
  in[3] = t;

  // sub bytes from forward sbox
  in[0] = sbox_f[in[0]];
  in[1] = sbox_f[in[1]];
  in[2] = sbox_f[in[2]];
  in[3] = sbox_f[in[3]];

  // xor with rcon[rconIteration]
  in[0] ^= rcon[i];
}

// Generates 10 new keys (11 total) and stores them in expandedKeys.
void keyExpansion(const unsigned char key[16],
                  unsigned char expandedKeys[176]) {
  // the first 16 bytes are the original key
  for (int i = 0; i < 16; i++) {
    expandedKeys[i] = key[i];
  }

  int bytesGenerated = 16;  // 16 bytes of expandedKeys has now been generated
  int rconIteration = 1;    // 1 iteration has been completed

  // initialise temporary array for keyExpansionCore
  unsigned char temp[4];

  while (bytesGenerated < 176) {
    // store the previous 4 bytes of expandedKeys in temp array
    for (int i = 0; i < 4; i++) {
      temp[i] = expandedKeys[i + bytesGenerated - 4];
    }

    // perform key expansion core only on the first four bytes of each new key
    if (bytesGenerated % 16 == 0) {
      keyExpansionCore(temp, rconIteration);
      rconIteration++;
    }

    // store the newly generated 4 bytes
    for (int i = 0; i < 4; i++) {
      // xor each byte with the byte 16 positions behind
      temp[i] ^= expandedKeys[bytesGenerated - 16];
      expandedKeys[bytesGenerated] = temp[i];
      bytesGenerated++;
    }
  }
}

// XORs state and roundKey. Identical for encryption and decryption.
void addRoundKey(unsigned char* state, unsigned char* roundKey) {
  // for each element of the state
  for (int i = 0; i < 16; i++) {
    // xor state with roundkey
    state[i] ^= roundKey[i];
  }
}