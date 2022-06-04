#include <iostream>

// declare external lookup tables
extern int sbox_f[256];
extern int sbox_r[256];
extern int rcon[256];
extern int mul_2[256];
extern int mul_3[256];
extern int mul_9[256];
extern int mul_11[256];
extern int mul_13[256];
extern int mul_14[256];

extern void keyExpansionCore(unsigned char*, unsigned char);
extern void keyExpansion(const unsigned char*, unsigned char*);
extern void addRoundKey(unsigned char*, unsigned char*);

void subBytes_inv(unsigned char* state) {
  // for each element of the state
  for (int i = 0; i < 16; i++) {
    // use value at state[i] as the index of sbox
    state[i] = sbox_r[state[i]];
  }
}

void shiftRows_inv(unsigned char* state) {
  // initialise array to store shifted values
  unsigned char shifted[16];

  // shift first column
  shifted[0] = state[0];
  shifted[1] = state[13];
  shifted[2] = state[10];
  shifted[3] = state[7];

  // shift second column
  shifted[4] = state[4];
  shifted[5] = state[1];
  shifted[6] = state[14];
  shifted[7] = state[11];

  // shift third column
  shifted[8] = state[8];
  shifted[9] = state[5];
  shifted[10] = state[2];
  shifted[11] = state[15];

  // shift fourth column
  shifted[12] = state[12];
  shifted[13] = state[9];
  shifted[14] = state[6];
  shifted[15] = state[3];

  // copy shifted array to state
  for (int i = 0; i < 16; i++) {
    state[i] = shifted[i];
  }
}

void mixColumns_inv(unsigned char* state) {
  // initialise array to store mixed values
  unsigned char mixed[16];

  mixed[0] = (unsigned char)(mul_14[state[0]] ^ mul_11[state[1]] ^
                             mul_13[state[2]] ^ mul_9[state[3]]);
  mixed[1] = (unsigned char)(mul_9[state[0]] ^ mul_14[state[1]] ^
                             mul_11[state[2]] ^ mul_13[state[3]]);
  mixed[2] = (unsigned char)(mul_13[state[0]] ^ mul_9[state[1]] ^
                             mul_14[state[2]] ^ mul_11[state[3]]);
  mixed[3] = (unsigned char)(mul_11[state[0]] ^ mul_13[state[1]] ^
                             mul_9[state[2]] ^ mul_14[state[3]]);

  mixed[4] = (unsigned char)(mul_14[state[4]] ^ mul_11[state[5]] ^
                             mul_13[state[6]] ^ mul_9[state[7]]);
  mixed[5] = (unsigned char)(mul_9[state[4]] ^ mul_14[state[5]] ^
                             mul_11[state[6]] ^ mul_13[state[7]]);
  mixed[6] = (unsigned char)(mul_13[state[4]] ^ mul_9[state[5]] ^
                             mul_14[state[6]] ^ mul_11[state[7]]);
  mixed[7] = (unsigned char)(mul_11[state[4]] ^ mul_13[state[5]] ^
                             mul_9[state[6]] ^ mul_14[state[7]]);

  mixed[8] = (unsigned char)(mul_14[state[8]] ^ mul_11[state[9]] ^
                             mul_13[state[10]] ^ mul_9[state[11]]);
  mixed[9] = (unsigned char)(mul_9[state[8]] ^ mul_14[state[9]] ^
                             mul_11[state[10]] ^ mul_13[state[11]]);
  mixed[10] = (unsigned char)(mul_13[state[8]] ^ mul_9[state[9]] ^
                              mul_14[state[10]] ^ mul_11[state[11]]);
  mixed[11] = (unsigned char)(mul_11[state[8]] ^ mul_13[state[9]] ^
                              mul_9[state[10]] ^ mul_14[state[11]]);

  mixed[12] = (unsigned char)(mul_14[state[12]] ^ mul_11[state[13]] ^
                              mul_13[state[14]] ^ mul_9[state[15]]);
  mixed[13] = (unsigned char)(mul_9[state[12]] ^ mul_14[state[13]] ^
                              mul_11[state[14]] ^ mul_13[state[15]]);
  mixed[14] = (unsigned char)(mul_13[state[12]] ^ mul_9[state[13]] ^
                              mul_14[state[14]] ^ mul_11[state[15]]);
  mixed[15] = (unsigned char)(mul_11[state[12]] ^ mul_13[state[13]] ^
                              mul_9[state[14]] ^ mul_14[state[15]]);

  for (int i = 0; i < 16; i++) {
    state[i] = mixed[i];
  }
}

void decryptCore(unsigned char* state, unsigned char* keys) {
  // addRoundKey(state, keys); ?
  addRoundKey(state, &keys[160]);

  for (int i = 8; i >= 0; i--) {
    shiftRows_inv(state);
    subBytes_inv(state);
    addRoundKey(state, &keys[16 * (i + 1)]);
    mixColumns_inv(state);
  }

  shiftRows_inv(state);
  subBytes_inv(state);
  addRoundKey(state, keys);
}

unsigned char* decrypt(const unsigned char* plaintext,
                       const unsigned char* key) {
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
  for (int i = 0; i < lengthPadded; i += 16) {
    decryptCore(&ciphertext[i], expandedKeys);
  }

  return ciphertext;
}