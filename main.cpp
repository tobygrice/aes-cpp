#include <iostream>

extern int sbox_f[256];

void keyExpansion() {}

void addRoundKey(unsigned char* state, unsigned char* roundKey) {
  // for each element of the state
  for (int i = 0; i < 16; i++) {
    // xor state with roundkey
    state[i] ^= roundKey[i];
  }
}

void subBytes(unsigned char* state) {
  // for each element of the state
  for (int i = 0; i < 16; i++) {
    // use value at state[i] as the index of sbox
    state[i] = sbox_f[state[i]];
  }
}

void shiftRows(unsigned char* state) {
  // initialise array to store shifted values
  unsigned char shifted[16];

  // shift first column
  shifted[0] = state[0];
  shifted[1] = state[5];
  shifted[2] = state[10];
  shifted[3] = state[15];

  // shift second column
  shifted[4] = state[4];
  shifted[5] = state[9];
  shifted[6] = state[14];
  shifted[7] = state[3];

  // shift third column
  shifted[8] = state[8];
  shifted[9] = state[13];
  shifted[10] = state[2];
  shifted[11] = state[7];

  // shift fourth column
  shifted[12] = state[12];
  shifted[13] = state[1];
  shifted[14] = state[6];
  shifted[15] = state[11];

  // copy shifted array to state
  for (int i = 0; i < 16; i++) {
    state[i] = shifted[i];
  }
}

void mixColumns() {}

void encrypt(unsigned char* state, unsigned char* key) {
  int numRounds = 10;

  keyExpansion();
  addRoundKey(state, key);

  for (int i = 0; i < numRounds; i++) {
    subBytes(state);
    shiftRows(state);
    mixColumns();
    addRoundKey(state, key);
  }

  subBytes(state);
  shiftRows(state);
  addRoundKey(state, key);
}

int main() {
  char* plaintext = "This is a message we will encrypt with AES!";
  unsigned char key[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                           9, 10, 11, 12, 13, 14, 15, 16};

  unsigned char state[16];
  for (int i = 0; i < 16; i++) {
    state[i] = plaintext[i];
  }

  encrypt(state, key);

  return 0;
}
