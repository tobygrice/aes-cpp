// declare external lookup tables
extern int sbox_f[256];
extern int mul_2[256];
extern int mul_3[256];

extern void addRoundKey(unsigned char*, unsigned char*);

// Substitutes each element of the state with its corresponding sbox value.
void subBytes(unsigned char* state) {
  // for each element of the state
  for (int i = 0; i < 16; i++) {
    // use value at state[i] as the index of sbox
    state[i] = sbox_f[state[i]];
  }
}

// Shift each row of the state according to the Rijndael encryption method.
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

// Mix each column of the state according to the Rijndael encryption method.
void mixColumns(unsigned char* state) {
  // initialise array to store mixed values
  unsigned char mixed[16];

  // mix first column
  mixed[0] =
      (unsigned char)(mul_2[state[0]] ^ mul_3[state[1]] ^ state[2] ^ state[3]);
  mixed[1] =
      (unsigned char)(state[0] ^ mul_2[state[1]] ^ mul_3[state[2]] ^ state[3]);
  mixed[2] =
      (unsigned char)(state[0] ^ state[1] ^ mul_2[state[2]] ^ mul_3[state[3]]);
  mixed[3] =
      (unsigned char)(mul_3[state[0]] ^ state[1] ^ state[2] ^ mul_2[state[3]]);

  // mix second column
  mixed[4] =
      (unsigned char)(mul_2[state[4]] ^ mul_3[state[5]] ^ state[6] ^ state[7]);
  mixed[5] =
      (unsigned char)(state[4] ^ mul_2[state[5]] ^ mul_3[state[6]] ^ state[7]);
  mixed[6] =
      (unsigned char)(state[4] ^ state[5] ^ mul_2[state[6]] ^ mul_3[state[7]]);
  mixed[7] =
      (unsigned char)(mul_3[state[4]] ^ state[5] ^ state[6] ^ mul_2[state[7]]);

  // mix third column
  mixed[8] = (unsigned char)(mul_2[state[8]] ^ mul_3[state[9]] ^ state[10] ^
                             state[11]);
  mixed[9] = (unsigned char)(state[8] ^ mul_2[state[9]] ^ mul_3[state[10]] ^
                             state[11]);
  mixed[10] = (unsigned char)(state[8] ^ state[9] ^ mul_2[state[10]] ^
                              mul_3[state[11]]);
  mixed[11] = (unsigned char)(mul_3[state[8]] ^ state[9] ^ state[10] ^
                              mul_2[state[11]]);

  // mix fourth column
  mixed[12] = (unsigned char)(mul_2[state[12]] ^ mul_3[state[13]] ^ state[14] ^
                              state[15]);
  mixed[13] = (unsigned char)(state[12] ^ mul_2[state[13]] ^ mul_3[state[14]] ^
                              state[15]);
  mixed[14] = (unsigned char)(state[12] ^ state[13] ^ mul_2[state[14]] ^
                              mul_3[state[15]]);
  mixed[15] = (unsigned char)(mul_3[state[12]] ^ state[13] ^ state[14] ^
                              mul_2[state[15]]);

  for (int i = 0; i < 16; i++) {
    state[i] = mixed[i];
  }
}

// Encrypts 16-byte input using the Rijndael algorithm with provided keys.
void encrypt(unsigned char state[16], unsigned char keys[176]) {
  addRoundKey(state, keys);

  for (int i = 0; i < 9; i++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, &keys[16 * (i + 1)]);
  }

  subBytes(state);
  shiftRows(state);
  addRoundKey(state, &keys[160]);
}