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

void keyExpansionCore(unsigned char* in, unsigned char i) {
  // rotate bytes left
  unsigned char t = in[0];
  in[0] = in[1];
  in[1] = in[2];
  in[2] = in[3];
  in[3] = t;

  // sub bytes from sbox
  in[0] = sbox_f[in[0]];
  in[1] = sbox_f[in[1]];
  in[2] = sbox_f[in[2]];
  in[3] = sbox_f[in[3]];

  // RCon
  in[0] ^= rcon[i];
}

void keyExpansion(const unsigned char* key, unsigned char* expandedKeys) {
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

void encryptCore(unsigned char* state, unsigned char* keys) {
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

unsigned char* encrypt(const unsigned char* plaintext,
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
    encryptCore(&ciphertext[i], expandedKeys);
  }

  return ciphertext;
}

int main() {
  const unsigned char plaintext[] =
      "This is a message we will encrypt with AES!";

  const unsigned char key[16] = {0x9b, 0xe0, 0x91, 0x1b, 0xfc, 0x4b,
                                 0x03, 0x2c, 0xdc, 0xb5, 0xa0, 0xed,
                                 0x4c, 0x0d, 0xbf, 0xf7};

  unsigned char* ciphertext = encrypt(plaintext, key);

  // print the ciphertext array, adding a newline every 16 bytes
  for (int i = 0; i < strlen((const char*)ciphertext); i++) {
    std::cout << std::hex << +ciphertext[i] << " ";
    if ((i + 1) % 16 == 0) std::cout << std::endl;
  }

  delete[] ciphertext;

  return 0;
}
