#include <iostream>

#include "aes.h"

// clang++ main.cpp source/aes.cpp source/encrypt.cpp source/decrypt.cpp
// source/lookup.cpp 

// extern unsigned char* aes(const unsigned char*, const unsigned char*, bool);

int main() {
  const unsigned char plaintext[] =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
      "tempor incididunt ut labore et dolore magna aliqua. Condimentum mattis "
      "pellentesque id nibh tortor. Auctor urna nunc id cursus metus aliquam. "
      "In fermentum et sollicitudin ac. Faucibus nisl tincidunt eget nullam.";

  const unsigned char key[16] = {0x9b, 0xe0, 0x91, 0x1b, 0xfc, 0x4b,
                                 0x03, 0x2c, 0xdc, 0xb5, 0xa0, 0xed,
                                 0x4c, 0x0d, 0xbf, 0xf7};

  unsigned char* ciphertext = aes(plaintext, key, true);

  // print the ciphertext array, adding a newline every 16 bytes
  for (int i = 0; i < strlen((const char*)ciphertext); i++) {
    std::cout << std::hex << +ciphertext[i] << " ";
    if ((i + 1) % 16 == 0) std::cout << std::endl;
  }

  std::cout << std::endl;

  std::cout << aes(ciphertext, key, false) << std::endl;

  delete[] ciphertext;

  return 0;
}
