#include <iostream>

#include "aes.h"

// extern unsigned char* aes(const unsigned char*, const unsigned char*, bool);

int main() {
  const unsigned char plaintext[] =
      "This is a message we will encrypt with AES!";

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

  ciphertext = aes(ciphertext, key, false);
  for (int i = 0; i < strlen((const char*)ciphertext); i++) {
    std::cout << ciphertext[i];
  }

  std::cout << std::endl;

  delete[] ciphertext;

  return 0;
}
