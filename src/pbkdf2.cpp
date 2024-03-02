#include <openssl/evp.h>

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

int main() {
  std::string passphrase = "passphrase";
  std::vector<uint8_t> salt{'s', 'a', 'l', 't'};

  std::vector<uint8_t> key(32);

  PKCS5_PBKDF2_HMAC(passphrase.c_str(), passphrase.size(), salt.data(), salt.size(), PKCS5_DEFAULT_ITER, EVP_sha256(),
                    key.size(), key.data());
  for (auto &v : key) {
    std::cout << std::setfill('0') << std::setw(2) << std::hex << (0xFF & v);
  }
  std::cout << '\n';

  return 0;
}
