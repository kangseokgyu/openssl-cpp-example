#include <openssl/sha.h>

#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

enum class hash_type {
  sha1,
  sha224,
  sha256,
  sha384,
  sha512,
};

using hash_func_t = std::function<unsigned char *(const unsigned char *, size_t, unsigned char *)>;

std::map<hash_type, std::pair<size_t, hash_func_t>> sha_map{
    {hash_type::sha1, {SHA_DIGEST_LENGTH, SHA1}},        {hash_type::sha224, {SHA224_DIGEST_LENGTH, SHA224}},
    {hash_type::sha256, {SHA256_DIGEST_LENGTH, SHA256}}, {hash_type::sha384, {SHA384_DIGEST_LENGTH, SHA384}},
    {hash_type::sha512, {SHA512_DIGEST_LENGTH, SHA512}},
};

std::vector<uint8_t> sha(const hash_type &t, const std::vector<uint8_t> &msg) {
  std::vector<uint8_t> md(sha_map[t].first);
  sha_map[t].second(msg.data(), msg.size(), md.data());
  return md;
}

int main() {
  std::string msg = "sample message";
  std::vector<uint8_t> input;
  input.insert(input.end(), msg.begin(), msg.end());

  auto md = sha(hash_type::sha256, input);
  for (auto &v : md) {
    std::cout << std::setfill('0') << std::setw(2) << std::hex << (0xFF & v);
  }
  std::cout << '\n';

  return 0;
}
