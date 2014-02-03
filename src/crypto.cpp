#include "crypto.h"
#include "config.h"

// TODO: Make a crypto interface and remove ifdefs!
#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/sha.h>
#else
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#endif

namespace lastpass
{

Bytes pbkdf2_sha256(Bytes const &password, Bytes const &salt, int iteration_count, size_t size)
{
    static_assert(sizeof(uint8_t) == sizeof(char), "uint8_t should be the same size as char");

    std::vector<uint8_t> key(size);

#ifdef USE_OPENSSL
    PKCS5_PBKDF2_HMAC(reinterpret_cast<char const *>(password.data()),
                      password.size(),
                      salt.data(),
                      salt.size(),
                      iteration_count,
                      EVP_sha256(),
                      size,
                      &key[0]);
#else
    CCKeyDerivationPBKDF(kCCPBKDF2,
                         reinterpret_cast<char const *>(password.data()),
                         password.size(),
                         salt.data(),
                         salt.size(),
                         kCCPRFHmacAlgSHA256,
                         iteration_count,
                         &key[0],
                         size);
#endif

    return key;
}

Bytes sha256(std::string const &text)
{
#ifdef USE_OPENSSL
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, text.c_str(), text.size());
    SHA256_Final(&hash[0], &sha256);
#else
    std::vector<uint8_t> hash(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(text.c_str(), text.size(), &hash[0]);
#endif

    return hash;
}

}
