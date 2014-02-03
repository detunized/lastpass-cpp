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

std::string pbkdf2_sha256(std::string const &password, std::string const &salt, int iteration_count, size_t size)
{
    std::string key(size, '\0');

#ifdef USE_OPENSSL
    PKCS5_PBKDF2_HMAC(password.data(),
                      password.size(),
                      reinterpret_cast<unsigned char const *>(salt.data()),
                      salt.size(),
                      iteration_count,
                      EVP_sha256(),
                      size,
                      reinterpret_cast<unsigned char *>(&key[0]));
#else
    CCKeyDerivationPBKDF(kCCPBKDF2,
                         password.data(),
                         password.size(),
                         reinterpret_cast<uint8_t const *>(salt.data()),
                         salt.size(),
                         kCCPRFHmacAlgSHA256,
                         iteration_count,
                         reinterpret_cast<uint8_t *>(&key[0]),
                         size);
#endif

    return key;
}

std::string sha256(std::string const &text)
{
#ifdef USE_OPENSSL
    std::string hash(SHA256_DIGEST_LENGTH, '\0');
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, text.c_str(), text.size());
    SHA256_Final(reinterpret_cast<unsigned char *>(&hash[0]), &sha256);
#else
    std::string hash(CC_SHA256_DIGEST_LENGTH, '\0');
    CC_SHA256(text.c_str(), text.size(), reinterpret_cast<unsigned char *>(&hash[0]));
#endif

    return hash;
}

}
