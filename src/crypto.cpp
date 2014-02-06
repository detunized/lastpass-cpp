#include "crypto.h"
#include "config.h"
#include "utils.h"

#include <stdexcept>

// TODO: Make a crypto interface and remove ifdefs!
#ifdef USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/sha.h>
#else
#include <CommonCrypto/CommonCryptor.h>
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

std::string decrypt_aes256(std::string const &data,
                           std::string const &encryption_key,
                           CipherMode mode,
                           std::string const &iv)
{
    if (data.empty())
        return {};

    std::string decrypted(data.size(), '\0');

#ifdef USE_OPENSSL
    EVP_CIPHER const *cipher = nullptr;
    switch (mode)
    {
    case CipherMode::CBC:
        cipher = EVP_aes_256_cbc();
        break;
    case CipherMode::ECB:
        cipher = EVP_aes_256_ecb();
        break;
    default:
        throw std::runtime_error("Invalid cipher mode");
    }

    EVP_CIPHER_CTX context;

    EVP_CIPHER_CTX_init(&context);
    AtExit relese_context([&](){
        EVP_CIPHER_CTX_cleanup(&context);
    });

    EVP_DecryptInit(&context,
                    cipher,
                    reinterpret_cast<unsigned char const *>(encryption_key.data()),
                    reinterpret_cast<unsigned char const *>(iv.data()));

    int decrypted_size = 0;
    auto status = EVP_DecryptUpdate(&context,
                                    reinterpret_cast<unsigned char *>(&decrypted[0]),
                                    &decrypted_size,
                                    reinterpret_cast<unsigned char const *>(data.data()),
                                    data.size());
    if (!status)
        throw std::runtime_error("Decryption failed: (EVP_DecryptUpdate failed)");

    int final_size = 0;
    status = EVP_DecryptFinal(&context,
                              reinterpret_cast<unsigned char *>(&decrypted[decrypted_size]),
                              &final_size);

    if (!status)
        throw std::runtime_error("Decryption failed: (EVP_DecryptFinal failed)");

    decrypted.resize(decrypted_size + final_size);
#else
    CCOptions mode_option = 0;
    switch (mode)
    {
    case CipherMode::CBC:
        mode_option = 0;
        break;
    case CipherMode::ECB:
        mode_option = kCCOptionECBMode;
        break;
    default:
        throw std::runtime_error("Invalid cipher mode");
    }

    size_t decrypted_size = 0;
    auto status = CCCrypt(kCCDecrypt,
                          kCCAlgorithmAES128,
                          kCCOptionPKCS7Padding | mode_option,
                          encryption_key.data(),
                          kCCKeySizeAES256,
                          iv.data(),
                          data.data(),
                          data.size(),
                          &decrypted[0],
                          decrypted.size(),
                          &decrypted_size);

    if (status != kCCSuccess)
        throw std::runtime_error("Decryption failed: (CCCrypt failed)");

    decrypted.resize(decrypted_size);
#endif

    return decrypted;
}


}
