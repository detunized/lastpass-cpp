#include "utils.h"
#include "config.h"

#include <cctype>
#include <stdexcept>

#ifdef USE_OPENSSL
#include <openssl/bio.h>
#include <openssl/evp.h>
#else
#include <resolv.h>
#endif

namespace lastpass
{

std::string to_hex(std::string const &bytes)
{
    static char const hex_chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::string hex;
    hex.reserve(bytes.size() * 2);

    for (unsigned char i: bytes)
    {
        hex += hex_chars[i / 16];
        hex += hex_chars[i % 16];
    }

    return hex;
}

std::string decode_hex(std::string const &hex_text)
{
    size_t size = hex_text.size();
    if (size % 2 != 0)
        throw std::runtime_error("Input length must be multple of 2");

    std::string decoded(size / 2, '\0');
    for (size_t i = 0; i < size / 2; ++i)
    {
        int b = 0;
        for (int j = 0; j < 2; ++j)
        {
            b <<= 4;
            char c = std::tolower(hex_text[i * 2 + j]);
            if (c >= '0' && c <= '9')
                b |= c - '0';
            else if (c >= 'a' && c <= 'f')
                b |= c - 'a' + 10;
            else
                throw std::runtime_error("Input contains invalid characters");
        }

        decoded[i] = static_cast<char>(b);
    }

    return decoded;
}

std::string decode_base64(std::string const &base64_text)
{
    // The size is the upper bound, the actual size could be smaller.
    // After decoding we need to trim unused space.
    std::string decoded(base64_text.size() * 3 / 4, '\0');

#ifdef USE_OPENSSL
    BIO *context = BIO_push(BIO_new(BIO_f_base64()),
                            BIO_new_mem_buf((void *)base64_text.c_str(), base64_text.size()));
    BIO_set_flags(context, BIO_FLAGS_BASE64_NO_NL | BIO_FLAGS_MEM_RDONLY);
    size_t actual_size = BIO_read(context, &decoded[0], decoded.size());
    BIO_free_all(context);
#else
    size_t actual_size = b64_pton(base64_text.c_str(),
                                  reinterpret_cast<u_char *>(&decoded[0]),
                                  decoded.size());
#endif

    decoded.resize(actual_size);
    return decoded;
}

}
