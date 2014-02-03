#include "utils.h"
#include "config.h"

#ifdef USE_OPENSSL
#include <openssl/bio.h>
#else
#include <resolv.h>
#endif

namespace lastpass
{

Bytes to_bytes(std::string const &text)
{
    std::vector<uint8_t> bytes(text.size());
    std::copy(text.begin(), text.end(), bytes.begin());
    return bytes;
}

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
