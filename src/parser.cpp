#include "parser.h"
#include "crypto.h"
#include "utils.h"

#include <array>
#include <stdexcept>
#include <sstream>

#include <arpa/inet.h>

namespace lastpass
{

Chunks Parser::extract_chunks(std::istream &stream, std::set<ChunkId> const &filter)
{
    Chunks chunks;

    // Need to do this get/unget funky voodoo to detect EOF early.
    char c;
    while (stream.get(c))
    {
        stream.unget();

        auto id_chunk = read_chunk(stream);
        if (filter.empty() || filter.count(id_chunk.first) > 0)
            chunks[id_chunk.first].push_back(id_chunk.second);
    }

    return chunks;
}

std::pair<ChunkId, std::string> Parser::read_chunk(std::istream &stream)
{
    // LastPass blob chunk is made up of 4-byte ID, big endian 4-byte size and payload of that size
    // Example:
    //   0000: 'IDID'
    //   0004: 4
    //   0008: 0xDE 0xAD 0xBE 0xEF
    //   000C: --- Next chunk ---

    auto id = read_id(stream);
    auto payload = read_payload(stream, read_size(stream));
    return std::make_pair(id, payload);
}

std::string Parser::read_item(std::istream &stream)
{
    // An item in an itemized chunk is made up of the big endian size and the payload of that size
    // Example:
    //   0000: 4
    //   0004: 0xDE 0xAD 0xBE 0xEF
    //   0008: --- Next item ---

    auto payload = read_payload(stream, read_size(stream));
    return {std::begin(payload), std::end(payload)};
}

void Parser::skip_item(std::istream &stream)
{
    auto size = read_size(stream);
    if (!stream.seekg(size, std::ios_base::cur))
        throw std::runtime_error("Failed to skip chunk");
}

ChunkId Parser::read_id(std::istream &stream)
{
    std::array<char, sizeof(ChunkId)> buffer;
    if (!stream.read(buffer.data(), buffer.max_size()))
        throw std::runtime_error("Failed to read chunk id");

    static_assert(sizeof(ChunkId) == sizeof(uint32_t), "ChunkId must be of the same size as uint32_t");
    return ChunkId(htonl(*reinterpret_cast<uint32_t const *>(buffer.data())));
}

size_t Parser::read_size(std::istream &stream)
{
    std::array<char, 4> buffer;
    if (!stream.read(buffer.data(), buffer.max_size()))
        throw std::runtime_error("Failed to read payload size");

    return htonl(*reinterpret_cast<uint32_t const *>(buffer.data()));
}

std::string Parser::read_payload(std::istream &stream, size_t size)
{
    std::string buffer(size, '\0');
    if (!stream.read(&buffer[0], size))
        throw std::runtime_error("Failed to read payload");

    return buffer;
}

std::string Parser::decrypt_aes256(std::string const &data, std::string const &encryption_key)
{
    auto size = data.size();
    auto size16 = size % 16;
    auto size64 = size % 64;

    if (size == 0)
        return {};
    else if (size16 == 0)
        return decrypt_aes256_ecb_plain(data, encryption_key);
    else if (size64 == 0 || size64 == 24 || size64 == 44)
        return decrypt_aes256_ecb_base64(data, encryption_key);
    else if (size16 == 1)
        return decrypt_aes256_cbc_plain(data, encryption_key);
    else if (size64 == 6 || size64 == 26 || size64 == 50)
        return decrypt_aes256_cbc_base64(data, encryption_key);

    throw std::runtime_error("Input doesn't seem to be AES-256 encrypted");
}

std::string Parser::decrypt_aes256_ecb_plain(std::string const &data,
                                             std::string const &encryption_key)
{
    return lastpass::decrypt_aes256(data,
                                    encryption_key,
                                    CipherMode::ECB,
                                    {});
}

std::string Parser::decrypt_aes256_ecb_base64(std::string const &data,
                                              std::string const &encryption_key)
{
    return lastpass::decrypt_aes256(decode_base64(data),
                                    encryption_key,
                                    CipherMode::ECB,
                                    {});
}

std::string Parser::decrypt_aes256_cbc_plain(std::string const &data,
                                             std::string const &encryption_key)
{
    return lastpass::decrypt_aes256(data.substr(17),
                                    encryption_key,
                                    CipherMode::CBC,
                                    data.substr(1, 16));
}

std::string Parser::decrypt_aes256_cbc_base64(std::string const &data,
                                              std::string const &encryption_key)
{
    return lastpass::decrypt_aes256(decode_base64(data.substr(26)),
                                    encryption_key,
                                    CipherMode::CBC,
                                    decode_base64(data.substr(1, 24)));
}

Account Parser::parse_account(std::string const &chunk, std::string const &encryption_key)
{
    std::istringstream s(chunk); // TODO: Get rid of the copy!

    auto id = read_item(s);
    auto name = read_item(s);
    auto group = read_item(s);
    auto url = read_item(s);

    for (int i = 0; i < 3; ++i)
        skip_item(s);

    auto username = read_item(s);
    auto password = read_item(s);

    return {std::move(id),
            decrypt_aes256(name, encryption_key),
            decrypt_aes256(username, encryption_key),
            decrypt_aes256(password, encryption_key),
            decode_hex(url),
            decrypt_aes256(group, encryption_key)};

}

}
