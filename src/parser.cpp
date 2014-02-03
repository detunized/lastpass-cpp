#include "parser.h"

#include <array>
#include <arpa/inet.h>

#include <iostream>

namespace lastpass
{

Chunks Parser::extract_chunks(std::istream &stream)
{
    Chunks chunks;

    // Need to do this get/unget fucky voodoo to detect EOF early.
    char c;
    while (stream.get(c))
    {
        stream.unget();

        auto id_chunk = read_chunk(stream);
        chunks[id_chunk.first].push_back(id_chunk.second);
    }

    return chunks;
}

std::pair<ChunkId, Bytes> Parser::read_chunk(std::istream &stream)
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

ChunkId Parser::read_id(std::istream &stream)
{
    std::array<char, sizeof(ChunkId)> buffer;
    if (!stream.read(buffer.data(), buffer.max_size()))
        throw std::runtime_error("Failed to read chunk id");

    return htonl(*reinterpret_cast<ChunkId const *>(buffer.data()));
}

size_t Parser::read_size(std::istream &stream)
{
    std::array<char, 4> buffer;
    if (!stream.read(buffer.data(), buffer.max_size()))
        throw std::runtime_error("Failed to read payload size");

    return htonl(*reinterpret_cast<uint32_t const *>(buffer.data()));
}

Bytes Parser::read_payload(std::istream &stream, size_t size)
{
    Bytes buffer(size);
    if (!stream.read(reinterpret_cast<char *>(buffer.data()), size))
        throw std::runtime_error("Failed to read payload");

    return buffer;
}

}
