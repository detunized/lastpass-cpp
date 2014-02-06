#pragma once

#include "account.h"

#include <istream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace lastpass
{

typedef uint32_t ChunkId;
typedef std::map<ChunkId, std::vector<std::string>> Chunks;

class Parser
{
public:
    typedef std::set<ChunkId> Filter;

    static Chunks extract_chunks(std::istream &stream, Filter const &filter = Filter());
    static std::pair<ChunkId, std::string> read_chunk(std::istream &stream);
    static std::string read_item(std::istream &stream);
    static void skip_item(std::istream &stream);
    static ChunkId read_id(std::istream &stream);
    static size_t read_size(std::istream &stream);
    static std::string read_payload(std::istream &stream, size_t size);

    // AES256
    static std::string decrypt_aes256(std::string const &data, std::string const &encryption_key);
    static std::string decrypt_aes256_ecb_plain(std::string const &data, std::string const &encryption_key);
    static std::string decrypt_aes256_ecb_base64(std::string const &data, std::string const &encryption_key);
    static std::string decrypt_aes256_cbc_plain(std::string const &data, std::string const &encryption_key);
    static std::string decrypt_aes256_cbc_base64(std::string const &data, std::string const &encryption_key);

    // Chunk parsers
    static Account parse_account(std::string const &chunk, std::string const &encryption_key);
};

}
