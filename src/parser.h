#pragma once

#include "account.h"

#include <istream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace lastpass
{

constexpr uint32_t chunk_id(char c1, char c2, char c3, char c4)
{
    return (static_cast<uint32_t>(c1) << 24) |
           (static_cast<uint32_t>(c2) << 16) |
           (static_cast<uint32_t>(c3) << 8) |
           static_cast<uint32_t>(c4);
}

// Known chunk IDs
enum class ChunkId: uint32_t
{
    ACCT = chunk_id('A', 'C', 'C', 'T'),
    ANTE = chunk_id('A', 'N', 'T', 'E'),
    ATVR = chunk_id('A', 'T', 'V', 'R'),
    BBTE = chunk_id('B', 'B', 'T', 'E'),
    CBCU = chunk_id('C', 'B', 'C', 'U'),
    DOTE = chunk_id('D', 'O', 'T', 'E'),
    ENCU = chunk_id('E', 'N', 'C', 'U'),
    ENDM = chunk_id('E', 'N', 'D', 'M'),
    EQDN = chunk_id('E', 'Q', 'D', 'N'),
    FETE = chunk_id('F', 'E', 'T', 'E'),
    FUTE = chunk_id('F', 'U', 'T', 'E'),
    IPTE = chunk_id('I', 'P', 'T', 'E'),
    LPAV = chunk_id('L', 'P', 'A', 'V'),
    NMAC = chunk_id('N', 'M', 'A', 'C'),
    SPMT = chunk_id('S', 'P', 'M', 'T'),
    SYTE = chunk_id('S', 'Y', 'T', 'E'),
    TATE = chunk_id('T', 'A', 'T', 'E'),
    URUL = chunk_id('U', 'R', 'U', 'L'),
    WMTE = chunk_id('W', 'M', 'T', 'E'),
    WOTE = chunk_id('W', 'O', 'T', 'E'),
    WPTE = chunk_id('W', 'P', 'T', 'E'),
};

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
