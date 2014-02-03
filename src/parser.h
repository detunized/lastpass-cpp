#pragma once

#include <istream>
#include <map>
#include <string>
#include <vector>

namespace lastpass
{

typedef uint32_t ChunkId;
typedef std::map<ChunkId, std::vector<std::string>> Chunks;

class Parser
{
public:
    static Chunks extract_chunks(std::istream &stream);
    static std::pair<ChunkId, std::string> read_chunk(std::istream &stream);
    static std::string read_item(std::istream &stream);
    static ChunkId read_id(std::istream &stream);
    static size_t read_size(std::istream &stream);
    static std::string read_payload(std::istream &stream, size_t size);
};

}
