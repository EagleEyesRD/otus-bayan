#pragma once
#include <iostream>
#include <vector>
#include <filesystem>
#include <string>
#include <tuple>
#include <map>
#include <fstream>
#include <boost/uuid/detail/md5.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/crc.hpp>
//
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
namespace md5 = boost::uuids::detail;
namespace fs = std::filesystem;
std::map<std::string, std::string> listFiles;
using ScanVars = std::tuple<std::vector<std::string>, int, int, std::string, int, std::string>;

class Pathfinder
{
    struct FileDescriptor {
        int id;
        std::string path;
        std::string hashcode;
    };
    boost::multi_index::multi_index_container<
        FileDescriptor,
        boost::multi_index::indexed_by<
        boost::multi_index::hashed_unique<
        boost::multi_index::member<
        FileDescriptor, int, &FileDescriptor::id
        >
        >,
        boost::multi_index::hashed_non_unique<
        boost::multi_index::member<
        FileDescriptor, std::string, &FileDescriptor::path
        >
        >,
        boost::multi_index::hashed_non_unique<
        boost::multi_index::member<
        FileDescriptor, std::string, &FileDescriptor::hashcode
        >
        >
        >
    > fdescstore;
public:
    Pathfinder();
    void loadVars(ScanVars sv);
    void showResultSearch();
private:
    std::string toString(const md5::md5::digest_type& digest);
    std::uintmax_t ComputeFileSize(const fs::path& pathToCheck);
    std::string getHash(std::string path, std::string hashname, int blockSize);
    void DisplayFileInfo(const std::filesystem::directory_entry& entry, std::string& lead, std::string& filename, int blockSize, std::string hashf);
    void DisplayDirectoryTreeImp(const fs::path& pathToShow, int level, int minSize, std::string masks, int blockSize, std::string hashf);
};
/////////////////////////////////////////////////////////////////////
Pathfinder::Pathfinder() {};

void Pathfinder::showResultSearch() {
    std::string oldhashcode = "";
    for (auto j : fdescstore) {
        if (oldhashcode.length() > 0) {
            if (oldhashcode != j.hashcode)
                std::cout << std::endl;

            std::cout << j.id << " + " << j.path << " + " << j.hashcode << std::endl;
        }
        oldhashcode = j.hashcode;
    }
};

std::string Pathfinder::toString(const md5::md5::digest_type& digest)
{
    const auto charDigest = reinterpret_cast<const char*>(&digest);
    std::string result;
    boost::algorithm::hex(charDigest, charDigest + sizeof(md5::md5::digest_type), std::back_inserter(result));
    return result;
};

std::uintmax_t Pathfinder::ComputeFileSize(const fs::path& pathToCheck)
{
    if (fs::exists(pathToCheck) && fs::is_regular_file(pathToCheck))
    {
        auto err = std::error_code{};
        auto filesize = fs::file_size(pathToCheck, err);
        if (filesize != static_cast<uintmax_t>(-1))
            return filesize;
    }
    return static_cast<uintmax_t>(-1);
};

std::string Pathfinder::getHash(std::string path, std::string hashname, int blockSize) {
    std::ifstream xfile(path, std::ios::in | std::ios::binary);
    xfile.seekg(0, std::ios::beg);
    std::vector<char> buff;
    buff.resize(blockSize);
    xfile.read(buff.data(), blockSize);
    std::string str = std::string(buff.data());
    std::string res;

    if ((int)hashname.find("crc32") >= 0) {
        boost::crc_32_type crc32;
        crc32.process_bytes(str.data(), str.length());
        res = std::to_string(crc32.checksum());
        std::cout << "crc32-hash part of(" << path << ")=" << res << std::endl;
    }
    else {
        md5::md5 hash;
        md5::md5::digest_type digest;
        hash.process_bytes(str.data(), str.length());
        hash.get_digest(digest);
        res = toString(digest);
        std::cout << "md5-hash part of(" << path << ")=" << res << std::endl;
    }
    return res;
}

void Pathfinder::DisplayFileInfo(const std::filesystem::directory_entry& entry, std::string& lead, std::string& filename, int blockSize, std::string hashf)
{
    int cntId = fdescstore.size();
    fdescstore.insert({ cntId,filename,getHash(entry.path().parent_path().string() + "/" + filename, hashf, blockSize) });
};

void Pathfinder::DisplayDirectoryTreeImp(const fs::path& pathToShow, int level, int minSize, std::string masks, int blockSize, std::string hashf)
{
    std::cout << "level=" << level
        << ", minSize=" << minSize
        << ", masks=" << masks
        << ", blockSize=" << blockSize
        << ", hashfunc=" << hashf << std::endl;
    if (fs::exists(pathToShow) && fs::is_directory(pathToShow))
    {
        auto lead = std::string(level * 3, ' ');
        for (const auto& entry : fs::directory_iterator(pathToShow))
        {
            auto filename = entry.path().filename();
            if (fs::is_directory(entry.status()))
            {
                std::cout << lead << "[+] " << filename << "\n";
                DisplayDirectoryTreeImp(entry, level + 1, minSize, masks, blockSize, hashf);
                std::cout << "\n";
            }
            else if (fs::is_regular_file(entry.status())) {
                std::string name = filename.string();
                int inxfind = static_cast<int>(name.find(masks));
                if (inxfind >= 0) {
                    //int fsize = ;
                    if (minSize < ComputeFileSize(entry))
                        DisplayFileInfo(entry, lead, name, blockSize, hashf);
                }
            }
            else
                std::cout << lead << " [?]" << filename << "\n";
        }
    }
};

void Pathfinder::loadVars(ScanVars sv) {
    auto dirs = std::get<0>(sv);
    for (auto& d : dirs) {
        auto pathToShow = fs::path{ d };
        DisplayDirectoryTreeImp(pathToShow, std::get<1>(sv), std::get<2>(sv), std::get<3>(sv), std::get<4>(sv), std::get<5>(sv));
    }
};
