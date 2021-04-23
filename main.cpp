#pragma once
#include "Pathfinder.h"
#include <boost/program_options.hpp>
namespace po = boost::program_options;
ScanVars CommandLineParser(int argc, char** argv) {
    std::vector<std::string> dirs;
    int levelScan = 0;
    int minSize = 1;
    std::string masks = "";
    int blockSize = 1;
    std::string hashFunc = "crc32";
    po::options_description desc("Allowed options");

    desc.add_options()
        ("help,h", "produce help message")
        ("dir_scan,scan", po::value<std::vector<std::string>>(), "folders for scaner")
        ("level_scan,level", po::value<int>(), "level to scan: 1 - full deep, 0 - only in root this folder")
        ("min_size,minsize", po::value<int>(), "minimum file's size bytes: default is more then 1 byte")
        ("masks,masks", po::value<std::string>(), "masks's files for finder with any masks and registers")
        ("S,S", po::value<int>(), "block's size is a part of real size of file to compare")
        ("H,hash", po::value<std::string>(), "hash algorithm: crc32 or md5")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
    if (vm.count("help")) {
        std::cout << desc << "\n";
        //return 1;
    }

    if (vm.count("dir_scan")) {
        std::cout << "folders scan\n";
        dirs = vm["dir_scan"].as<std::vector<std::string>>();
        for (auto& d : dirs)
        {
            std::cout << d << std::endl;
        }
    }

    if (vm.count("level_scan")) {
        std::cout << "level scan=";
        levelScan = vm["level_scan"].as<int>();
        std::cout << levelScan << std::endl;
    }

    if (vm.count("min_size")) {
        std::cout << "min_size=";
        minSize = vm["min_size"].as<int>();
        std::cout << minSize << std::endl;
    }

    if (vm.count("masks")) {
        std::cout << "masks=";
        masks = vm["masks"].as<std::string>();
        std::cout << masks << std::endl;
    }

    if (vm.count("S")) {
        std::cout << "block_size=";
        blockSize = vm["S"].as<int>();
        std::cout << blockSize << std::endl;
    }

    if (vm.count("H")) {
        std::cout << "hash_func=";
        hashFunc = vm["H"].as<std::string>();
        std::cout << hashFunc << std::endl;
    }

    std::tuple<std::vector<std::string>, int, int, std::string, int, std::string> result = { dirs,levelScan,minSize,masks,blockSize,hashFunc };
    return result;
};


int main(int argc, char* argv[])
{
    ScanVars inputVars;
    try {
        auto scanner = new Pathfinder();
        inputVars = CommandLineParser(argc, argv); 
        if (std::get<0>(inputVars).size() > 0) {
            scanner->loadVars(inputVars);
            scanner->showResultSearch();
        }
        else
            std::cout << "No scan folders: to set --dir_scan x:/yyyyy/ \n";
    }
    catch (po::error& e) { std::cout << e.what() << std::endl; }

    return 0;
}


