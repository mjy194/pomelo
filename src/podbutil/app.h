#pragma once

#include <string>
#include <database.h>

class App {
    enum class cmd {
        unknown,
        build_db,
        patch_db,
        find_record,
        convert,
        generate,
        help,
        info,
        merge,
        performance_test
    };
public:
    int exec(int argc, char* argv[]);
private:
    bool parse(int argc, char* argv[]);
    bool build_db(int argc, char* argv[]);
    bool patch_db(int argc, char* argv[]);
    bool find_record(int argc, char* argv[]);
    bool convert(int argc, char* argv[]);
    bool gen_hash_file(int argc, char* argv[]);
    bool show_info(int argc, char* argv[]);
    bool performance_test(int argc, char* argv[]);
    bool merge(int argc, char* argv[]);
    cmd get_cmd(char cmd);
    void show_usage();
    bool get_hash(pomelo::db_algo_t algo, uint8_t* data, uint32_t datasz, uint8_t* hash, uint8_t& hashsz);

    std::string get_algo_name(pomelo::db_algo_t algo);
private:
    cmd _cmd;
    uint32_t _count;
    pomelo::db_algo_t _algo;
    bool _compress;
    bool _verbose;
    std::string _sourceFilePath;
    std::string _outputFilePath;

};