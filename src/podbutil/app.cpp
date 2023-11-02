#include "app.h"
#include "hash/sha512.h"
#include "binhex/binhex.h"
#include "../pomelodb/database.h"
#include "hash/murmur.h"
#include "utils/performance.hpp"
#include <typedef.h>

#include <fstream>
#include <set>

#include <sys/stat.h>
#include <fcntl.h>

#ifdef WIN32
#include <io.h>
#include <getopt/getopt.h>
#include <mman.h>
#else
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#endif

#ifndef APP_NAME
#define APP_NAME "podbutil"
#endif

int App::exec(int argc, char** argv) {
    if (!parse(argc, argv)) {
        show_usage();
        return -1;
    }
    return 0;
}

bool App::parse(int argc, char** argv) {
    if (argc == 1) {
        return false;
    }
    const char* sub_cmd = argv[1];
    _cmd = get_cmd(sub_cmd[0]);
    if (sub_cmd[1] != '\0' || _cmd == cmd::unknown) {
        printf("Unknown command: %s\n", sub_cmd);
        return false;
    }
    if (_cmd == cmd::help) {
        return false;
    }
    static struct option options[] = {
        { "source file", required_argument, nullptr, 's' },
        { "algorithm", required_argument, nullptr, 'a' },
        { "compress", required_argument, nullptr, 'c' },
        { "count", required_argument, nullptr, 'n' },
        { "verbose", required_argument, nullptr, 'v' },
    };

    while (true) {
        int optidx = 0;
		int opt = getopt_long(argc - 1, argv + 1, "s:a:c:n:v:", options, &optidx);
        if (opt == -1) {
            break;
        }
        switch (opt) {
            case 'c':
                _compress = atoi(optarg);
                break;
            case 'n':
                _count = atoi(optarg);
                break;
            case 's':
                if (optarg) {
                    _sourceFilePath = optarg;
                }
                break;
            case 'v':
                _verbose = atoi(optarg);
                break;
            case 'a': {
                uint32_t a = (uint32_t) atoi(optarg);
                if (a < pomelo::db_algo_maximum) {
                    _algo = (pomelo::db_algo_t) a;
                }
                break;
            }
            default:
                return false;
        }
    }

    typedef bool (App::*handle_t)(int argc, char* argv[]);
    struct {
        cmd c;
        handle_t handle;
    } handlers[] = {
        {cmd::build_db,         &App::build_db},
        {cmd::convert,          &App::convert},
        {cmd::find_record,      &App::find_record},
        {cmd::patch_db,         &App::patch_db},
        {cmd::generate,         &App::gen_hash_file},
        {cmd::performance_test, &App::performance_test},
        {cmd::info,             &App::show_info},
        {cmd::merge,            &App::merge},
    };

    bool ret = false;
    for (int i = 0; i < ARRAY_SIZE(handlers); i++) {
        if (_cmd == handlers[i].c) {
            ret = (this->*handlers[i].handle)(argc, argv);
            break;
        }
    }

    if (!ret) {
        printf("\n");
    }
    return ret;
}

bool App::build_db(int argc, char* argv[]) {
    if (argc != 7 && argc != 9) {
        printf("Incorrect parameters counts\n");
        return false;
    }
    std::string outputFilePath = argv[argc - 1];
    if (access(_sourceFilePath.c_str(), 0) == -1) {
        printf("%s not exist\n", _sourceFilePath.c_str());
        return false;
    }
    if (_algo >= pomelo::db_algo_maximum) {
        printf("Unknown algorithm\n");
        return false;
    }
    if (outputFilePath.empty()) {
        printf("No output file\n");
        return false;
    }

    performance::time_sp sp;
    pomelo::database* db = pomelo::database::make(_sourceFilePath, outputFilePath, _algo, _compress);
    if (!db) {
        printf("Build db failed\n");
        return false;
    }
    db->release();
    printf("Build db succeed\n");
    return true;
}

bool App::patch_db(int argc, char* argv[]) {
    if (argc != 5) {
        printf("Incorrect parameters counts\n");
        return false;
    }
    uint32_t count = pomelo::database::make_patch(argv[2], argv[3], argv[4]);
    printf("Make patched db record count: %d\n", count);
    return count;
}

bool App::find_record(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Incorrect parameters counts\n");
        return false;
    }

    std::string hash = argv[2];
    std::string db_path = argv[argc - 1];
    pomelo::database* db = pomelo::database::load(db_path);
    if (!db) {
        printf("Unable to open db file: %s\n", db_path.c_str());
        return false;
    }

    uint8_t bin[sha512_hash_size];
    size_t binsz = hash.size() / 2;
    hex_to_bin(hash.c_str(), hash.size(), bin, binsz);
    bool found = db->match(bin, binsz);
    if (_verbose || !found) {
        printf("Found: %s\n", found ? "true" : "false");
    }
    db->release();
    return true;
}

bool App::convert(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Incorrect parameters counts\n");
        return false;
    }

    std::ifstream file(argv[2]);
    if (!file) {
        printf("Unable to open text hash file: %s\n", argv[2]);
        return false;
    }
    struct stat st;
    if (stat(argv[2], &st) == -1) {
        printf("Unable to get file stat\n");
        return false;
    }
    fmap_t* omap = fmap_alloc_creat_by_path(argv[3], O_RDWR | O_CREAT | O_CLOEXEC, st.st_size / 2,
                                            PROT_READ | PROT_WRITE,
                                            MAP_SHARED);
    if (!omap) {
        printf("Unable to create binary hash file\n");
        return false;
    }
    std::string line;
    unsigned char bin[sha512_block_size];
    uint32_t count = 0;
    uint64_t size = 0;
    while (std::getline(file, line)) {
        size_t binsz = line.size() / 2;
        hex_to_bin(line.c_str(), line.size(), bin, binsz);
        size += fmap_write(omap, bin, binsz);
        count++;
    }
    fmap_truncate(omap, size);
    fmap_release(omap);
    printf("Convert total count: %u\n", count);
    return true;
}

bool App::gen_hash_file(int argc, char* argv[]) {
    if (argc < 7) {
        printf("Incorrect parameters counts\n");
        return false;
    }
    std::string hash_path = argv[argc - 1];
    std::ofstream hash_file(hash_path);
    if (!hash_file) {
        printf("Unable to create hash file: %s\n", hash_path.c_str());
        return false;
    }

    if (_algo >= pomelo::db_algo_maximum) {
        printf("Unknown algorithm\n");
        return false;
    }
    if (_algo == pomelo::db_algo_normal) {
        printf("No special algorithm\n");
        return false;
    }

    srand((uint32_t)time(nullptr));

    uint8_t hash[sha512_hash_size];
    char hex_sha512[sha512_block_size + 1] = {};
    for (uint32_t i = 0; i < _count; i++) {
        uint8_t hashsz = sha512_hash_size;
        uint64_t num = MK_U64(rand() % (0xFFFFFFFE + 1), i);
        get_hash(_algo, (uint8_t*) &num, sizeof(num), hash, hashsz);
        bin_to_hex(hash, hashsz, hex_sha512, hashsz * 2);
        hash_file << hex_sha512 << "\n";
    }
    printf("Generate total count: %d\n", _count);
    return true;
}

bool App::show_info(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Incorrect parameters counts\n");
        return false;
    }
    pomelo::database* db = pomelo::database::load(argv[2]);
    if (!db) {
        printf("Unable to open database\n");
    }

    pomelo::db_header_t* hdr = db->get_header();
    printf("version: %d.%d\n", H16(hdr->version), L16(hdr->version));
    printf("algorithm: %s\n", get_algo_name(db->get_algo()).c_str());
    printf("compressed: %s\n", hdr->compressed ? "true" : "false");
    printf("record count: %u\n", (uint32_t)hdr->record_count);

    db->release();
    return true;
}

bool App::performance_test(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Incorrect parameters counts\n");
        return false;
    }
    std::string hash_path = argv[2];
    std::string db_path = argv[3];

    pomelo::database* db = pomelo::database::load(db_path);
    if (!db) {
        printf("Unable to open database\n");
        return false;
    }
    bool ret = false;
    int count = 0;
    uint32_t matched = 0;
    uint32_t mismatched = 0;
    do {
        pomelo::db_algo_t algo = db->get_algo();
        if (algo == pomelo::db_algo_normal || algo > pomelo::db_algo_maximum) {
            printf("Unsupported algorithm\n");
            break;
        }

        fmap_t* imap = fmap_alloc_by_path(hash_path.c_str(), O_RDONLY | O_CLOEXEC, PROT_READ, MAP_PRIVATE);
        if (!imap) {
            printf("Unable to open binary hash file\n");
            break;
        }

        uint8_t hashsz = pomelo::algo_size[algo];

        performance::time_sp sp;
        for (; count < imap->size / hashsz; count++) {
            const uint8_t* hash = imap->addr + hashsz * count;
            if (!db->match(hash, hashsz)) {
                mismatched++;
                continue;
            }
            matched++;
        }
        fmap_release(imap);
        ret = true;
    } while (0);

    db->release();
    printf("Test total: %d\nmatched: %d\nmismatched: %d\n", count, matched, mismatched);
    return ret;
}

bool App::merge(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Incorrect parameters counts\n");
        return false;
    }

    if (access(argv[2], 0) == -1) {
        printf("%s not exist\n", argv[2]);
        return false;
    }

    if (access(argv[3], 0) == -1) {
        printf("%s not exist\n", argv[3]);
        return false;
    }

    performance::time_sp sp;
    uint32_t count = pomelo::database::apply_patch(argv[2], argv[3]);
    printf("%d new record ware merged\n", count);

    return true;
}

void App::show_usage() {
    printf("Usage: " APP_NAME "<command> [OPTION...] ...\n");
    printf("<Command>\n");
    printf("  b : Build db file from binary hash file.\n");
    printf("  c : Convert from text hash file to binary hash file.\n");
    printf("  f : Find hash in db.\n");
    printf("  g : Generate hash file.\n");
    printf("  i : show database info.\n");
    printf("  m : merge database.\n");
    printf("  p : Create patched db file.\n");
    printf("  t : Performance test.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  " APP_NAME " b -s <hash file> -a <algorithm> <db> [-c compress]\n");
    printf("  " APP_NAME " c <text hash file> <hash file>\n");
    printf("  " APP_NAME " f <hash> <db>\n");
    printf("  " APP_NAME " g -n <count> -a <algorithm> <hash file>\n");
    printf("  " APP_NAME " i <db>\n");
    printf("  " APP_NAME " m <db> <patch>\n");
    printf("  " APP_NAME " p <db1> <db2> <patch>\n");
    printf("  " APP_NAME " t <hash file> <db>\n");
    printf("\n");
    printf("Options:\n");
    printf("  -h: binary hash file\n");
    printf("  -a: normal[0], murmur64[1], md5[2], sha1[3], sha512[4]\n");
    printf("  -c: compress\n");
    printf("  -n: count\n");
    printf("  -v: verbose\n");

}

App::cmd App::get_cmd(char c) {
    struct {
        char c;
        cmd sub;
    } cmds[]{
        {'b', cmd::build_db},
        {'c', cmd::convert},
        {'f', cmd::find_record},
        {'g', cmd::generate},
        {'i', cmd::info},
        {'m', cmd::merge},
        {'p', cmd::patch_db},
        {'t', cmd::performance_test},
        {'h', cmd::help},
    };
    for (int i = 0; i < ARRAY_SIZE(cmds); i++) {
        if (cmds[i].c == c) {
            return cmds[i].sub;
        }
    }
    return cmd::unknown;
}

bool App::get_hash(pomelo::db_algo_t algo, uint8_t* data, uint32_t datasz, uint8_t* hash, uint8_t& hashsz) {
    switch (algo) {
        case pomelo::db_algo_murmur64: {
            uint64_t h = murmur_hash64(data, datasz);
            hashsz = sizeof(uint64_t);
            memcpy(hash, &h, hashsz);
            break;
        }
        case pomelo::db_algo_md5: {
            md5_ctx md5;
            rhash_md5_init(&md5);
            rhash_md5_update(&md5, data, datasz);
            rhash_md5_final(&md5, hash);
            hashsz = md5_hash_size;
            break;
        }
        case pomelo::db_algo_sha1: {
            sha1_ctx sha1;
            rhash_sha1_init(&sha1);
            rhash_sha1_update(&sha1, data, datasz);
            rhash_sha1_final(&sha1, hash);
            hashsz = sha1_hash_size;
            break;
        }
        case pomelo::db_algo_sha512: {
            sha512_ctx sha512;
            rhash_sha512_init(&sha512);
            rhash_sha512_update(&sha512, data, datasz);
            rhash_sha512_final(&sha512, hash);
            hashsz = sha512_hash_size;
            break;
        }
        default:
            return false;
    }
    return true;
}

std::string App::get_algo_name(pomelo::db_algo_t algo) {
    struct {
        pomelo::db_algo_t algo;
        const char* name;
    } algos[] = {
        {pomelo::db_algo_normal,   "normal"},
        {pomelo::db_algo_murmur64, "murmur64"},
        {pomelo::db_algo_md5,      "md5"},
        {pomelo::db_algo_sha1,     "sha1"},
        {pomelo::db_algo_sha512,   "sha512"},
    };
    for (int i =0; i < ARRAY_SIZE(algos); i++) {
        if (algos[i].algo == algo) {
            return algos[i].name;
        }
    }
    return "unknown";
}
