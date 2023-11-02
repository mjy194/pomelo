#pragma once

#include <typedef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string>
#include "fs/fmap.h"

#include <hash/md5.h>
#include <hash/sha1.h>
#include <hash/sha512.h>

#ifdef WIN32
#   ifndef PODB_EXPORTS
#       define PODB_API __declspec(dllimport)
#   else
#       define PODB_API __declspec(dllexport)
#   endif
#else
#   ifndef PODB_EXPORTS
#       define PODB_API
#   else
#       define PODB_API __attribute__((visibility("default")))
#   endif
#endif

namespace pomelo {

#define DB_MAGIC 0x62646f6c656d6f70
#define DB_VER MK_U32(1, 0)
#define COMP_HASHSZ sizeof(uint64_t)
#define HASH2SIGN(h) (uint16_t)MK_U16((h)[1], (h)[0])

#define TAB_SIZE 0x10000
#define TAB_COUNT_TYPE uint16_t // This type is determined by TAB_SIZE
#define RECORD_RESERVE_SIZE (sizeof(TAB_COUNT_TYPE) / sizeof(uint8_t))
#define RECORD_OFFSET(r) ((uint8_t*)r + RECORD_RESERVE_SIZE)
#define RECORD_SIZE(s) ((s) - RECORD_RESERVE_SIZE)

    typedef enum db_algo {
        db_algo_normal,
        db_algo_murmur64,
        db_algo_md5,
        db_algo_sha1,
        db_algo_sha512,
        db_algo_maximum
    } db_algo_t;

    typedef enum db_type {
        db_type_normal,
        db_type_patch,
    } db_type_t;

    typedef enum patch_method {
        db_patch_method_create,
        db_patch_method_remove,
    } patch_method_t;

    static uint32_t algo_size[db_algo_maximum] = {
            0,
            sizeof(uint64_t),
            md5_hash_size,
            sha1_hash_size,
            sha512_hash_size
    };

    typedef PACK(struct primary_table {
        uint32_t offset;
        TAB_COUNT_TYPE count;
    }) primary_table_t;

    typedef PACK(struct db_header {
        uint64_t magic;
        uint32_t version;
        uint64_t algo : 4;
        uint64_t dbtype : 1;
        uint64_t compressed : 1;
        uint64_t record_count : 32;
        uint64_t hashsz : 8;
        uint64_t reserved : 18;
    }) db_header_t;

    typedef PACK(struct hash_db {
        db_header_t hdr;
        primary_table_t idx_tbl[TAB_SIZE];
        uint8_t record[1];
    }) hashdb_t;

    typedef PACK(struct normal_db {
        db_header_t hdr;
        uint8_t record[1];
    }) normal_db_t;

    typedef PACK(struct pat_record {
        patch_method method;
        uint8_t hash[1];
    }) pat_record_t;

    typedef PACK(struct hash_patch_db {
        db_header_t hdr;
        pat_record record[1];
    }) hash_patch_db_t;

    class PODB_API database {
    public:
        static database* make(const std::string& filepath, const std::string& output_filepath, db_algo_t algo, bool compress, db_type_t type = db_type_normal);
        static uint64_t make_normal_db(const uint8_t* src, uint64_t size, fmap_t* omap, bool compress);
        static uint64_t make_hash_db(const uint8_t* src, uint64_t size, uint8_t hashsz, hashdb_t* hashdb, fmap_t* omap, bool compress);

        static database* load(const std::string& filepath);

        static uint32_t make_patch(const std::string& db1, const std::string& db2, const std::string& pat_filepath);
        static uint32_t apply_patch(const std::string& db1, const std::string& db2);

        database();
        ~database();

        void release();

        void attach_fmap(fmap_t* map);
        bool match(const uint8_t* hash, size_t hashsz) const;
        bool match(const std::string& filepath) const;

        db_header_t* get_header() const;
        db_algo_t get_algo() const;
        db_type_t get_type() const;
        bool compressed() const;

        uint64_t size();
        bool resize(uint64_t size);

        uint8_t* first_record();
        uint8_t* next_record(uint8_t* hash);
        bool get_sign(uint8_t* hash, size_t hashsz, uint16_t& sign) const;
    private:
        void init_header();

        uint8_t* find(const uint8_t* hash, size_t hashsz) const;
        static bool get_file_hash(const std::string& filepath, db_algo_t algo, uint8_t* hash, uint8_t& hashsz);
    private:
        fmap_t* _map;
    };
}

