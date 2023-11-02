#include <stdlib.h>
#include "database.h"
#include "hash/murmur.h"
#include "binhex/binhex.h"

#include <set>
#include <vector>
#include <map>
#include <string>


#include <errno.h>
#include <string.h>
#include <assert.h>

#include <zlib/zlib.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef WIN32
#include <mman.h>
#else

#include <sys/mman.h>

#endif

namespace pomelo {
    uint64_t compress_hash(const uint8_t* hash, uint8_t size) {
        if (size == sizeof(uint64_t)) {
            return *(uint64_t*) hash;
        }
        return murmur_hash64(hash, size);
    }

    void fix_offset(hashdb_t* hashdb, uint16_t idx) {
        uint32_t offset = hashdb->idx_tbl[idx].offset;
        for (int i = idx; i < ARRAY_SIZE(hashdb->idx_tbl); i++) {
            uint32_t val = hashdb->idx_tbl[i].count;
            hashdb->idx_tbl[i].offset = offset;
            offset += val;
        }
    }

    database* database::make(const std::string& filepath, const std::string& output_filepath, db_algo_t algo,
                             bool comp, db_type_t type) {
        if (algo >= db_algo_maximum) {
            return nullptr;
        }
        fmap_t* imap = fmap_alloc_by_path(filepath.c_str(), O_RDONLY | O_CLOEXEC, PROT_READ, MAP_PRIVATE);
        if (!imap) {
            return nullptr;
        }
        fmap_t* omap = fmap_alloc_creat_by_path(output_filepath.c_str(), O_RDWR | O_CREAT | O_CLOEXEC,
                                                fmap_size(imap) + offsetof(hashdb_t, record),
                                                PROT_READ | PROT_WRITE,
                                                MAP_SHARED);
        if (!omap) {
            fmap_release(imap);
            return nullptr;
        }
        database* db = new database;
        db->attach_fmap(omap);
        db->init_header();
        db_header_t* hdr = db->get_header();
        hdr->algo = algo;
        hdr->compressed = comp;
        hdr->dbtype = type;

        uint64_t writesz = 0;
        if (algo <= db_algo_normal) {
            writesz = fmap_write(omap, (uint8_t*) hdr, sizeof(*hdr));
            if (writesz) {
                uint64_t datasz = make_normal_db(imap->addr, imap->size, omap, comp);
                if (!datasz) {
                    writesz = 0;
                }
                writesz += datasz;
            }
        } else {
            hashdb_t* hashdb = (hashdb_t*)hdr;
            hashdb->hdr.hashsz = algo_size[algo];
            writesz = fmap_write(omap, (uint8_t*) hashdb, offsetof(hashdb_t, record));
            if (writesz) {
                uint64_t datasz = make_hash_db(imap->addr, imap->size, algo_size[algo], hashdb, omap, comp);
                if (!datasz) {
                    writesz = 0;
                }
                writesz += datasz;
            }
        }
        fmap_release(imap);
        fmap_release(omap);

        if (!writesz) {
            db->release();
            unlink(output_filepath.c_str());
            return nullptr;
        }
        fmap_truncate(omap, writesz);
        return db;
    }

    uint64_t database::make_normal_db(const uint8_t* src, uint64_t size, fmap_t* omap, bool comp) {
        if (comp) {
            uLongf destsz = compressBound((uLongf)size);
            if (compress((Bytef*) omap->addr, &destsz, (Bytef*) src, (uLongf)size) == Z_OK) {
                return destsz;
            }
            return 0;
        }
        return fmap_write(omap, src, size);
    }

    uint64_t database::make_hash_db(const uint8_t* src, uint64_t size, uint8_t hashsz, hashdb_t* hashdb, fmap_t* omap, bool comp) {
        uint64_t writesz = 0;
        uint8_t real_hashsz = hashsz;
        if (comp) {
            real_hashsz = COMP_HASHSZ;
        }
        memset(&hashdb->idx_tbl, 0, sizeof(hashdb->idx_tbl));

        std::set<std::string> hashes;
        for (int i = 0; i < size / hashsz; i++) {
            const uint8_t* hash = src + hashsz * i;
            uint64_t ch;
            if (comp) {
                ch = compress_hash(hash, hashsz);
                hash = (uint8_t*) &ch;
            }
            if (hashes.emplace((char*)hash, real_hashsz).second) {
                hashdb->idx_tbl[HASH2SIGN(hash)].count++;
            }
        }

        fix_offset(hashdb,  0);
        hashdb->hdr.record_count = hashes.size();

        for (auto&& item: hashes) {
            writesz += fmap_write(omap, (uint8_t*)RECORD_OFFSET(item.data()), RECORD_SIZE(item.size()));
        }
        return writesz;
    }

    database* database::load(const std::string& filepath) {
        fmap_t* imap = fmap_alloc_by_path(filepath.c_str(), O_RDWR | O_CLOEXEC, PROT_READ | PROT_WRITE, MAP_SHARED);
        if (!imap) {
            return nullptr;
        }
        database* db = nullptr;
        db_header_t* header = (db_header_t*) imap->addr;
        if (header->magic == DB_MAGIC) {
            if (header->algo < db_algo_maximum) {
                db = new database;
                db->attach_fmap(imap);
            }
        }
        fmap_release(imap);
        return db;
    }

    db_algo_t database::get_algo() const {
        db_header_t* hdr = get_header();
        if (hdr) {
            return (db_algo_t)hdr->algo;
        }
        return db_algo_maximum;
    }

    db_type_t database::get_type() const {
        db_header_t* hdr = get_header();
        if (hdr) {
            return (db_type_t)hdr->dbtype;
        }
        return db_type_normal;
    }

    bool database::compressed() const {
        if (_map && _map->addr) {
            return ((db_header_t*) _map->addr)->compressed;
        }
        return false;
    }

    database::database() : _map() {}

    database::~database() {
        if (_map) {
            fmap_release(_map);
        }
    }

    bool database::match(const uint8_t* hash, size_t hashsz) const {
        const uint8_t* real_hash = hash;
        uint64_t ch;
        if (compressed()) {
            ch = murmur_hash64(hash, (int)hashsz);
            real_hash = (uint8_t*)&ch;
            hashsz = COMP_HASHSZ;
        }
        return find(real_hash, hashsz);
    }

    bool database::match(const std::string& filepath) const {
        uint8_t hash[sha512_hash_size] = {};
        uint8_t hashsz = 0;
        if (!get_file_hash(filepath, get_algo(), hash, hashsz)) {
            return false;
        }
        return match(hash, hashsz);
    }

    void database::init_header() {
        db_header_t* hdr = get_header();
        if (hdr) {
            hdr->magic = DB_MAGIC;
            hdr->version = DB_VER;
        }
    }

    db_header_t* database::get_header() const {
        if (_map && _map->addr) {
            return (db_header_t*)_map->addr;
        }
        return nullptr;
    }

    uint8_t* database::find(const uint8_t* hash, size_t hashsz) const {
        uint16_t sign = HASH2SIGN(hash);
        hashdb_t* hashdb = (hashdb_t*)get_header();
        if (!hashdb) {
            return nullptr;
        }
        hashsz = RECORD_SIZE(hashsz);
        hash = RECORD_OFFSET(hash);
        uint8_t* record = nullptr;
        if (hashdb->idx_tbl[sign].count > 0) {
            uint8_t* r = hashdb->record + hashdb->idx_tbl[sign].offset * hashsz;
            for (uint32_t i = 0; i < hashdb->idx_tbl[sign].count; i++, r += hashsz) {
                if (memcmp(hash, r, hashsz) == 0) {
                    record = r;
                    break;
                }
            }
        }
        return record;
    }

    void database::release() {
        delete this;
    }

    void database::attach_fmap(fmap_t* map) {
        assert(map);
        _map = fmap_incref(map);
    }

    int comp_hash(const uint8_t* r1, uint16_t sign1, const uint8_t* r2, uint16_t sign2, uint8_t sz) {
        if (sign1 < sign2) {
            return -1;
        } else if (sign1 > sign2) {
            return 1;
        }
        return memcmp(r1, r2, sz);
    }

    uint32_t database::make_patch(const std::string& db1_filepath, const std::string& db2_filepath,
                              const std::string& pat_filepath) {
        uint32_t count = 0;
        database* db1 = load(db1_filepath);
        if (!db1) {
            return count;
        }
        database* db2 = load(db2_filepath);
        if (!db2) {
            db1->release();
            return count;
        }

        fmap_t* omap = fmap_alloc_creat_by_path(pat_filepath.c_str(), O_RDWR | O_CREAT | O_CLOEXEC,
                                                1,
                                                PROT_READ | PROT_WRITE,
                                                MAP_SHARED);
        do {
            if (!omap) {
                break;
            }
            db_algo_t algo = db1->get_algo();
            if (algo != db2->get_algo() || algo >= db_algo_maximum) {
                break;
            }
            bool compressed = db1->compressed();
            if (compressed != db2->compressed()) {
                break;
            }
            uint8_t hashsz = algo_size[algo];
            if (compressed) {
                hashsz = algo_size[db_algo_murmur64];
            }
            hashsz = RECORD_SIZE(hashsz);

            uint8_t* r1 = db1->first_record();
            uint8_t* r2 = db2->first_record();

            normal_db_t normaldb = {};
            normaldb.hdr.magic = DB_MAGIC;
            normaldb.hdr.version = DB_VER;
            normaldb.hdr.algo = db_algo_normal;
            normaldb.hdr.dbtype = db_type_patch;
            normaldb.hdr.hashsz = algo_size[db1->get_algo()];
            normaldb.hdr.compressed = db1->compressed();

            uint64_t writesz = fmap_write(omap, (const uint8_t*)&normaldb, offsetof(normal_db_t, record));

            while(r1 || r2) {
                uint16_t sign1;
                if (!db1->get_sign(r1, hashsz, sign1)) {
                    assert(0 && "unable to get sign");
                    break;
                }
                uint16_t sign2;
                if (!db2->get_sign(r2, hashsz, sign2)) {
                    assert(0 && "unable to get sign");
                    break;
                }

                if (!r2 || (r1 && comp_hash(r1, sign1, r2, sign2, hashsz) < 0)) {                    
                    patch_method method = db_patch_method_remove;
                    writesz += fmap_write(omap, (uint8_t*)&method, sizeof(method));
                    uint16_t sign = b16swp(sign1);
                    writesz += fmap_write(omap, (uint8_t*)&sign, sizeof(sign));
                    writesz += fmap_write(omap, r1, hashsz);
                    r1 = db1->next_record(r1);
                    count++;
                } else if (!r1 || (r2 && comp_hash(r1, sign1, r2, sign2, hashsz) > 0)) {                    
                    patch_method method = db_patch_method_create;
                    writesz += fmap_write(omap, (uint8_t*)&method, sizeof(method));
                    uint16_t sign = b16swp(sign2);
                    writesz += fmap_write(omap, (uint8_t*)&sign, sizeof(sign));
                    writesz += fmap_write(omap, r2, hashsz);
                    r2 = db2->next_record(r2);
                    count++;
                } else {
                    r1 = db1->next_record(r1);
                    r2 = db2->next_record(r2);
                }
            }
            ((normal_db_t*)omap->addr)->hdr.record_count = count;
            fmap_truncate(omap, writesz);
        } while (false);

        db1->release();
        db2->release();
        fmap_release(omap);
        return count;
    }

    uint32_t database::apply_patch(const std::string& db1_filepath, const std::string& db2_filepath) {
        uint32_t created_count = 0;
        database* db1 = load(db1_filepath);
        if (!db1) {
            return created_count;
        }
        database* db2 = load(db2_filepath);
        if (!db2) {
            db1->release();
            return created_count;
        }

        do {
            if (db1->get_algo() == db_algo_normal) {
                break;
            }
            if (db2->get_type() != db_type_patch) {
                break;
            }
            uint64_t db1_origsz = db1->size();
            db_header_t* db2_hdr = db2->get_header();
            size_t real_hashsz = (db1->compressed() ? COMP_HASHSZ : db2_hdr->hashsz);
            db1->resize(db1_origsz + db2_hdr->record_count * real_hashsz);

            hashdb_t* hashdb = (hashdb_t*)db1->get_header();
            normal_db_t* normal_db = (normal_db_t*)db2_hdr;
            pat_record_t* record = (pat_record_t*)normal_db->record;
            uint8_t* record_tail = hashdb->record + hashdb->hdr.record_count * real_hashsz;

            for (int i = 0; i < normal_db->hdr.record_count; i++) {
                uint16_t sign = HASH2SIGN(record->hash);
                size_t record_size = RECORD_SIZE(real_hashsz);
                if (record->method == db_patch_method_remove) {
                    uint8_t* addr = db1->find(record->hash, real_hashsz);
                    assert(addr);
                    if (addr) {
                        memmove(addr, addr + RECORD_SIZE(real_hashsz), record_tail - addr + RECORD_SIZE(real_hashsz));
                        record_tail -= RECORD_SIZE(real_hashsz);
                        hashdb->idx_tbl[sign].count--;
                        created_count--;
                    }
                } else {
                    uint8_t* r = hashdb->record + hashdb->idx_tbl[sign].offset * record_size;
                    for (uint32_t i = 0; i < hashdb->idx_tbl[sign].count; i++, r += record_size) {
						if (memcmp(r, RECORD_OFFSET(record->hash), record_size) > 0) {
                            break;
                        }
                    }

                    memmove(r + record_size, r, record_tail - r);
                    memcpy(r, RECORD_OFFSET(record->hash), record_size);
                    record_tail += record_size;
                    hashdb->idx_tbl[sign].count++;
                    created_count++;
                }
                fix_offset(hashdb, sign);
                record = (pat_record_t*)((uint8_t*)record + offsetof(pat_record_t, hash) + real_hashsz);
            }
            hashdb->hdr.record_count += created_count;
            db1->resize(db1_origsz + created_count * RECORD_SIZE(real_hashsz));
        } while (false);

        db1->release();
        db2->release();
        return created_count;
    }

    uint64_t database::size() {
        return _map ? _map->size : 0;
    }

    bool database::resize(uint64_t size) {
        if (_map) {
            if (fmap_truncate(_map, size) == 0) {
                return true;
            }
        }
        return false;
    }

    uint8_t* database::first_record() {
        hashdb_t* hashdb = (hashdb_t*)get_header();
        if ( hashdb &&  hashdb->hdr.algo != db_algo_normal) {
            return hashdb->record;
        }
        return nullptr;
    }

    uint8_t* database::next_record(uint8_t* hash) {
        hashdb_t* hashdb = (hashdb_t*)get_header();
        if (hashdb && hashdb->hdr.algo != db_algo_normal) {
            size_t real_hashsz = (hashdb->hdr.compressed ? COMP_HASHSZ : hashdb->hdr.hashsz);
            uint8_t* record_tail = hashdb->record + hashdb->hdr.record_count * RECORD_SIZE(real_hashsz);
            uint8_t* nr = hash + RECORD_SIZE(real_hashsz);
            if (nr >= record_tail || hash < hashdb->record) {
                return nullptr;
            }
            return nr;
        }
        return nullptr;
    }

    bool database::get_sign(uint8_t* hash, size_t hashsz, uint16_t& sign) const {
        hashdb_t* hashdb = (hashdb_t*)get_header();
        uint32_t offset = hashdb->idx_tbl[0].offset;
        for (int i = 0; i < ARRAY_SIZE(hashdb->idx_tbl); i++) {
            uint32_t val = hashdb->idx_tbl[i].count;
            if (val) {
                offset += val;
                if ((hashdb->record + offset * hashsz) > hash) {
                    sign = i;
                    return true;
                }                
            }            
        }
        return false;
    }

    bool database::get_file_hash(const std::string& filepath, db_algo_t algo, uint8_t* hash, uint8_t& hashsz) {
        fmap_t* imap = fmap_alloc_by_path(filepath.c_str(), O_RDONLY, PROT_READ, MAP_SHARED);
        if (!imap) {
            return false;
        }
        bool ret = true;
        switch (algo) {
            case db_algo_murmur64: {
                uint64_t h = murmur_hash64(imap->addr, (int)imap->size);
                hashsz = sizeof(uint64_t);
                memcpy(hash, &h, hashsz);
                break;
            }
            case db_algo_md5: {
                md5_ctx md5;
                rhash_md5_init(&md5);
                rhash_md5_update(&md5, imap->addr, imap->size);
                rhash_md5_final(&md5, hash);
                hashsz = md5_hash_size;
                break;
            }
            case db_algo_sha1: {
                sha1_ctx sha1;
                rhash_sha1_init(&sha1);
                rhash_sha1_update(&sha1, imap->addr, imap->size);
                rhash_sha1_final(&sha1, hash);
                hashsz = sha1_hash_size;
                break;
            }
            case db_algo_sha512: {
                sha512_ctx sha512;
                rhash_sha512_init(&sha512);
                rhash_sha512_update(&sha512, imap->addr, imap->size);
                rhash_sha512_final(&sha512, hash);
                hashsz = sha512_hash_size;
                break;
            }
            default:
                ret = false;
                break;
        }
        fmap_release(imap);
        return ret;
    }
}