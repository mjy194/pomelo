# 基于二进制搜索的数据库
## 特性
- [x] 支持多种hash算法
- [x] 基于库文件搜索，不需要加载到内存，再转换成内存的数据结构
- [x] 支持以补丁的方式进行分发
- [x] 跨平台支持(Windows Linux macOS)
- [ ] 加密分发


## 库相关工具
```
Usage: podbutil<command> [OPTION...] ...
<Command>
  b : Build db file from binary hash file.
  c : Convert from text hash file to binary hash file.
  f : Find hash in db.
  g : Generate hash file.
  i : show database info.
  m : merge database.
  p : Create patched db file.
  t : Performance test.

Examples:
  podbutil b -s <hash file> -a <algorithm> <db> [-c compress]
  podbutil c <text hash file> <hash file>
  podbutil f <hash> <db>
  podbutil g -n <count> -a <algorithm> <hash file>
  podbutil i <db>
  podbutil m <db> <patch>
  podbutil p <db1> <db2> <patch>
  podbutil t <hash file> <db>

Options:
  -h: binary hash file
  -a: normal[0], murmur64[1], md5[2], sha1[3], sha512[4]
  -c: compress
  -n: count
  -v: verbose
```


## 快速开始

### 编译
Linux & macOS
```
$ git clone https://github.com/mjy194/pomelo.git
$ cd pomelo
$ mkdir build
$ cmake ..

linux:
$ make -j$(nproc)

macOS
$ make -j$(sysctl -n hw.logicalcpu)
```

Windows
```
Windows 下Visual Studio大法好，直接右键使用Visual Studio打开，会自动识别cmake工程，然后编译即可。本人使用的是Visual Studio 2022，更老的版本没有测试，不支持cmake工程的Visual studio可以使用 cmake -G 生成解决方案，如遇问题可提issues
```

### 用法
```
# 生成测试hash
$ ./podbutil g -n 1000 -a 4 a.txt

# 将hash文本转换为二进制
$ ./podbutil c a.txt a.bin

# 构建hashdb
$ ./podbutil b -s a.bin -a 4 a.db

# 生成测试hash2
$ ./podbutil g -n 100 -a 4 b.txt

# 将a.txt中的hash拷贝到b.txt 也可以删除一些记录

# 将hash2文本转换为二进制
$ ./podbutil c b.txt b.bin

# 构建hashdb2
$ ./podbutil b -s b.bin -a 4 b.db

# 生成patch
$ ./podbutil p a.db b.db p.patch

# 将patch merge回数据库
$ ./podbutil m a.db p.patch

# 测试合并结果
$ ./podbutil t b.bin a.db

```
## 库的设计

### 关键结构

#### 数据库头
```
struct db_header {  
	 uint64_t magic;  
	 uint32_t version;  
	 uint64_t algo: 4;  
	 uint64_t dbtype: 1;  
	 uint64_t compressed: 1;  
	 uint64_t record_count: 32;  
	 uint64_t hashsz: 8;  
	 uint64_t reserved: 18;  
 };
```

#### hash库结构
```
#define TAB_SIZE 0x10000

struct primary_table {  
	 uint32_t offset;  
	 uint16_t count;  
 };

struct hash_db {  
	 db_header_t hdr;  
	 primary_table_t idx_tbl[TAB_SIZE];  
	 uint8_t record[1];  
 };
```

* hashdb 可通过调整表大小来平衡性能和空间占用；
* 为何命名为主表，是因为考虑过多层表结构的方式来进行存储，测试了一些方式没有很好的效果，故暂定一层表；

#### 普通库结构
```
struct normal_db {  
	 db_header_t hdr;  
	 uint8_t record[1];  
 };
```

#### patch库记录
```
struct hash_patch_db {  
	 db_header_t hdr;  
	 pat_record record[1];  
 };
```
* 由于patch不一定占用多少，一般应该不会有太多记录，如果用hash表，hash表中的idx_tbl大部分将毫无意义，所以patch库就根据记录来存储

### 主要逻辑

#### hashdb
* 构建
    1. 遍历hash，将hash通过set进行去重、排序
    2. 计算sign的数量，存到primary_table_t中
    3. 遍历完根据count计算offset
    4. 将数据库头部写入
    5. 遍历set，将裁减的hash写入库中

**注：对hash进行裁减，前两字节作为sign已经包含了前两字节，数据库记录中无需再存(约等于压缩，但有限)**

* 压缩
    1. 压缩数据通过murmur对非64bit hash重新计算hash，将计算完的hash作为记录存到数据库中

* 匹配
    1. 将hash前两字节作为sign直接通过idx_tbl进行索引，获取主表中此sign的count和offset，遍历sign根据offset进行匹配，10,000,000数据平均的记录在150条左右；
    2. 若数据有压缩，匹配时会根据原始hash算法先进行计算，再通过murmur对原始hash计算再进行匹配

* 补丁
    1. 对两个数据库进行diff将diff的结果存入normal db，开始考虑使用binary patch，由于可以获取数据库记录，故通过记录的方式更合适，
    2. 应用补丁需要对原始数据库的记录进行移动，当数据过多或数据更靠前效率相对会变低，这个还取决于磁盘io的性能，这个问题的处理方向：将数据库分块，使用多个文件的方式进行存储，这样每次移动内存和io的数量将减小
    3. 补丁库中的记录是完整的hash，应用的时候会裁减hash存到对应的hashdb中


### 生成库大小
```
-rw-r--r-- 1 58M Nov  2 21:57 compressed.db
-rw-r--r-- 1 1.3G Nov  2 21:55 origin_data.txt
-rw-r--r-- 1 611M Nov  2 21:56 origin_data.bin
-rw-r--r-- 1 592M Nov  2 21:58 uncompress.db
```

### 性能测试:
```
测试机器配置：
OS: Linux archmini 6.5.9-arch2-1 #1 SMP PREEMPT_DYNAMIC Thu, 26 Oct 2023 00:52:20 +0000 x86_64 GNU/Linux
CPU: 12th Gen Intel(R) Core(TM) i5-12600
RAM: Cuso 3200MHz 16G x 2
Disk: SanDisk Extreme 55AE 1TB
```

#### 测试压缩库
```
$ ./podbutil t origin_data.bin compressed.db
spent: 2.881252 s
Test total: 10000000
matched: 0
mismatched: 0


$ ./podbutil t origin_data.bin compressed.db
spent: 2.482362 s
Test total: 10000000
matched: 10000000
mismatched: 0


$ ./podbutil t origin_data.bin compressed.db
spent: 2.430079 s
Test total: 10000000
matched: 0
mismatched: 0
```

#### 测试未压缩的库
```
$ ./podbutil t origin_data.bin uncompress.db
spent: 4.022955 s
Test total: 10000000
matched: 10000000
mismatched: 0


$ ./podbutil t origin_data.bin uncompress.db
spent: 4.054167 s
Test total: 10000000
matched: 10000000
mismatched: 0


$ ./podbutil t origin_data.bin uncompress.db
spent: 4.046511 s
Test total: 10000000
matched: 10000000
mismatched: 0
```
**注：压缩的库匹配速度快是因为记录的字节数少**


## 其他
#### 一些想法
1. 如果这个作为白名单的库，如果有文件更多的信息可以效率更高，因为默认采用文件hash的方式进行匹配，所以需要进行io操作，匹配的速度和io性能正相关，如果有更多的文件信息，比如大小（需要每一条记录都包含此信息），可以构建一个文件大小的表，先过文件大小的表，如果没有命中则无需计算hash

2. 二进制压缩采取了一个比较取巧的方式，对于hash的压缩想法：因为每条hash是固定长的，所以有对应的边界，如果能将多条hash中最长的数据取出来只保留一份，而hash中保留此数据的关联信息（偏移），在匹配的时候通过位置信息进行hash还原，应该既能达到压缩，又能保证搜索效率


## 特别鸣谢
  * @benly