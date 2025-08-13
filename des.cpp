#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <chrono>
#include <stdexcept>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <iterator>

using namespace std;
using namespace chrono;

// 定义DES工作模式
enum DESMode {
    ECB,    // 电子密码本模式
    CBC,    // 密码分组链接模式
    CFB,    // 密码反馈模式
    OFB     // 输出反馈模式
};

// 操作模式
enum OperationMode {
    ENCRYPT,
    DECRYPT
};

// 命令行参数结构体
struct Args {
    OperationMode opMode;
    DESMode desMode;
    string key;       // 8字节密钥
    string iv;        // 8字节初始化向量(部分模式需要)
    string inputFile;
    string outputFile;
};

// DES常量定义 - 初始置换表(IP)
const int IP[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// 初始置换逆表(IP^-1)
const int IP_INV[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

// 扩展置换表(E)
const int E[] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

// 置换函数P
const int P[] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};

// S盒
const int S[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

// 密钥置换表PC-1
const int PC1[] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

// 密钥置换表PC-2
const int PC2[] = {
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
};

// 循环左移位数
const int SHIFT[] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

// 工具函数：将64位数据按置换表置换
uint64_t permute(uint64_t data, const int* table, int tableSize) {
    uint64_t result = 0;
    for (int i = 0; i < tableSize; i++) {
        // 提取第table[i]位(从1开始)
        uint64_t bit = (data >> (64 - table[i])) & 1;
        // 放入结果的第(64 - i)位
        result |= (bit << (63 - i));
    }
    return result;
}

// 工具函数：循环左移
uint64_t leftShift(uint64_t data, int bits, int totalBits) {
    uint64_t mask = (1ULL << totalBits) - 1;
    data &= mask; // 确保数据不超过totalBits位
    return ((data << bits) | (data >> (totalBits - bits))) & mask;
}

// 生成16个子密钥
vector<uint64_t> generateSubkeys(uint64_t key) {
    vector<uint64_t> subkeys(16);

    // 第一步：PC-1置换(64位->56位)
    uint64_t permutedKey = 0;
    for (int i = 0; i < 56; i++) {
        uint64_t bit = (key >> (64 - PC1[i])) & 1;
        permutedKey |= (bit << (55 - i));
    }

    // 分成C0和D0两部分(各28位)
    uint64_t C = (permutedKey >> 28) & 0x0FFFFFFF; // 高28位
    uint64_t D = permutedKey & 0x0FFFFFFF;         // 低28位

    // 生成16个子密钥
    for (int i = 0; i < 16; i++) {
        // 循环左移
        C = leftShift(C, SHIFT[i], 28);
        D = leftShift(D, SHIFT[i], 28);

        // 合并C和D，再进行PC-2置换(56位->48位)
        uint64_t CD = (C << 28) | D;
        uint64_t subkey = 0;

        for (int j = 0; j < 48; j++) {
            uint64_t bit = (CD >> (56 - PC2[j])) & 1;
            subkey |= (bit << (47 - j));
        }

        subkeys[i] = subkey;
    }

    return subkeys;
}

// F函数
uint32_t fFunction(uint32_t R, uint64_t subkey) {
    // 扩展置换(32位->48位)
    uint64_t expanded = 0;
    for (int i = 0; i < 48; i++) {
        uint64_t bit = (R >> (32 - E[i])) & 1;
        expanded |= (bit << (47 - i));
    }

    // 与子密钥异或
    expanded ^= subkey;

    // S盒替换(48位->32位)
    uint32_t sOutput = 0;
    for (int i = 0; i < 8; i++) {
        // 每个S盒处理6位
        uint64_t block = (expanded >> (42 - i * 6)) & 0x3F;

        // 计算行和列
        int row = ((block >> 5) & 1) << 1 | (block & 1);
        int col = (block >> 1) & 0x0F;

        // 从S盒获取值(4位)
        uint32_t val = S[i][row][col];
        sOutput |= (val << (28 - i * 4));
    }

    // P置换
    uint32_t pOutput = 0;
    for (int i = 0; i < 32; i++) {
        uint32_t bit = (sOutput >> (32 - P[i])) & 1;
        pOutput |= (bit << (31 - i));
    }

    return pOutput;
}

// 单块DES加密
uint64_t desBlockEncrypt(uint64_t block, const vector<uint64_t>& subkeys) {
    // 初始置换
    uint64_t permuted = permute(block, IP, 64);

    // 分成左右两部分
    uint32_t L = (permuted >> 32) & 0xFFFFFFFF;
    uint32_t R = permuted & 0xFFFFFFFF;

    // 16轮迭代
    for (int i = 0; i < 16; i++) {
        uint32_t temp = R;
        R = L ^ fFunction(R, subkeys[i]);
        L = temp;
    }

    // 交换左右两部分并进行初始置换的逆置换
    uint64_t combined = ((uint64_t)R << 32) | L;
    return permute(combined, IP_INV, 64);
}

// 单块DES解密
uint64_t desBlockDecrypt(uint64_t block, const vector<uint64_t>& subkeys) {
    // 初始置换
    uint64_t permuted = permute(block, IP, 64);

    // 分成左右两部分
    uint32_t L = (permuted >> 32) & 0xFFFFFFFF;
    uint32_t R = permuted & 0xFFFFFFFF;

    // 16轮迭代(使用逆序的子密钥)
    for (int i = 15; i >= 0; i--) {
        uint32_t temp = R;
        R = L ^ fFunction(R, subkeys[i]);
        L = temp;
    }

    // 交换左右两部分并进行初始置换的逆置换
    uint64_t combined = ((uint64_t)R << 32) | L;
    return permute(combined, IP_INV, 64);
}

// 将字符串转换为64位密钥
uint64_t stringToKey(const string& keyStr) {
    if (keyStr.length() != 8) {
        throw invalid_argument("密钥必须是8个字符");
    }

    uint64_t key = 0;
    for (int i = 0; i < 8; i++) {
        key = (key << 8) | static_cast<uint8_t>(keyStr[i]);
    }
    return key;
}

// 解析命令行参数
Args parseArgs(int argc, char* argv[]) {
    Args args;
    args.opMode = ENCRYPT; // 默认加密
    args.desMode = ECB;    // 默认ECB模式

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-m" || arg == "--mode") {
            if (i + 1 >= argc) throw invalid_argument("缺少模式参数值");
            string mode = argv[++i];
            if (mode == "encrypt") args.opMode = ENCRYPT;
            else if (mode == "decrypt") args.opMode = DECRYPT;
            else throw invalid_argument("无效的模式: " + mode);
        }
        else if (arg == "-d" || arg == "--des-mode") {
            if (i + 1 >= argc) throw invalid_argument("缺少DES模式参数值");
            string mode = argv[++i];
            if (mode == "ecb") args.desMode = ECB;
            else if (mode == "cbc") args.desMode = CBC;
            else if (mode == "cfb") args.desMode = CFB;
            else if (mode == "ofb") args.desMode = OFB;
            else throw invalid_argument("无效的DES模式: " + mode);
        }
        else if (arg == "-k" || arg == "--key") {
            if (i + 1 >= argc) throw invalid_argument("缺少密钥参数值");
            args.key = argv[++i];
            if (args.key.length() != 8) {
                throw invalid_argument("密钥必须是8个字符");
            }
        }
        else if (arg == "-i" || arg == "--iv") {
            if (i + 1 >= argc) throw invalid_argument("缺少初始化向量参数值");
            args.iv = argv[++i];
            if (args.iv.length() != 8) {
                throw invalid_argument("初始化向量必须是8个字符");
            }
        }
        else if (arg == "-f" || arg == "--file") {
            if (i + 1 >= argc) throw invalid_argument("缺少输入文件参数值");
            args.inputFile = argv[++i];
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) throw invalid_argument("缺少输出文件参数值");
            args.outputFile = argv[++i];
        }
        else if (arg == "-h" || arg == "--help") {
            cout << "DES加解密工具" << endl;
            cout << "用法: " << argv[0] << " [选项]" << endl;
            cout << "选项:" << endl;
            cout << "  -m, --mode     模式: encrypt(加密) 或 decrypt(解密)，默认encrypt" << endl;
            cout << "  -d, --des-mode DES工作模式: ecb, cbc, cfb, ofb，默认ecb" << endl;
            cout << "  -k, --key      密钥，必须是8个字符" << endl;
            cout << "  -i, --iv       初始化向量，必须是8个字符(CBC/CFB/OFB模式需要)" << endl;
            cout << "  -f, --file     输入文件路径" << endl;
            cout << "  -o, --output   输出文件路径" << endl;
            cout << "  -h, --help     显示帮助信息" << endl;
            exit(0);
        }
        else {
            throw invalid_argument("无效的参数: " + arg);
        }
    }

    // 验证必要参数
    if (args.inputFile.empty()) {
        throw invalid_argument("必须提供输入文件");
    }
    if (args.outputFile.empty()) {
        throw invalid_argument("必须提供输出文件");
    }
    if (args.key.empty()) {
        throw invalid_argument("必须提供密钥");
    }

    // 验证IV
    if ((args.desMode == CBC || args.desMode == CFB || args.desMode == OFB) && args.iv.empty()) {
        throw invalid_argument(CBC == args.desMode ? "CBC" : (CFB == args.desMode ? "CFB" : "OFB") + string("模式需要初始化向量"));
    }

    return args;
}

// 读取文件内容
vector<uint8_t> readFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("无法打开文件: " + filename);
    }

    // 获取文件大小
    file.seekg(0, ios::end);
    size_t size = file.tellg();
    file.seekg(0, ios::beg);

    // 读取文件内容
    vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);

    return data;
}

// 写入文件
void writeFile(const string& filename, const vector<uint8_t>& data) {
    ofstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("无法创建输出文件: " + filename);
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// 处理填充（PKCS#7）
vector<uint8_t> addPadding(const vector<uint8_t>& data) {
    size_t blockSize = 8;
    size_t paddingSize = blockSize - (data.size() % blockSize);
    vector<uint8_t> padded = data;

    for (size_t i = 0; i < paddingSize; i++) {
        padded.push_back(static_cast<uint8_t>(paddingSize));
    }

    return padded;
}

// 移除填充
vector<uint8_t> removePadding(const vector<uint8_t>& data) {
    if (data.empty()) {
        return data;
    }

    size_t paddingSize = data.back();
    if (paddingSize > data.size() || paddingSize > 8) {
        throw runtime_error("无效的填充");
    }

    return vector<uint8_t>(data.begin(), data.end() - paddingSize);
}

// ECB模式加密
vector<uint8_t> ecbEncrypt(const vector<uint8_t>& data, const vector<uint64_t>& subkeys) {
    vector<uint8_t> padded = addPadding(data);
    vector<uint8_t> result;
    result.reserve(padded.size());

    // 按块处理
    for (size_t i = 0; i < padded.size(); i += 8) {
        uint64_t block = 0;
        for (int j = 0; j < 8; j++) {
            block = (block << 8) | padded[i + j];
        }

        uint64_t encrypted = desBlockEncrypt(block, subkeys);

        // 将加密后的块添加到结果
        for (int j = 7; j >= 0; j--) {
            result.push_back(static_cast<uint8_t>((encrypted >> (j * 8)) & 0xFF));
        }
    }

    return result;
}

// ECB模式解密
vector<uint8_t> ecbDecrypt(const vector<uint8_t>& data, const vector<uint64_t>& subkeys) {
    if (data.size() % 8 != 0) {
        throw runtime_error("解密数据长度必须是8的倍数");
    }

    vector<uint8_t> result;
    result.reserve(data.size());

    // 按块处理
    for (size_t i = 0; i < data.size(); i += 8) {
        uint64_t block = 0;
        for (int j = 0; j < 8; j++) {
            block = (block << 8) | data[i + j];
        }

        uint64_t decrypted = desBlockDecrypt(block, subkeys);

        // 将解密后的块添加到结果
        for (int j = 7; j >= 0; j--) {
            result.push_back(static_cast<uint8_t>((decrypted >> (j * 8)) & 0xFF));
        }
    }

    // 移除填充
    return removePadding(result);
}

// CBC模式加密
vector<uint8_t> cbcEncrypt(const vector<uint8_t>& data, const vector<uint64_t>& subkeys, uint64_t iv) {
    vector<uint8_t> padded = addPadding(data);
    vector<uint8_t> result;
    result.reserve(padded.size());

    uint64_t prevBlock = iv;

    // 按块处理
    for (size_t i = 0; i < padded.size(); i += 8) {
        // 构建当前块
        uint64_t block = 0;
        for (int j = 0; j < 8; j++) {
            block = (block << 8) | padded[i + j];
        }

        // 与前一块加密结果异或
        block ^= prevBlock;

        // 加密
        uint64_t encrypted = desBlockEncrypt(block, subkeys);
        prevBlock = encrypted;

        // 将加密后的块添加到结果
        for (int j = 7; j >= 0; j--) {
            result.push_back(static_cast<uint8_t>((encrypted >> (j * 8)) & 0xFF));
        }
    }

    return result;
}

// CBC模式解密
vector<uint8_t> cbcDecrypt(const vector<uint8_t>& data, const vector<uint64_t>& subkeys, uint64_t iv) {
    if (data.size() % 8 != 0) {
        throw runtime_error("解密数据长度必须是8的倍数");
    }

    vector<uint8_t> result;
    result.reserve(data.size());

    uint64_t prevBlock = iv;

    // 按块处理
    for (size_t i = 0; i < data.size(); i += 8) {
        // 构建当前块
        uint64_t block = 0;
        for (int j = 0; j < 8; j++) {
            block = (block << 8) | data[i + j];
        }

        // 解密
        uint64_t decrypted = desBlockDecrypt(block, subkeys);

        // 与前一块密文异或
        decrypted ^= prevBlock;
        prevBlock = block;

        // 将解密后的块添加到结果
        for (int j = 7; j >= 0; j--) {
            result.push_back(static_cast<uint8_t>((decrypted >> (j * 8)) & 0xFF));
        }
    }

    // 移除填充
    return removePadding(result);
}

// CFB模式加密/解密
vector<uint8_t> cfbProcess(const vector<uint8_t>& data, const vector<uint64_t>& subkeys, uint64_t iv, OperationMode mode) {
    vector<uint8_t> result;
    result.reserve(data.size());

    uint64_t registerValue = iv;  // 移位寄存器

    // 按字节处理
    for (uint8_t byte : data) {
        // 加密寄存器内容
        uint64_t encryptedReg = desBlockEncrypt(registerValue, subkeys);

        // 取加密结果的最高位字节
        uint8_t keystreamByte = static_cast<uint8_t>((encryptedReg >> 56) & 0xFF);

        // 与明文/密文异或
        uint8_t outputByte = byte ^ keystreamByte;
        result.push_back(outputByte);

        // 更新移位寄存器
        registerValue = (registerValue << 8) | (mode == ENCRYPT ? outputByte : byte);
        registerValue &= 0xFFFFFFFFFFFFFFFF;  // 保持64位
    }

    return result;
}

// OFB模式加密/解密
vector<uint8_t> ofbProcess(const vector<uint8_t>& data, const vector<uint64_t>& subkeys, uint64_t iv) {
    vector<uint8_t> result;
    result.reserve(data.size());

    uint64_t registerValue = iv;  // 移位寄存器

    // 按字节处理
    for (uint8_t byte : data) {
        // 加密寄存器内容
        uint64_t encryptedReg = desBlockEncrypt(registerValue, subkeys);

        // 取加密结果的最高位字节作为密钥流
        uint8_t keystreamByte = static_cast<uint8_t>((encryptedReg >> 56) & 0xFF);

        // 与明文/密文异或
        result.push_back(byte ^ keystreamByte);

        // 更新移位寄存器
        registerValue = encryptedReg;
    }

    return result;
}

int main(int argc, char* argv[]) {
    try {
        // 解析命令行参数
        Args args = parseArgs(argc, argv);

        // 读取输入文件
        vector<uint8_t> inputData = readFile(args.inputFile);
        cout << "读取文件: " << args.inputFile << " (" << inputData.size() << " 字节)" << endl;

        // 转换密钥
        uint64_t key = stringToKey(args.key);

        // 生成子密钥
        vector<uint64_t> subkeys = generateSubkeys(key);

        // 处理初始化向量
        uint64_t iv = 0;
        if (!args.iv.empty()) {
            iv = stringToKey(args.iv);
        }

        // 执行加解密操作并计时
        vector<uint8_t> outputData;
        auto start = high_resolution_clock::now();

        switch (args.desMode) {
        case ECB:
            if (args.opMode == ENCRYPT) {
                outputData = ecbEncrypt(inputData, subkeys);
            }
            else {
                outputData = ecbDecrypt(inputData, subkeys);
            }
            break;
        case CBC:
            if (args.opMode == ENCRYPT) {
                outputData = cbcEncrypt(inputData, subkeys, iv);
            }
            else {
                outputData = cbcDecrypt(inputData, subkeys, iv);
            }
            break;
        case CFB:
            outputData = cfbProcess(inputData, subkeys, iv, args.opMode);
            break;
        case OFB:
            outputData = ofbProcess(inputData, subkeys, iv);
            break;
        }

        auto end = high_resolution_clock::now();
        auto duration = duration_cast<milliseconds>(end - start);

        // 写入输出文件
        writeFile(args.outputFile, outputData);
        cout << "写入文件: " << args.outputFile << " (" << outputData.size() << " 字节)" << endl;

        // 输出信息
        cout << "操作: " << (args.opMode == ENCRYPT ? "加密" : "解密") << " 完成" << endl;
        cout << "DES模式: ";
        switch (args.desMode) {
        case ECB: cout << "ECB"; break;
        case CBC: cout << "CBC"; break;
        case CFB: cout << "CFB"; break;
        case OFB: cout << "OFB"; break;
        }
        cout << endl;
        cout << "耗时: " << duration.count() << " 毫秒" << endl;

    }
    catch (const exception& e) {
        cerr << "错误: " << e.what() << endl;
        cerr << "使用 -h 或 --help 查看帮助信息" << endl;
        return 1;
    }

    return 0;
}
