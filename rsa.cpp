#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <iomanip>
#include <cstring>

using namespace std;
using namespace chrono;

// 大整数类型定义（使用64位无符号整数数组，低位在前）
typedef vector<uint64_t> BigInt;

// 操作模式
enum OperationMode {
    GENERATE_KEYS,
    ENCRYPT,
    DECRYPT
};

// 命令行参数结构体
struct Args {
    OperationMode opMode;
    string publicKeyFile;    // 公钥文件
    string privateKeyFile;   // 私钥文件
    string inputFile;        // 输入文件
    string outputFile;       // 输出文件
    int keySize;             // 密钥长度（比特）
};

// 随机数生成器
uint64_t generateRandom64() {
    static mt19937_64 rng(system_clock::now().time_since_epoch().count());
    return rng();
}

// 大整数比较：a > b
bool greaterThan(const BigInt& a, const BigInt& b) {
    if (a.size() != b.size()) return a.size() > b.size();
    for (int i = a.size() - 1; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return false;
}

// 大整数比较：a == b
bool equals(const BigInt& a, const BigInt& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// 大整数加法
BigInt add(const BigInt& a, const BigInt& b) {
    BigInt result;
    uint64_t carry = 0;
    size_t maxSize = max(a.size(), b.size());

    for (size_t i = 0; i < maxSize || carry; ++i) {
        uint64_t aVal = (i < a.size()) ? a[i] : 0;
        uint64_t bVal = (i < b.size()) ? b[i] : 0;

        uint64_t sum = aVal + bVal + carry;
        carry = (sum < aVal) ? 1 : 0;  // 检测溢出
        result.push_back(sum);
    }

    return result;
}

// 大整数减法（假设a >= b）
BigInt subtract(const BigInt& a, const BigInt& b) {
    BigInt result;
    uint64_t borrow = 0;

    for (size_t i = 0; i < a.size(); ++i) {
        uint64_t aVal = a[i];
        uint64_t bVal = (i < b.size()) ? b[i] : 0;

        aVal -= borrow;
        borrow = 0;

        if (aVal < bVal) {
            aVal += UINT64_MAX + 1;  // 处理借位
            borrow = 1;
        }

        result.push_back(aVal - bVal);
    }

    // 移除前导零
    while (result.size() > 1 && result.back() == 0) {
        result.pop_back();
    }

    return result;
}

// 大整数乘法（与64位整数）
BigInt multiply(const BigInt& a, uint64_t b) {
    if (b == 0) return { 0 };

    BigInt result;
    uint64_t carry = 0;

    for (uint64_t aVal : a) {
        __uint128_t product = (__uint128_t)aVal * b + carry;
        result.push_back((uint64_t)(product & 0xFFFFFFFFFFFFFFFF));
        carry = (uint64_t)(product >> 64);
    }

    if (carry > 0) {
        result.push_back(carry);
    }

    return result;
}

// 大整数乘法
BigInt multiply(const BigInt& a, const BigInt& b) {
    BigInt result(a.size() + b.size(), 0);

    for (size_t i = 0; i < a.size(); ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b.size() || carry; ++j) {
            __uint128_t product = result[i + j] +
                (__uint128_t)a[i] * (j < b.size() ? b[j] : 0) + carry;
            result[i + j] = (uint64_t)(product & 0xFFFFFFFFFFFFFFFF);
            carry = (uint64_t)(product >> 64);
        }
    }

    // 移除前导零
    while (result.size() > 1 && result.back() == 0) {
        result.pop_back();
    }

    return result;
}

// 大整数除法（返回商和余数）
pair<BigInt, BigInt> divide(const BigInt& a, const BigInt& b) {
    if (equals(b, BigInt{ 0 })) {
        throw runtime_error("除以零错误");
    }

    if (greaterThan(b, a)) {
        return { BigInt{0}, a };
    }

    BigInt quotient;
    BigInt remainder;

    // 从最高位开始处理
    for (int i = a.size() - 1; i >= 0; --i) {
        // 将当前位添加到余数
        remainder.insert(remainder.begin(), a[i]);

        // 移除前导零
        while (remainder.size() > 1 && remainder.back() == 0) {
            remainder.pop_back();
        }

        // 计算当前位的商
        uint64_t q = 0;
        BigInt temp = b;

        // 找到最大的q使得q*b <= remainder
        while (greaterThan(remainder, temp) || equals(remainder, temp)) {
            q++;
            temp = add(temp, b);
        }

        quotient.insert(quotient.begin(), q);

        // 更新余数
        if (q > 0) {
            temp = subtract(temp, b);  // 回退一步
            remainder = subtract(remainder, temp);
        }
    }

    // 移除商的前导零
    while (quotient.size() > 1 && quotient.back() == 0) {
        quotient.pop_back();
    }

    return { quotient, remainder };
}

// 大整数取模（重命名以避免与关键字冲突）
BigInt bigMod(const BigInt& a, const BigInt& m) {
    return divide(a, m).second;
}

// 大整数模幂运算 (base^exponent mod mod)
BigInt modPow(const BigInt& base, const BigInt& exponent, const BigInt& mod) {
    BigInt result = { 1 };
    BigInt currentBase = bigMod(base, mod);  // 使用重命名的函数
    BigInt currentExponent = exponent;

    while (!equals(currentExponent, BigInt{ 0 })) {
        // 如果指数是奇数，乘以当前基数
        if (currentExponent[0] % 2 == 1) {
            result = bigMod(multiply(result, currentBase), mod);  // 使用重命名的函数
        }

        // 指数除以2
        currentExponent = divide(currentExponent, BigInt{ 2 }).first;

        // 基数平方
        currentBase = bigMod(multiply(currentBase, currentBase), mod);  // 使用重命名的函数
    }

    return result;
}

// 计算最大公约数 (GCD)
BigInt gcd(const BigInt& a, const BigInt& b) {
    if (equals(b, BigInt{ 0 })) {
        return a;
    }
    return gcd(b, bigMod(a, b));  // 使用重命名的函数
}

// 扩展欧几里得算法，计算ax + by = gcd(a, b)
tuple<BigInt, BigInt, BigInt> extendedGcd(const BigInt& a, const BigInt& b) {
    if (equals(b, BigInt{ 0 })) {
        return { a, BigInt{1}, BigInt{0} };
    }

    auto [g, x, y] = extendedGcd(b, bigMod(a, b));  // 使用重命名的函数
    BigInt q = divide(a, b).first;
    BigInt newX = subtract(y, multiply(q, x));

    return { g, y, newX };
}

// 计算模逆元 (a^-1 mod m)
BigInt modInverse(const BigInt& a, const BigInt& m) {
    auto [g, x, y] = extendedGcd(a, m);

    if (!equals(g, BigInt{ 1 })) {
        // 逆元不存在
        return BigInt{ 0 };
    }
    else {
        // 确保结果为正数
        BigInt result = bigMod(x, m);  // 使用重命名的函数
        return result;
    }
}

// 将64位整数转换为大整数
BigInt toBigInt(uint64_t num) {
    if (num == 0) return { 0 };
    return { num };
}

// 将字符串转换为大整数
BigInt stringToBigInt(const string& s) {
    BigInt result = { 0 };
    for (char c : s) {
        // 每次乘以10然后加上当前数字
        result = multiply(result, 10);
        result = add(result, toBigInt((uint64_t)(c - '0')));
    }
    return result;
}

// 将大整数转换为十六进制字符串
string bigIntToHex(const BigInt& num) {
    if (equals(num, BigInt{ 0 })) return "0";

    stringstream ss;
    ss << hex << setfill('0');

    // 处理最高位（可能不需要前导零）
    size_t last = num.size() - 1;
    ss << num[last];

    // 处理其他位（需要前导零以确保16个十六进制数字）
    for (int i = last - 1; i >= 0; --i) {
        ss << setw(16) << num[i];
    }

    return ss.str();
}

// 将十六进制字符串转换为大整数
BigInt hexToBigInt(const string& hexStr) {
    BigInt result = { 0 };
    string temp = hexStr;

    // 每次处理16个十六进制数字（64位）
    while (!temp.empty()) {
        size_t start = max(0, (int)temp.size() - 16);
        string chunk = temp.substr(start);
        temp = temp.substr(0, start);

        uint64_t val;
        stringstream ss;
        ss << hex << chunk;
        ss >> val;

        // 修复：使用移位操作替代过大的整数常量
        BigInt shifted = multiply(result, 0x100000000ULL);  // 乘以2^32
        shifted = multiply(shifted, 0x100000000ULL);        // 再乘以2^32，总共2^64
        result = add(shifted, toBigInt(val));
    }

    return result;
}

// Miller-Rabin素性测试
bool isPrime(const BigInt& n, int iterations = 5) {
    // 处理小数字的情况
    if (equals(n, BigInt{ 2 }) || equals(n, BigInt{ 3 })) return true;
    if (equals(n, BigInt{ 1 }) || n[0] % 2 == 0) return false;

    // 写成n-1 = d*2^s
    BigInt d = subtract(n, BigInt{ 1 });
    int s = 0;

    while (d[0] % 2 == 0) {
        d = divide(d, BigInt{ 2 }).first;
        s++;
    }

    // 进行多次测试
    for (int i = 0; i < iterations; ++i) {
        // 生成随机数a，1 < a < n
        BigInt a;
        do {
            // 生成与n大小相似的随机数
            a.clear();
            for (size_t j = 0; j < n.size(); ++j) {
                a.push_back(generateRandom64());
            }
            // 确保a < n
            a = bigMod(a, subtract(n, BigInt{ 2 }));  // 使用重命名的函数
            a = add(a, BigInt{ 1 });  // 确保a >= 1
        } while (!greaterThan(a, BigInt{ 1 }) || !greaterThan(n, a));

        BigInt x = modPow(a, d, n);

        if (equals(x, BigInt{ 1 }) || equals(x, subtract(n, BigInt{ 1 }))) {
            continue;
        }

        bool composite = true;
        for (int j = 0; j < s - 1; ++j) {
            x = modPow(x, BigInt{ 2 }, n);
            if (equals(x, subtract(n, BigInt{ 1 }))) {
                composite = false;
                break;
            }
        }

        if (composite) {
            return false;
        }
    }

    return true;
}

// 生成指定比特长度的随机素数
BigInt generatePrime(int bits) {
    if (bits < 8) {
        throw runtime_error("素数长度至少为8位");
    }

    int num64Chunks = (bits + 63) / 64;
    BigInt p;

    do {
        p.clear();
        // 生成随机数
        for (int i = 0; i < num64Chunks; ++i) {
            p.push_back(generateRandom64());
        }

        // 设置最高位确保长度
        int highestBit = bits - 1;
        int highestChunk = highestBit / 64;
        int highestChunkBit = highestBit % 64;
        p[highestChunk] |= (uint64_t)1 << highestChunkBit;

        // 确保是奇数
        p[0] |= 1;

    } while (!isPrime(p));

    return p;
}

// 生成RSA密钥对
void generateRSAKeys(int keySize, const string& publicKeyFile, const string& privateKeyFile) {
    cout << "生成" << keySize << "位RSA密钥对..." << endl;

    auto start = high_resolution_clock::now();

    // 生成两个大素数p和q
    cout << "生成素数p...";
    BigInt p = generatePrime(keySize / 2);
    cout << "完成" << endl;

    cout << "生成素数q...";
    BigInt q = generatePrime(keySize / 2);
    cout << "完成" << endl;

    // 计算n = p * q
    BigInt n = multiply(p, q);
    cout << "计算n = p * q 完成" << endl;

    // 计算欧拉函数φ(n) = (p-1) * (q-1)
    BigInt pMinus1 = subtract(p, BigInt{ 1 });
    BigInt qMinus1 = subtract(q, BigInt{ 1 });
    BigInt phi = multiply(pMinus1, qMinus1);
    cout << "计算φ(n) 完成" << endl;

    // 选择公钥指数e（通常选择65537）
    BigInt e = stringToBigInt("65537");

    // 确保e与φ(n)互质
    while (!equals(gcd(e, phi), BigInt{ 1 })) {
        e = add(e, BigInt{ 2 });  // 尝试下一个奇数
    }
    cout << "选择公钥指数e 完成" << endl;

    // 计算私钥指数d，e的模逆
    BigInt d = modInverse(e, phi);
    if (equals(d, BigInt{ 0 })) {
        throw runtime_error("无法计算私钥指数d，e和φ(n)不互质");
    }
    cout << "计算私钥指数d 完成" << endl;

    // 保存公钥 (e, n)
    ofstream publicFile(publicKeyFile);
    if (!publicFile) {
        throw runtime_error("无法创建公钥文件: " + publicKeyFile);
    }
    publicFile << "e=" << bigIntToHex(e) << endl;
    publicFile << "n=" << bigIntToHex(n) << endl;
    publicFile.close();

    // 保存私钥 (d, n)
    ofstream privateFile(privateKeyFile);
    if (!privateFile) {
        throw runtime_error("无法创建私钥文件: " + privateKeyFile);
    }
    privateFile << "d=" << bigIntToHex(d) << endl;
    privateFile << "n=" << bigIntToHex(n) << endl;
    privateFile.close();

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<seconds>(end - start);

    cout << "密钥对生成完成，耗时: " << duration.count() << "秒" << endl;
    cout << "公钥保存到: " << publicKeyFile << endl;
    cout << "私钥保存到: " << privateKeyFile << endl;
}

// 从文件加载密钥
pair<BigInt, BigInt> loadKey(const string& filename) {
    ifstream file(filename);
    if (!file) {
        throw runtime_error("无法打开密钥文件: " + filename);
    }

    string line;
    BigInt exp, mod;

    while (getline(file, line)) {
        size_t eqPos = line.find('=');
        if (eqPos == string::npos) continue;

        string key = line.substr(0, eqPos);
        string value = line.substr(eqPos + 1);

        if (key == "e" || key == "d") {
            exp = hexToBigInt(value);
        }
        else if (key == "n") {
            mod = hexToBigInt(value);
        }
    }

    if (exp.empty() || mod.empty()) {
        throw runtime_error("密钥文件格式不正确: " + filename);
    }

    return { exp, mod };
}

// RSA加密
void rsaEncrypt(const string& publicKeyFile, const string& inputFile, const string& outputFile) {
    cout << "使用RSA加密文件..." << endl;

    // 加载公钥
    auto [e, n] = loadKey(publicKeyFile);
    cout << "加载公钥完成" << endl;

    // 读取输入文件
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        throw runtime_error("无法打开输入文件: " + inputFile);
    }

    // 获取文件大小
    inFile.seekg(0, ios::end);
    streamsize fileSize = inFile.tellg();
    inFile.seekg(0, ios::beg);

    // 计算最大明文块大小（字节）
    int maxBlockSize = (n.size() * 8 - 16) / 8;  // 预留16位用于填充
    cout << "最大明文块大小: " << maxBlockSize << "字节" << endl;

    // 打开输出文件
    ofstream outFile(outputFile, ios::binary);
    if (!outFile) {
        throw runtime_error("无法创建输出文件: " + outputFile);
    }

    // 写入块大小信息（前4字节）
    uint32_t blockSize = maxBlockSize;
    outFile.write(reinterpret_cast<const char*>(&blockSize), sizeof(blockSize));

    // 写入原始文件大小（接下来8字节）
    uint64_t originalSize = static_cast<uint64_t>(fileSize);
    outFile.write(reinterpret_cast<const char*>(&originalSize), sizeof(originalSize));

    // 分块加密
    vector<uint8_t> buffer(maxBlockSize);
    streamsize bytesRead;
    size_t totalBlocks = 0;

    auto start = high_resolution_clock::now();

    // 修复：正确读取流并获取读取的字节数
    while (inFile.read(reinterpret_cast<char*>(buffer.data()), maxBlockSize)) {
        bytesRead = inFile.gcount();

        // 如果不是完整块，填充随机数据
        if (bytesRead < maxBlockSize) {
            for (streamsize i = bytesRead; i < maxBlockSize; ++i) {
                buffer[i] = static_cast<uint8_t>(generateRandom64() % 256);
            }
        }

        // 将字节缓冲区转换为大整数
        BigInt m;
        for (int i = maxBlockSize - 1; i >= 0; i -= 8) {
            uint64_t val = 0;
            for (int j = 0; j < 8 && i - j >= 0; ++j) {
                val |= static_cast<uint64_t>(buffer[i - j]) << (j * 8);
            }
            m.push_back(val);
        }

        // 加密: c = m^e mod n
        BigInt c = modPow(m, e, n);

        // 写入加密后的块大小（4字节）
        uint32_t encryptedSize = c.size() * 8;
        outFile.write(reinterpret_cast<const char*>(&encryptedSize), sizeof(encryptedSize));

        // 写入加密后的数据
        for (auto chunk : c) {
            outFile.write(reinterpret_cast<const char*>(&chunk), sizeof(chunk));
        }

        totalBlocks++;
        if (totalBlocks % 10 == 0) {
            cout << "已加密 " << totalBlocks << " 块..." << endl;
        }
    }

    // 处理最后一个不完整的块
    bytesRead = inFile.gcount();
    if (bytesRead > 0) {
        // 填充随机数据
        for (streamsize i = bytesRead; i < maxBlockSize; ++i) {
            buffer[i] = static_cast<uint8_t>(generateRandom64() % 256);
        }

        // 转换为大整数并加密
        BigInt m;
        for (int i = maxBlockSize - 1; i >= 0; i -= 8) {
            uint64_t val = 0;
            for (int j = 0; j < 8 && i - j >= 0; ++j) {
                val |= static_cast<uint64_t>(buffer[i - j]) << (j * 8);
            }
            m.push_back(val);
        }

        BigInt c = modPow(m, e, n);

        // 写入加密结果
        uint32_t encryptedSize = c.size() * 8;
        outFile.write(reinterpret_cast<const char*>(&encryptedSize), sizeof(encryptedSize));
        for (auto chunk : c) {
            outFile.write(reinterpret_cast<const char*>(&chunk), sizeof(chunk));
        }

        totalBlocks++;
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);

    cout << "加密完成，共 " << totalBlocks << " 块，耗时: " << duration.count() << "毫秒" << endl;
    cout << "加密结果保存到: " << outputFile << endl;
}

// RSA解密
void rsaDecrypt(const string& privateKeyFile, const string& inputFile, const string& outputFile) {
    cout << "使用RSA解密文件..." << endl;

    // 加载私钥
    auto [d, n] = loadKey(privateKeyFile);
    cout << "加载私钥完成" << endl;

    // 打开输入文件
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        throw runtime_error("无法打开输入文件: " + inputFile);
    }

    // 读取块大小信息
    uint32_t maxBlockSize;
    inFile.read(reinterpret_cast<char*>(&maxBlockSize), sizeof(maxBlockSize));

    // 读取原始文件大小
    uint64_t originalSize;
    inFile.read(reinterpret_cast<char*>(&originalSize), sizeof(originalSize));

    // 打开输出文件
    ofstream outFile(outputFile, ios::binary);
    if (!outFile) {
        throw runtime_error("无法创建输出文件: " + outputFile);
    }

    // 分块解密
    size_t totalBlocks = 0;
    uint64_t bytesWritten = 0;

    auto start = high_resolution_clock::now();

    while (inFile.peek() != EOF) {
        // 读取加密块大小
        uint32_t encryptedSize;
        inFile.read(reinterpret_cast<char*>(&encryptedSize), sizeof(encryptedSize));

        int numChunks = (encryptedSize + 63) / 64;

        // 读取加密数据
        BigInt c;
        for (int i = 0; i < numChunks; ++i) {
            uint64_t chunk;
            inFile.read(reinterpret_cast<char*>(&chunk), sizeof(chunk));
            c.push_back(chunk);
        }

        // 解密: m = c^d mod n
        BigInt m = modPow(c, d, n);

        // 将大整数转换回字节缓冲区
        vector<uint8_t> buffer(maxBlockSize, 0);
        for (size_t i = 0; i < m.size() && i * 8 < maxBlockSize; ++i) {
            uint64_t val = m[i];
            for (int j = 0; j < 8 && i * 8 + j < maxBlockSize; ++j) {
                buffer[i * 8 + j] = static_cast<uint8_t>((val >> (j * 8)) & 0xFF);
            }
        }

        // 计算需要写入的字节数（最后一块可能少于maxBlockSize）
        streamsize writeSize = maxBlockSize;
        if (bytesWritten + writeSize > originalSize) {
            writeSize = originalSize - bytesWritten;
        }

        // 写入解密后的数据
        outFile.write(reinterpret_cast<const char*>(buffer.data()), writeSize);
        bytesWritten += writeSize;

        totalBlocks++;
        if (totalBlocks % 10 == 0) {
            cout << "已解密 " << totalBlocks << " 块..." << endl;
        }
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);

    cout << "解密完成，共 " << totalBlocks << " 块，耗时: " << duration.count() << "毫秒" << endl;
    cout << "解密结果保存到: " << outputFile << endl;
}

// 解析命令行参数
Args parseArgs(int argc, char* argv[]) {
    Args args;
    args.opMode = GENERATE_KEYS;  // 默认生成密钥
    args.keySize = 2048;          // 默认密钥长度

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-g" || arg == "--generate") {
            args.opMode = GENERATE_KEYS;
        }
        else if (arg == "-e" || arg == "--encrypt") {
            args.opMode = ENCRYPT;
        }
        else if (arg == "-d" || arg == "--decrypt") {
            args.opMode = DECRYPT;
        }
        else if (arg == "-s" || arg == "--key-size") {
            if (i + 1 >= argc) throw invalid_argument("缺少密钥长度参数值");
            args.keySize = stoi(argv[++i]);
            if (args.keySize < 512 || args.keySize % 512 != 0) {
                throw invalid_argument("密钥长度必须是512的倍数且至少为512");
            }
        }
        else if (arg == "-p" || arg == "--public-key") {
            if (i + 1 >= argc) throw invalid_argument("缺少公钥文件参数值");
            args.publicKeyFile = argv[++i];
        }
        else if (arg == "-r" || arg == "--private-key") {
            if (i + 1 >= argc) throw invalid_argument("缺少私钥文件参数值");
            args.privateKeyFile = argv[++i];
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
            cout << "RSA加解密工具" << endl;
            cout << "用法: " << argv[0] << " [选项]" << endl;
            cout << "选项:" << endl;
            cout << "  -g, --generate      生成密钥对（默认）" << endl;
            cout << "  -e, --encrypt       加密文件" << endl;
            cout << "  -d, --decrypt       解密文件" << endl;
            cout << "  -s, --key-size      密钥长度（512, 1024, 2048, 4096），默认2048" << endl;
            cout << "  -p, --public-key    公钥文件路径" << endl;
            cout << "  -r, --private-key   私钥文件路径" << endl;
            cout << "  -f, --file          输入文件路径" << endl;
            cout << "  -o, --output        输出文件路径" << endl;
            cout << "  -h, --help          显示帮助信息" << endl;
            cout << endl;
            cout << "示例:" << endl;
            cout << "  生成密钥对: " << argv[0] << " -g -s 2048 -p public.key -r private.key" << endl;
            cout << "  加密文件: " << argv[0] << " -e -p public.key -f plaintext.txt -o ciphertext.bin" << endl;
            cout << "  解密文件: " << argv[0] << " -d -r private.key -f ciphertext.bin -o plaintext.txt" << endl;
            exit(0);
        }
        else {
            throw invalid_argument("无效的参数: " + arg);
        }
    }

    // 验证必要参数
    switch (args.opMode) {
    case GENERATE_KEYS:
        if (args.publicKeyFile.empty() || args.privateKeyFile.empty()) {
            throw invalid_argument("生成密钥对需要指定公钥和私钥文件路径");
        }
        break;
    case ENCRYPT:
        if (args.publicKeyFile.empty() || args.inputFile.empty() || args.outputFile.empty()) {
            throw invalid_argument("加密需要指定公钥文件、输入文件和输出文件路径");
        }
        break;
    case DECRYPT:
        if (args.privateKeyFile.empty() || args.inputFile.empty() || args.outputFile.empty()) {
            throw invalid_argument("解密需要指定私钥文件、输入文件和输出文件路径");
        }
        break;
    }

    return args;
}

int main(int argc, char* argv[]) {
    try {
        // 解析命令行参数
        Args args = parseArgs(argc, argv);

        // 执行相应操作
        switch (args.opMode) {
        case GENERATE_KEYS:
            generateRSAKeys(args.keySize, args.publicKeyFile, args.privateKeyFile);
            break;
        case ENCRYPT:
            rsaEncrypt(args.publicKeyFile, args.inputFile, args.outputFile);
            break;
        case DECRYPT:
            rsaDecrypt(args.privateKeyFile, args.inputFile, args.outputFile);
            break;
        }

    }
    catch (const exception& e) {
        cerr << "错误: " << e.what() << endl;
        cerr << "使用 -h 或 --help 查看帮助信息" << endl;
        return 1;
    }

    return 0;
}
