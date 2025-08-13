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

// ���������Ͷ��壨ʹ��64λ�޷����������飬��λ��ǰ��
typedef vector<uint64_t> BigInt;

// ����ģʽ
enum OperationMode {
    GENERATE_KEYS,
    ENCRYPT,
    DECRYPT
};

// �����в����ṹ��
struct Args {
    OperationMode opMode;
    string publicKeyFile;    // ��Կ�ļ�
    string privateKeyFile;   // ˽Կ�ļ�
    string inputFile;        // �����ļ�
    string outputFile;       // ����ļ�
    int keySize;             // ��Կ���ȣ����أ�
};

// �����������
uint64_t generateRandom64() {
    static mt19937_64 rng(system_clock::now().time_since_epoch().count());
    return rng();
}

// �������Ƚϣ�a > b
bool greaterThan(const BigInt& a, const BigInt& b) {
    if (a.size() != b.size()) return a.size() > b.size();
    for (int i = a.size() - 1; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return false;
}

// �������Ƚϣ�a == b
bool equals(const BigInt& a, const BigInt& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// �������ӷ�
BigInt add(const BigInt& a, const BigInt& b) {
    BigInt result;
    uint64_t carry = 0;
    size_t maxSize = max(a.size(), b.size());

    for (size_t i = 0; i < maxSize || carry; ++i) {
        uint64_t aVal = (i < a.size()) ? a[i] : 0;
        uint64_t bVal = (i < b.size()) ? b[i] : 0;

        uint64_t sum = aVal + bVal + carry;
        carry = (sum < aVal) ? 1 : 0;  // ������
        result.push_back(sum);
    }

    return result;
}

// ����������������a >= b��
BigInt subtract(const BigInt& a, const BigInt& b) {
    BigInt result;
    uint64_t borrow = 0;

    for (size_t i = 0; i < a.size(); ++i) {
        uint64_t aVal = a[i];
        uint64_t bVal = (i < b.size()) ? b[i] : 0;

        aVal -= borrow;
        borrow = 0;

        if (aVal < bVal) {
            aVal += UINT64_MAX + 1;  // �����λ
            borrow = 1;
        }

        result.push_back(aVal - bVal);
    }

    // �Ƴ�ǰ����
    while (result.size() > 1 && result.back() == 0) {
        result.pop_back();
    }

    return result;
}

// �������˷�����64λ������
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

// �������˷�
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

    // �Ƴ�ǰ����
    while (result.size() > 1 && result.back() == 0) {
        result.pop_back();
    }

    return result;
}

// �����������������̺�������
pair<BigInt, BigInt> divide(const BigInt& a, const BigInt& b) {
    if (equals(b, BigInt{ 0 })) {
        throw runtime_error("���������");
    }

    if (greaterThan(b, a)) {
        return { BigInt{0}, a };
    }

    BigInt quotient;
    BigInt remainder;

    // �����λ��ʼ����
    for (int i = a.size() - 1; i >= 0; --i) {
        // ����ǰλ��ӵ�����
        remainder.insert(remainder.begin(), a[i]);

        // �Ƴ�ǰ����
        while (remainder.size() > 1 && remainder.back() == 0) {
            remainder.pop_back();
        }

        // ���㵱ǰλ����
        uint64_t q = 0;
        BigInt temp = b;

        // �ҵ�����qʹ��q*b <= remainder
        while (greaterThan(remainder, temp) || equals(remainder, temp)) {
            q++;
            temp = add(temp, b);
        }

        quotient.insert(quotient.begin(), q);

        // ��������
        if (q > 0) {
            temp = subtract(temp, b);  // ����һ��
            remainder = subtract(remainder, temp);
        }
    }

    // �Ƴ��̵�ǰ����
    while (quotient.size() > 1 && quotient.back() == 0) {
        quotient.pop_back();
    }

    return { quotient, remainder };
}

// ������ȡģ���������Ա�����ؼ��ֳ�ͻ��
BigInt bigMod(const BigInt& a, const BigInt& m) {
    return divide(a, m).second;
}

// ������ģ������ (base^exponent mod mod)
BigInt modPow(const BigInt& base, const BigInt& exponent, const BigInt& mod) {
    BigInt result = { 1 };
    BigInt currentBase = bigMod(base, mod);  // ʹ���������ĺ���
    BigInt currentExponent = exponent;

    while (!equals(currentExponent, BigInt{ 0 })) {
        // ���ָ�������������Ե�ǰ����
        if (currentExponent[0] % 2 == 1) {
            result = bigMod(multiply(result, currentBase), mod);  // ʹ���������ĺ���
        }

        // ָ������2
        currentExponent = divide(currentExponent, BigInt{ 2 }).first;

        // ����ƽ��
        currentBase = bigMod(multiply(currentBase, currentBase), mod);  // ʹ���������ĺ���
    }

    return result;
}

// �������Լ�� (GCD)
BigInt gcd(const BigInt& a, const BigInt& b) {
    if (equals(b, BigInt{ 0 })) {
        return a;
    }
    return gcd(b, bigMod(a, b));  // ʹ���������ĺ���
}

// ��չŷ������㷨������ax + by = gcd(a, b)
tuple<BigInt, BigInt, BigInt> extendedGcd(const BigInt& a, const BigInt& b) {
    if (equals(b, BigInt{ 0 })) {
        return { a, BigInt{1}, BigInt{0} };
    }

    auto [g, x, y] = extendedGcd(b, bigMod(a, b));  // ʹ���������ĺ���
    BigInt q = divide(a, b).first;
    BigInt newX = subtract(y, multiply(q, x));

    return { g, y, newX };
}

// ����ģ��Ԫ (a^-1 mod m)
BigInt modInverse(const BigInt& a, const BigInt& m) {
    auto [g, x, y] = extendedGcd(a, m);

    if (!equals(g, BigInt{ 1 })) {
        // ��Ԫ������
        return BigInt{ 0 };
    }
    else {
        // ȷ�����Ϊ����
        BigInt result = bigMod(x, m);  // ʹ���������ĺ���
        return result;
    }
}

// ��64λ����ת��Ϊ������
BigInt toBigInt(uint64_t num) {
    if (num == 0) return { 0 };
    return { num };
}

// ���ַ���ת��Ϊ������
BigInt stringToBigInt(const string& s) {
    BigInt result = { 0 };
    for (char c : s) {
        // ÿ�γ���10Ȼ����ϵ�ǰ����
        result = multiply(result, 10);
        result = add(result, toBigInt((uint64_t)(c - '0')));
    }
    return result;
}

// ��������ת��Ϊʮ�������ַ���
string bigIntToHex(const BigInt& num) {
    if (equals(num, BigInt{ 0 })) return "0";

    stringstream ss;
    ss << hex << setfill('0');

    // �������λ�����ܲ���Ҫǰ���㣩
    size_t last = num.size() - 1;
    ss << num[last];

    // ��������λ����Ҫǰ������ȷ��16��ʮ���������֣�
    for (int i = last - 1; i >= 0; --i) {
        ss << setw(16) << num[i];
    }

    return ss.str();
}

// ��ʮ�������ַ���ת��Ϊ������
BigInt hexToBigInt(const string& hexStr) {
    BigInt result = { 0 };
    string temp = hexStr;

    // ÿ�δ���16��ʮ���������֣�64λ��
    while (!temp.empty()) {
        size_t start = max(0, (int)temp.size() - 16);
        string chunk = temp.substr(start);
        temp = temp.substr(0, start);

        uint64_t val;
        stringstream ss;
        ss << hex << chunk;
        ss >> val;

        // �޸���ʹ����λ��������������������
        BigInt shifted = multiply(result, 0x100000000ULL);  // ����2^32
        shifted = multiply(shifted, 0x100000000ULL);        // �ٳ���2^32���ܹ�2^64
        result = add(shifted, toBigInt(val));
    }

    return result;
}

// Miller-Rabin���Բ���
bool isPrime(const BigInt& n, int iterations = 5) {
    // ����С���ֵ����
    if (equals(n, BigInt{ 2 }) || equals(n, BigInt{ 3 })) return true;
    if (equals(n, BigInt{ 1 }) || n[0] % 2 == 0) return false;

    // д��n-1 = d*2^s
    BigInt d = subtract(n, BigInt{ 1 });
    int s = 0;

    while (d[0] % 2 == 0) {
        d = divide(d, BigInt{ 2 }).first;
        s++;
    }

    // ���ж�β���
    for (int i = 0; i < iterations; ++i) {
        // ���������a��1 < a < n
        BigInt a;
        do {
            // ������n��С���Ƶ������
            a.clear();
            for (size_t j = 0; j < n.size(); ++j) {
                a.push_back(generateRandom64());
            }
            // ȷ��a < n
            a = bigMod(a, subtract(n, BigInt{ 2 }));  // ʹ���������ĺ���
            a = add(a, BigInt{ 1 });  // ȷ��a >= 1
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

// ����ָ�����س��ȵ��������
BigInt generatePrime(int bits) {
    if (bits < 8) {
        throw runtime_error("������������Ϊ8λ");
    }

    int num64Chunks = (bits + 63) / 64;
    BigInt p;

    do {
        p.clear();
        // ���������
        for (int i = 0; i < num64Chunks; ++i) {
            p.push_back(generateRandom64());
        }

        // �������λȷ������
        int highestBit = bits - 1;
        int highestChunk = highestBit / 64;
        int highestChunkBit = highestBit % 64;
        p[highestChunk] |= (uint64_t)1 << highestChunkBit;

        // ȷ��������
        p[0] |= 1;

    } while (!isPrime(p));

    return p;
}

// ����RSA��Կ��
void generateRSAKeys(int keySize, const string& publicKeyFile, const string& privateKeyFile) {
    cout << "����" << keySize << "λRSA��Կ��..." << endl;

    auto start = high_resolution_clock::now();

    // ��������������p��q
    cout << "��������p...";
    BigInt p = generatePrime(keySize / 2);
    cout << "���" << endl;

    cout << "��������q...";
    BigInt q = generatePrime(keySize / 2);
    cout << "���" << endl;

    // ����n = p * q
    BigInt n = multiply(p, q);
    cout << "����n = p * q ���" << endl;

    // ����ŷ��������(n) = (p-1) * (q-1)
    BigInt pMinus1 = subtract(p, BigInt{ 1 });
    BigInt qMinus1 = subtract(q, BigInt{ 1 });
    BigInt phi = multiply(pMinus1, qMinus1);
    cout << "�����(n) ���" << endl;

    // ѡ��Կָ��e��ͨ��ѡ��65537��
    BigInt e = stringToBigInt("65537");

    // ȷ��e���(n)����
    while (!equals(gcd(e, phi), BigInt{ 1 })) {
        e = add(e, BigInt{ 2 });  // ������һ������
    }
    cout << "ѡ��Կָ��e ���" << endl;

    // ����˽Կָ��d��e��ģ��
    BigInt d = modInverse(e, phi);
    if (equals(d, BigInt{ 0 })) {
        throw runtime_error("�޷�����˽Կָ��d��e�ͦ�(n)������");
    }
    cout << "����˽Կָ��d ���" << endl;

    // ���湫Կ (e, n)
    ofstream publicFile(publicKeyFile);
    if (!publicFile) {
        throw runtime_error("�޷�������Կ�ļ�: " + publicKeyFile);
    }
    publicFile << "e=" << bigIntToHex(e) << endl;
    publicFile << "n=" << bigIntToHex(n) << endl;
    publicFile.close();

    // ����˽Կ (d, n)
    ofstream privateFile(privateKeyFile);
    if (!privateFile) {
        throw runtime_error("�޷�����˽Կ�ļ�: " + privateKeyFile);
    }
    privateFile << "d=" << bigIntToHex(d) << endl;
    privateFile << "n=" << bigIntToHex(n) << endl;
    privateFile.close();

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<seconds>(end - start);

    cout << "��Կ��������ɣ���ʱ: " << duration.count() << "��" << endl;
    cout << "��Կ���浽: " << publicKeyFile << endl;
    cout << "˽Կ���浽: " << privateKeyFile << endl;
}

// ���ļ�������Կ
pair<BigInt, BigInt> loadKey(const string& filename) {
    ifstream file(filename);
    if (!file) {
        throw runtime_error("�޷�����Կ�ļ�: " + filename);
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
        throw runtime_error("��Կ�ļ���ʽ����ȷ: " + filename);
    }

    return { exp, mod };
}

// RSA����
void rsaEncrypt(const string& publicKeyFile, const string& inputFile, const string& outputFile) {
    cout << "ʹ��RSA�����ļ�..." << endl;

    // ���ع�Կ
    auto [e, n] = loadKey(publicKeyFile);
    cout << "���ع�Կ���" << endl;

    // ��ȡ�����ļ�
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        throw runtime_error("�޷��������ļ�: " + inputFile);
    }

    // ��ȡ�ļ���С
    inFile.seekg(0, ios::end);
    streamsize fileSize = inFile.tellg();
    inFile.seekg(0, ios::beg);

    // ����������Ŀ��С���ֽڣ�
    int maxBlockSize = (n.size() * 8 - 16) / 8;  // Ԥ��16λ�������
    cout << "������Ŀ��С: " << maxBlockSize << "�ֽ�" << endl;

    // ������ļ�
    ofstream outFile(outputFile, ios::binary);
    if (!outFile) {
        throw runtime_error("�޷���������ļ�: " + outputFile);
    }

    // д����С��Ϣ��ǰ4�ֽڣ�
    uint32_t blockSize = maxBlockSize;
    outFile.write(reinterpret_cast<const char*>(&blockSize), sizeof(blockSize));

    // д��ԭʼ�ļ���С��������8�ֽڣ�
    uint64_t originalSize = static_cast<uint64_t>(fileSize);
    outFile.write(reinterpret_cast<const char*>(&originalSize), sizeof(originalSize));

    // �ֿ����
    vector<uint8_t> buffer(maxBlockSize);
    streamsize bytesRead;
    size_t totalBlocks = 0;

    auto start = high_resolution_clock::now();

    // �޸�����ȷ��ȡ������ȡ��ȡ���ֽ���
    while (inFile.read(reinterpret_cast<char*>(buffer.data()), maxBlockSize)) {
        bytesRead = inFile.gcount();

        // ������������飬����������
        if (bytesRead < maxBlockSize) {
            for (streamsize i = bytesRead; i < maxBlockSize; ++i) {
                buffer[i] = static_cast<uint8_t>(generateRandom64() % 256);
            }
        }

        // ���ֽڻ�����ת��Ϊ������
        BigInt m;
        for (int i = maxBlockSize - 1; i >= 0; i -= 8) {
            uint64_t val = 0;
            for (int j = 0; j < 8 && i - j >= 0; ++j) {
                val |= static_cast<uint64_t>(buffer[i - j]) << (j * 8);
            }
            m.push_back(val);
        }

        // ����: c = m^e mod n
        BigInt c = modPow(m, e, n);

        // д����ܺ�Ŀ��С��4�ֽڣ�
        uint32_t encryptedSize = c.size() * 8;
        outFile.write(reinterpret_cast<const char*>(&encryptedSize), sizeof(encryptedSize));

        // д����ܺ������
        for (auto chunk : c) {
            outFile.write(reinterpret_cast<const char*>(&chunk), sizeof(chunk));
        }

        totalBlocks++;
        if (totalBlocks % 10 == 0) {
            cout << "�Ѽ��� " << totalBlocks << " ��..." << endl;
        }
    }

    // �������һ���������Ŀ�
    bytesRead = inFile.gcount();
    if (bytesRead > 0) {
        // ����������
        for (streamsize i = bytesRead; i < maxBlockSize; ++i) {
            buffer[i] = static_cast<uint8_t>(generateRandom64() % 256);
        }

        // ת��Ϊ������������
        BigInt m;
        for (int i = maxBlockSize - 1; i >= 0; i -= 8) {
            uint64_t val = 0;
            for (int j = 0; j < 8 && i - j >= 0; ++j) {
                val |= static_cast<uint64_t>(buffer[i - j]) << (j * 8);
            }
            m.push_back(val);
        }

        BigInt c = modPow(m, e, n);

        // д����ܽ��
        uint32_t encryptedSize = c.size() * 8;
        outFile.write(reinterpret_cast<const char*>(&encryptedSize), sizeof(encryptedSize));
        for (auto chunk : c) {
            outFile.write(reinterpret_cast<const char*>(&chunk), sizeof(chunk));
        }

        totalBlocks++;
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);

    cout << "������ɣ��� " << totalBlocks << " �飬��ʱ: " << duration.count() << "����" << endl;
    cout << "���ܽ�����浽: " << outputFile << endl;
}

// RSA����
void rsaDecrypt(const string& privateKeyFile, const string& inputFile, const string& outputFile) {
    cout << "ʹ��RSA�����ļ�..." << endl;

    // ����˽Կ
    auto [d, n] = loadKey(privateKeyFile);
    cout << "����˽Կ���" << endl;

    // �������ļ�
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        throw runtime_error("�޷��������ļ�: " + inputFile);
    }

    // ��ȡ���С��Ϣ
    uint32_t maxBlockSize;
    inFile.read(reinterpret_cast<char*>(&maxBlockSize), sizeof(maxBlockSize));

    // ��ȡԭʼ�ļ���С
    uint64_t originalSize;
    inFile.read(reinterpret_cast<char*>(&originalSize), sizeof(originalSize));

    // ������ļ�
    ofstream outFile(outputFile, ios::binary);
    if (!outFile) {
        throw runtime_error("�޷���������ļ�: " + outputFile);
    }

    // �ֿ����
    size_t totalBlocks = 0;
    uint64_t bytesWritten = 0;

    auto start = high_resolution_clock::now();

    while (inFile.peek() != EOF) {
        // ��ȡ���ܿ��С
        uint32_t encryptedSize;
        inFile.read(reinterpret_cast<char*>(&encryptedSize), sizeof(encryptedSize));

        int numChunks = (encryptedSize + 63) / 64;

        // ��ȡ��������
        BigInt c;
        for (int i = 0; i < numChunks; ++i) {
            uint64_t chunk;
            inFile.read(reinterpret_cast<char*>(&chunk), sizeof(chunk));
            c.push_back(chunk);
        }

        // ����: m = c^d mod n
        BigInt m = modPow(c, d, n);

        // ��������ת�����ֽڻ�����
        vector<uint8_t> buffer(maxBlockSize, 0);
        for (size_t i = 0; i < m.size() && i * 8 < maxBlockSize; ++i) {
            uint64_t val = m[i];
            for (int j = 0; j < 8 && i * 8 + j < maxBlockSize; ++j) {
                buffer[i * 8 + j] = static_cast<uint8_t>((val >> (j * 8)) & 0xFF);
            }
        }

        // ������Ҫд����ֽ��������һ���������maxBlockSize��
        streamsize writeSize = maxBlockSize;
        if (bytesWritten + writeSize > originalSize) {
            writeSize = originalSize - bytesWritten;
        }

        // д����ܺ������
        outFile.write(reinterpret_cast<const char*>(buffer.data()), writeSize);
        bytesWritten += writeSize;

        totalBlocks++;
        if (totalBlocks % 10 == 0) {
            cout << "�ѽ��� " << totalBlocks << " ��..." << endl;
        }
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);

    cout << "������ɣ��� " << totalBlocks << " �飬��ʱ: " << duration.count() << "����" << endl;
    cout << "���ܽ�����浽: " << outputFile << endl;
}

// ���������в���
Args parseArgs(int argc, char* argv[]) {
    Args args;
    args.opMode = GENERATE_KEYS;  // Ĭ��������Կ
    args.keySize = 2048;          // Ĭ����Կ����

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
            if (i + 1 >= argc) throw invalid_argument("ȱ����Կ���Ȳ���ֵ");
            args.keySize = stoi(argv[++i]);
            if (args.keySize < 512 || args.keySize % 512 != 0) {
                throw invalid_argument("��Կ���ȱ�����512�ı���������Ϊ512");
            }
        }
        else if (arg == "-p" || arg == "--public-key") {
            if (i + 1 >= argc) throw invalid_argument("ȱ�ٹ�Կ�ļ�����ֵ");
            args.publicKeyFile = argv[++i];
        }
        else if (arg == "-r" || arg == "--private-key") {
            if (i + 1 >= argc) throw invalid_argument("ȱ��˽Կ�ļ�����ֵ");
            args.privateKeyFile = argv[++i];
        }
        else if (arg == "-f" || arg == "--file") {
            if (i + 1 >= argc) throw invalid_argument("ȱ�������ļ�����ֵ");
            args.inputFile = argv[++i];
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) throw invalid_argument("ȱ������ļ�����ֵ");
            args.outputFile = argv[++i];
        }
        else if (arg == "-h" || arg == "--help") {
            cout << "RSA�ӽ��ܹ���" << endl;
            cout << "�÷�: " << argv[0] << " [ѡ��]" << endl;
            cout << "ѡ��:" << endl;
            cout << "  -g, --generate      ������Կ�ԣ�Ĭ�ϣ�" << endl;
            cout << "  -e, --encrypt       �����ļ�" << endl;
            cout << "  -d, --decrypt       �����ļ�" << endl;
            cout << "  -s, --key-size      ��Կ���ȣ�512, 1024, 2048, 4096����Ĭ��2048" << endl;
            cout << "  -p, --public-key    ��Կ�ļ�·��" << endl;
            cout << "  -r, --private-key   ˽Կ�ļ�·��" << endl;
            cout << "  -f, --file          �����ļ�·��" << endl;
            cout << "  -o, --output        ����ļ�·��" << endl;
            cout << "  -h, --help          ��ʾ������Ϣ" << endl;
            cout << endl;
            cout << "ʾ��:" << endl;
            cout << "  ������Կ��: " << argv[0] << " -g -s 2048 -p public.key -r private.key" << endl;
            cout << "  �����ļ�: " << argv[0] << " -e -p public.key -f plaintext.txt -o ciphertext.bin" << endl;
            cout << "  �����ļ�: " << argv[0] << " -d -r private.key -f ciphertext.bin -o plaintext.txt" << endl;
            exit(0);
        }
        else {
            throw invalid_argument("��Ч�Ĳ���: " + arg);
        }
    }

    // ��֤��Ҫ����
    switch (args.opMode) {
    case GENERATE_KEYS:
        if (args.publicKeyFile.empty() || args.privateKeyFile.empty()) {
            throw invalid_argument("������Կ����Ҫָ����Կ��˽Կ�ļ�·��");
        }
        break;
    case ENCRYPT:
        if (args.publicKeyFile.empty() || args.inputFile.empty() || args.outputFile.empty()) {
            throw invalid_argument("������Ҫָ����Կ�ļ��������ļ�������ļ�·��");
        }
        break;
    case DECRYPT:
        if (args.privateKeyFile.empty() || args.inputFile.empty() || args.outputFile.empty()) {
            throw invalid_argument("������Ҫָ��˽Կ�ļ��������ļ�������ļ�·��");
        }
        break;
    }

    return args;
}

int main(int argc, char* argv[]) {
    try {
        // ���������в���
        Args args = parseArgs(argc, argv);

        // ִ����Ӧ����
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
        cerr << "����: " << e.what() << endl;
        cerr << "ʹ�� -h �� --help �鿴������Ϣ" << endl;
        return 1;
    }

    return 0;
}
