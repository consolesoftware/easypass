#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <cctype>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <stdexcept>

using namespace std;
using namespace chrono;

// 支持的密码类型
enum CipherType {
    CAESAR,       // 凯撒密码
    AFFINE,       // 仿射密码
    ATBASH,       // 阿托巴希密码
    SIMPLE_SUB    // 简单替换密码
};

// 操作模式
enum Mode {
    ENCRYPT,
    DECRYPT
};

// 命令行参数结构体
struct Args {
    Mode mode;
    CipherType cipher;
    string key;
    string input;
    string output;
    bool inputIsFile;
    bool outputIsFile;
};

int gcd(int a, int b) {
    // 确保输入为非负数
    a = std::abs(a);
    b = std::abs(b);

    // 当b不为0时，循环计算
    while (b != 0) {
        int temp = b;
        b = a % b; // 取余数
        a = temp;
    }
    return a;
}

// 解析命令行参数
Args parseArgs(int argc, char* argv[]) {
    Args args;
    args.mode = ENCRYPT; // 默认加密模式
    args.cipher = CAESAR; // 默认凯撒密码
    args.inputIsFile = false;
    args.outputIsFile = false;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-m" || arg == "--mode") {
            if (i + 1 >= argc) throw invalid_argument("缺少模式参数值");
            string mode = argv[++i];
            if (mode == "encrypt") args.mode = ENCRYPT;
            else if (mode == "decrypt") args.mode = DECRYPT;
            else throw invalid_argument("无效的模式: " + mode);
        }
        else if (arg == "-c" || arg == "--cipher") {
            if (i + 1 >= argc) throw invalid_argument("缺少密码类型参数值");
            string cipher = argv[++i];
            if (cipher == "caesar") args.cipher = CAESAR;
            else if (cipher == "affine") args.cipher = AFFINE;
            else if (cipher == "atbash") args.cipher = ATBASH;
            else if (cipher == "simple") args.cipher = SIMPLE_SUB;
            else throw invalid_argument("无效的密码类型: " + cipher);
        }
        else if (arg == "-k" || arg == "--key") {
            if (i + 1 >= argc) throw invalid_argument("缺少密钥参数值");
            args.key = argv[++i];
        }
        else if (arg == "-i" || arg == "--input") {
            if (i + 1 >= argc) throw invalid_argument("缺少输入参数值");
            args.input = argv[++i];
        }
        else if (arg == "-f" || arg == "--input-file") {
            if (i + 1 >= argc) throw invalid_argument("缺少输入文件参数值");
            args.input = argv[++i];
            args.inputIsFile = true;
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) throw invalid_argument("缺少输出参数值");
            args.output = argv[++i];
            args.outputIsFile = true;
        }
        else if (arg == "-h" || arg == "--help") {
            cout << "单表密码加解密工具" << endl;
            cout << "用法: " << argv[0] << " [选项]" << endl;
            cout << "选项:" << endl;
            cout << "  -m, --mode     模式: encrypt(加密) 或 decrypt(解密)，默认encrypt" << endl;
            cout << "  -c, --cipher   密码类型: caesar(凯撒), affine(仿射), atbash(阿托巴希), simple(简单替换)，默认caesar" << endl;
            cout << "  -k, --key      密钥，根据密码类型不同格式不同" << endl;
            cout << "                 凯撒密码: 整数偏移量" << endl;
            cout << "                 仿射密码: 两个整数a和b，用逗号分隔(a必须与26互质)" << endl;
            cout << "                 简单替换: 26个字母的置换字符串" << endl;
            cout << "                 阿托巴希: 不需要密钥" << endl;
            cout << "  -i, --input    输入字符串" << endl;
            cout << "  -f, --input-file 输入文件路径" << endl;
            cout << "  -o, --output   输出文件路径，默认输出到控制台" << endl;
            cout << "  -h, --help     显示帮助信息" << endl;
            exit(0);
        }
        else {
            throw invalid_argument("无效的参数: " + arg);
        }
    }

    if (args.input.empty()) {
        throw invalid_argument("必须提供输入内容或输入文件");
    }

    // 验证密钥
    if (args.cipher == CAESAR) {
        if (args.key.empty()) {
            throw invalid_argument("凯撒密码需要密钥(偏移量)");
        }
        try {
            stoi(args.key); // 尝试转换为整数
        }
        catch (...) {
            throw invalid_argument("凯撒密码密钥必须是整数");
        }
    }
    else if (args.cipher == AFFINE) {
        if (args.key.empty()) {
            throw invalid_argument("仿射密码需要密钥(a,b)");
        }
        size_t commaPos = args.key.find(',');
        if (commaPos == string::npos) {
            throw invalid_argument("仿射密码密钥格式应为\"a,b\"");
        }
        string aStr = args.key.substr(0, commaPos);
        string bStr = args.key.substr(commaPos + 1);
        try {
            int a = stoi(aStr);
            int b = stoi(bStr);
            // 检查a是否与26互质
            if (gcd(abs(a), 26) != 1) {
                throw invalid_argument("仿射密码中a必须与26互质");
            }
        }
        catch (...) {
            throw invalid_argument("仿射密码密钥必须是两个整数");
        }
    }
    else if (args.cipher == SIMPLE_SUB) {
        if (args.key.empty()) {
            throw invalid_argument("简单替换密码需要密钥");
        }
        if (args.key.length() != 26) {
            throw invalid_argument("简单替换密码密钥必须是26个字母的置换");
        }
        // 检查是否包含所有字母
        vector<bool> seen(26, false);
        for (char c : args.key) {
            if (!isalpha(c)) {
                throw invalid_argument("简单替换密码密钥只能包含字母");
            }
            int idx = toupper(c) - 'A';
            if (seen[idx]) {
                throw invalid_argument("简单替换密码密钥不能包含重复字母");
            }
            seen[idx] = true;
        }
    }

    return args;
}

// 读取文件内容
string readFile(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("无法打开文件: " + filename);
    }
    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// 写入文件
void writeFile(const string& filename, const string& content) {
    ofstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("无法创建输出文件: " + filename);
    }
    file << content;
}

// 凯撒密码加密
string caesarEncrypt(const string& plaintext, int shift) {
    string ciphertext;
    shift %= 26;
    if (shift < 0) shift += 26;

    for (char c : plaintext) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            ciphertext += (char)((c - base + shift) % 26 + base);
        }
        else {
            ciphertext += c; // 非字母字符不变
        }
    }
    return ciphertext;
}

// 凯撒密码解密
string caesarDecrypt(const string& ciphertext, int shift) {
    return caesarEncrypt(ciphertext, 26 - (shift % 26));
}

// 求模逆元
int modInverse(int a, int m) {
    a %= m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return 1; // 应该不会执行到这里，因为a和m互质
}

// 仿射密码加密
string affineEncrypt(const string& plaintext, int a, int b) {
    string ciphertext;
    a %= 26;
    if (a < 0) a += 26;
    b %= 26;
    if (b < 0) b += 26;

    for (char c : plaintext) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            ciphertext += (char)(((a * (c - base) + b) % 26 + 26) % 26 + base);
        }
        else {
            ciphertext += c; // 非字母字符不变
        }
    }
    return ciphertext;
}

// 仿射密码解密
string affineDecrypt(const string& ciphertext, int a, int b) {
    string plaintext;
    a %= 26;
    if (a < 0) a += 26;
    b %= 26;
    if (b < 0) b += 26;

    int aInv = modInverse(a, 26);

    for (char c : ciphertext) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            plaintext += (char)(((aInv * ((c - base - b) % 26 + 26)) % 26) + base);
        }
        else {
            plaintext += c; // 非字母字符不变
        }
    }
    return plaintext;
}

// 阿托巴希密码加解密(加解密相同)
string atbashCipher(const string& text) {
    string result;
    for (char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            result += (char)(base + (25 - (c - base)));
        }
        else {
            result += c; // 非字母字符不变
        }
    }
    return result;
}

// 简单替换密码加密
string simpleSubEncrypt(const string& plaintext, const string& key) {
    string ciphertext;
    // 创建映射表: 明文字母 -> 密文字母
    map<char, char> encryptMap;

    for (int i = 0; i < 26; ++i) {
        encryptMap['A' + i] = toupper(key[i]);
        encryptMap['a' + i] = tolower(key[i]);
    }

    for (char c : plaintext) {
        if (isalpha(c)) {
            ciphertext += encryptMap[c];
        }
        else {
            ciphertext += c; // 非字母字符不变
        }
    }
    return ciphertext;
}

// 简单替换密码解密
string simpleSubDecrypt(const string& ciphertext, const string& key) {
    string plaintext;
    // 创建映射表: 密文字母 -> 明文字母
    map<char, char> decryptMap;

    for (int i = 0; i < 26; ++i) {
        decryptMap[toupper(key[i])] = 'A' + i;
        decryptMap[tolower(key[i])] = 'a' + i;
    }

    for (char c : ciphertext) {
        if (isalpha(c)) {
            plaintext += decryptMap[c];
        }
        else {
            plaintext += c; // 非字母字符不变
        }
    }
    return plaintext;
}

int main(int argc, char* argv[]) {
    try {
        // 解析命令行参数
        Args args = parseArgs(argc, argv);

        // 读取输入
        string inputText;
        if (args.inputIsFile) {
            inputText = readFile(args.input);
        }
        else {
            inputText = args.input;
        }

        // 执行加解密操作并计时
        string result;
        auto start = high_resolution_clock::now();

        switch (args.cipher) {
        case CAESAR: {
            int shift = stoi(args.key);
            if (args.mode == ENCRYPT) {
                result = caesarEncrypt(inputText, shift);
            }
            else {
                result = caesarDecrypt(inputText, shift);
            }
            break;
        }
        case AFFINE: {
            size_t commaPos = args.key.find(',');
            int a = stoi(args.key.substr(0, commaPos));
            int b = stoi(args.key.substr(commaPos + 1));
            if (args.mode == ENCRYPT) {
                result = affineEncrypt(inputText, a, b);
            }
            else {
                result = affineDecrypt(inputText, a, b);
            }
            break;
        }
        case ATBASH: {
            result = atbashCipher(inputText); // 阿托巴希加解密相同
            break;
        }
        case SIMPLE_SUB: {
            if (args.mode == ENCRYPT) {
                result = simpleSubEncrypt(inputText, args.key);
            }
            else {
                result = simpleSubDecrypt(inputText, args.key);
            }
            break;
        }
        }

        auto end = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end - start);

        // 输出结果
        string output;

        // 构建输出信息
        output += "密码类型: ";
        switch (args.cipher) {
        case CAESAR: output += "凯撒密码\n"; break;
        case AFFINE: output += "仿射密码\n"; break;
        case ATBASH: output += "阿托巴希密码\n"; break;
        case SIMPLE_SUB: output += "简单替换密码\n"; break;
        }

        output += "操作模式: " + string(args.mode == ENCRYPT ? "加密" : "解密") + "\n";
        output += "密钥: " + (args.cipher == ATBASH ? "无" : args.key) + "\n";
        output += "明文: " + (args.mode == ENCRYPT ? inputText : result) + "\n";
        output += "密文: " + (args.mode == ENCRYPT ? result : inputText) + "\n";
        output += "处理时间: " + to_string(duration.count()) + " 微秒\n";

        // 输出到文件或控制台
        if (args.outputIsFile) {
            writeFile(args.output, output);
            cout << "操作完成，结果已保存到 " << args.output << endl;
        }
        else {
            cout << output << endl;
        }

    }
    catch (const exception& e) {
        cerr << "错误: " << e.what() << endl;
        cerr << "使用 -h 或 --help 查看帮助信息" << endl;
        return 1;
    }

    return 0;
}
