#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <chrono>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <algorithm>

using namespace std;
using namespace chrono;

// 支持的多表密码类型
enum CipherType {
    VIGENERE,      // 维吉尼亚密码
    BEAUFORT,      // 博福特密码
    AUTO_KEY       // 自动密钥密码
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

// 解析命令行参数
Args parseArgs(int argc, char* argv[]) {
    Args args;
    args.mode = ENCRYPT; // 默认加密模式
    args.cipher = VIGENERE; // 默认维吉尼亚密码
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
            if (cipher == "vigenere") args.cipher = VIGENERE;
            else if (cipher == "beaufort") args.cipher = BEAUFORT;
            else if (cipher == "auto") args.cipher = AUTO_KEY;
            else throw invalid_argument("无效的密码类型: " + cipher);
        }
        else if (arg == "-k" || arg == "--key") {
            if (i + 1 >= argc) throw invalid_argument("缺少密钥参数值");
            args.key = argv[++i];
            // 验证密钥仅包含字母
            for (char c : args.key) {
                if (!isalpha(c)) {
                    throw invalid_argument("密钥只能包含字母");
                }
            }
            if (args.key.empty()) {
                throw invalid_argument("密钥不能为空");
            }
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
            cout << "多表密码加解密工具" << endl;
            cout << "用法: " << argv[0] << " [选项]" << endl;
            cout << "选项:" << endl;
            cout << "  -m, --mode     模式: encrypt(加密) 或 decrypt(解密)，默认encrypt" << endl;
            cout << "  -c, --cipher   密码类型: vigenere(维吉尼亚), beaufort(博福特), auto(自动密钥)，默认vigenere" << endl;
            cout << "  -k, --key      密钥，必须为字母字符串" << endl;
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

// 处理密钥，生成与明文长度匹配的密钥序列（仅包含字母）
string processKey(const string& key, const string& text, Mode mode, CipherType cipher) {
    string processedKey;
    // 首先处理原始密钥，转换为大写
    for (char c : key) {
        processedKey += toupper(c);
    }

    // 对于自动密钥密码，加密时密钥是原始密钥+明文
    if (cipher == AUTO_KEY && mode == ENCRYPT) {
        string plaintextUpper;
        for (char c : text) {
            if (isalpha(c)) {
                plaintextUpper += toupper(c);
            }
        }
        processedKey += plaintextUpper;
    }

    // 生成与文本中字母数量相同长度的密钥
    string textLetters;
    for (char c : text) {
        if (isalpha(c)) {
            textLetters += c;
        }
    }

    string extendedKey;
    int keyIndex = 0;
    int keyLength = processedKey.length();

    for (size_t i = 0; i < textLetters.length(); ++i) {
        extendedKey += processedKey[keyIndex % keyLength];
        keyIndex++;

        // 对于自动密钥密码，解密时动态生成密钥
        if (cipher == AUTO_KEY && mode == DECRYPT && i < textLetters.length() - 1) {
            // 解密时，使用已解密的字符作为后续密钥
            extendedKey += toupper(textLetters[i]);
            keyLength++;
        }
    }

    return extendedKey;
}

// 维吉尼亚密码加密
string vigenereEncrypt(const string& plaintext, const string& key) {
    string ciphertext;
    string extendedKey = processKey(key, plaintext, ENCRYPT, VIGENERE);
    int keyIndex = 0;

    for (char c : plaintext) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int shift = extendedKey[keyIndex] - 'A';
            ciphertext += (char)((c - base + shift) % 26 + base);
            keyIndex++;
        }
        else {
            ciphertext += c; // 非字母字符不变
        }
    }

    return ciphertext;
}

// 维吉尼亚密码解密
string vigenereDecrypt(const string& ciphertext, const string& key) {
    string plaintext;
    string extendedKey = processKey(key, ciphertext, DECRYPT, VIGENERE);
    int keyIndex = 0;

    for (char c : ciphertext) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int shift = extendedKey[keyIndex] - 'A';
            plaintext += (char)(((c - base - shift) % 26 + 26) % 26 + base);
            keyIndex++;
        }
        else {
            plaintext += c; // 非字母字符不变
        }
    }

    return plaintext;
}

// 博福特密码加密/解密（博福特密码的加密和解密算法相同）
string beaufortCipher(const string& text, const string& key, Mode mode) {
    string result;
    string extendedKey = processKey(key, text, mode, BEAUFORT);
    int keyIndex = 0;

    for (char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int keyShift = extendedKey[keyIndex] - 'A';
            int textVal = c - base;

            // 博福特密码公式：C = (K - P) mod 26
            int resultVal = (keyShift - textVal + 26) % 26;
            result += (char)(resultVal + base);
            keyIndex++;
        }
        else {
            result += c; // 非字母字符不变
        }
    }

    return result;
}

// 自动密钥密码加密
string autoKeyEncrypt(const string& plaintext, const string& key) {
    string ciphertext;
    string extendedKey = processKey(key, plaintext, ENCRYPT, AUTO_KEY);
    int keyIndex = 0;

    for (char c : plaintext) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int shift = extendedKey[keyIndex] - 'A';
            ciphertext += (char)((c - base + shift) % 26 + base);
            keyIndex++;
        }
        else {
            ciphertext += c; // 非字母字符不变
        }
    }

    return ciphertext;
}

// 自动密钥密码解密
string autoKeyDecrypt(const string& ciphertext, const string& key) {
    string plaintext;
    string extendedKey = processKey(key, ciphertext, DECRYPT, AUTO_KEY);
    int keyIndex = 0;

    for (char c : ciphertext) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int shift = extendedKey[keyIndex] - 'A';
            plaintext += (char)(((c - base - shift) % 26 + 26) % 26 + base);
            keyIndex++;
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
        case VIGENERE:
            if (args.mode == ENCRYPT) {
                result = vigenereEncrypt(inputText, args.key);
            }
            else {
                result = vigenereDecrypt(inputText, args.key);
            }
            break;
        case BEAUFORT:
            // 博福特密码加解密算法相同
            result = beaufortCipher(inputText, args.key, args.mode);
            break;
        case AUTO_KEY:
            if (args.mode == ENCRYPT) {
                result = autoKeyEncrypt(inputText, args.key);
            }
            else {
                result = autoKeyDecrypt(inputText, args.key);
            }
            break;
        }

        auto end = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(end - start);

        // 构建输出信息
        string output;

        output += "密码类型: ";
        switch (args.cipher) {
        case VIGENERE: output += "维吉尼亚密码\n"; break;
        case BEAUFORT: output += "博福特密码\n"; break;
        case AUTO_KEY: output += "自动密钥密码\n"; break;
        }

        output += "操作模式: " + string(args.mode == ENCRYPT ? "加密" : "解密") + "\n";
        output += "密钥: " + args.key + "\n";
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
