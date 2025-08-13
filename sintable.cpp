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

// ֧�ֵ���������
enum CipherType {
    CAESAR,       // ��������
    AFFINE,       // ��������
    ATBASH,       // ���а�ϣ����
    SIMPLE_SUB    // ���滻����
};

// ����ģʽ
enum Mode {
    ENCRYPT,
    DECRYPT
};

// �����в����ṹ��
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
    // ȷ������Ϊ�Ǹ���
    a = std::abs(a);
    b = std::abs(b);

    // ��b��Ϊ0ʱ��ѭ������
    while (b != 0) {
        int temp = b;
        b = a % b; // ȡ����
        a = temp;
    }
    return a;
}

// ���������в���
Args parseArgs(int argc, char* argv[]) {
    Args args;
    args.mode = ENCRYPT; // Ĭ�ϼ���ģʽ
    args.cipher = CAESAR; // Ĭ�Ͽ�������
    args.inputIsFile = false;
    args.outputIsFile = false;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-m" || arg == "--mode") {
            if (i + 1 >= argc) throw invalid_argument("ȱ��ģʽ����ֵ");
            string mode = argv[++i];
            if (mode == "encrypt") args.mode = ENCRYPT;
            else if (mode == "decrypt") args.mode = DECRYPT;
            else throw invalid_argument("��Ч��ģʽ: " + mode);
        }
        else if (arg == "-c" || arg == "--cipher") {
            if (i + 1 >= argc) throw invalid_argument("ȱ���������Ͳ���ֵ");
            string cipher = argv[++i];
            if (cipher == "caesar") args.cipher = CAESAR;
            else if (cipher == "affine") args.cipher = AFFINE;
            else if (cipher == "atbash") args.cipher = ATBASH;
            else if (cipher == "simple") args.cipher = SIMPLE_SUB;
            else throw invalid_argument("��Ч����������: " + cipher);
        }
        else if (arg == "-k" || arg == "--key") {
            if (i + 1 >= argc) throw invalid_argument("ȱ����Կ����ֵ");
            args.key = argv[++i];
        }
        else if (arg == "-i" || arg == "--input") {
            if (i + 1 >= argc) throw invalid_argument("ȱ���������ֵ");
            args.input = argv[++i];
        }
        else if (arg == "-f" || arg == "--input-file") {
            if (i + 1 >= argc) throw invalid_argument("ȱ�������ļ�����ֵ");
            args.input = argv[++i];
            args.inputIsFile = true;
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) throw invalid_argument("ȱ���������ֵ");
            args.output = argv[++i];
            args.outputIsFile = true;
        }
        else if (arg == "-h" || arg == "--help") {
            cout << "��������ӽ��ܹ���" << endl;
            cout << "�÷�: " << argv[0] << " [ѡ��]" << endl;
            cout << "ѡ��:" << endl;
            cout << "  -m, --mode     ģʽ: encrypt(����) �� decrypt(����)��Ĭ��encrypt" << endl;
            cout << "  -c, --cipher   ��������: caesar(����), affine(����), atbash(���а�ϣ), simple(���滻)��Ĭ��caesar" << endl;
            cout << "  -k, --key      ��Կ�������������Ͳ�ͬ��ʽ��ͬ" << endl;
            cout << "                 ��������: ����ƫ����" << endl;
            cout << "                 ��������: ��������a��b���ö��ŷָ�(a������26����)" << endl;
            cout << "                 ���滻: 26����ĸ���û��ַ���" << endl;
            cout << "                 ���а�ϣ: ����Ҫ��Կ" << endl;
            cout << "  -i, --input    �����ַ���" << endl;
            cout << "  -f, --input-file �����ļ�·��" << endl;
            cout << "  -o, --output   ����ļ�·����Ĭ�����������̨" << endl;
            cout << "  -h, --help     ��ʾ������Ϣ" << endl;
            exit(0);
        }
        else {
            throw invalid_argument("��Ч�Ĳ���: " + arg);
        }
    }

    if (args.input.empty()) {
        throw invalid_argument("�����ṩ�������ݻ������ļ�");
    }

    // ��֤��Կ
    if (args.cipher == CAESAR) {
        if (args.key.empty()) {
            throw invalid_argument("����������Ҫ��Կ(ƫ����)");
        }
        try {
            stoi(args.key); // ����ת��Ϊ����
        }
        catch (...) {
            throw invalid_argument("����������Կ����������");
        }
    }
    else if (args.cipher == AFFINE) {
        if (args.key.empty()) {
            throw invalid_argument("����������Ҫ��Կ(a,b)");
        }
        size_t commaPos = args.key.find(',');
        if (commaPos == string::npos) {
            throw invalid_argument("����������Կ��ʽӦΪ\"a,b\"");
        }
        string aStr = args.key.substr(0, commaPos);
        string bStr = args.key.substr(commaPos + 1);
        try {
            int a = stoi(aStr);
            int b = stoi(bStr);
            // ���a�Ƿ���26����
            if (gcd(abs(a), 26) != 1) {
                throw invalid_argument("����������a������26����");
            }
        }
        catch (...) {
            throw invalid_argument("����������Կ��������������");
        }
    }
    else if (args.cipher == SIMPLE_SUB) {
        if (args.key.empty()) {
            throw invalid_argument("���滻������Ҫ��Կ");
        }
        if (args.key.length() != 26) {
            throw invalid_argument("���滻������Կ������26����ĸ���û�");
        }
        // ����Ƿ����������ĸ
        vector<bool> seen(26, false);
        for (char c : args.key) {
            if (!isalpha(c)) {
                throw invalid_argument("���滻������Կֻ�ܰ�����ĸ");
            }
            int idx = toupper(c) - 'A';
            if (seen[idx]) {
                throw invalid_argument("���滻������Կ���ܰ����ظ���ĸ");
            }
            seen[idx] = true;
        }
    }

    return args;
}

// ��ȡ�ļ�����
string readFile(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("�޷����ļ�: " + filename);
    }
    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// д���ļ�
void writeFile(const string& filename, const string& content) {
    ofstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("�޷���������ļ�: " + filename);
    }
    file << content;
}

// �����������
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
            ciphertext += c; // ����ĸ�ַ�����
        }
    }
    return ciphertext;
}

// �����������
string caesarDecrypt(const string& ciphertext, int shift) {
    return caesarEncrypt(ciphertext, 26 - (shift % 26));
}

// ��ģ��Ԫ
int modInverse(int a, int m) {
    a %= m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return 1; // Ӧ�ò���ִ�е������Ϊa��m����
}

// �����������
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
            ciphertext += c; // ����ĸ�ַ�����
        }
    }
    return ciphertext;
}

// �����������
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
            plaintext += c; // ����ĸ�ַ�����
        }
    }
    return plaintext;
}

// ���а�ϣ����ӽ���(�ӽ�����ͬ)
string atbashCipher(const string& text) {
    string result;
    for (char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            result += (char)(base + (25 - (c - base)));
        }
        else {
            result += c; // ����ĸ�ַ�����
        }
    }
    return result;
}

// ���滻�������
string simpleSubEncrypt(const string& plaintext, const string& key) {
    string ciphertext;
    // ����ӳ���: ������ĸ -> ������ĸ
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
            ciphertext += c; // ����ĸ�ַ�����
        }
    }
    return ciphertext;
}

// ���滻�������
string simpleSubDecrypt(const string& ciphertext, const string& key) {
    string plaintext;
    // ����ӳ���: ������ĸ -> ������ĸ
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
            plaintext += c; // ����ĸ�ַ�����
        }
    }
    return plaintext;
}

int main(int argc, char* argv[]) {
    try {
        // ���������в���
        Args args = parseArgs(argc, argv);

        // ��ȡ����
        string inputText;
        if (args.inputIsFile) {
            inputText = readFile(args.input);
        }
        else {
            inputText = args.input;
        }

        // ִ�мӽ��ܲ�������ʱ
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
            result = atbashCipher(inputText); // ���а�ϣ�ӽ�����ͬ
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

        // ������
        string output;

        // ���������Ϣ
        output += "��������: ";
        switch (args.cipher) {
        case CAESAR: output += "��������\n"; break;
        case AFFINE: output += "��������\n"; break;
        case ATBASH: output += "���а�ϣ����\n"; break;
        case SIMPLE_SUB: output += "���滻����\n"; break;
        }

        output += "����ģʽ: " + string(args.mode == ENCRYPT ? "����" : "����") + "\n";
        output += "��Կ: " + (args.cipher == ATBASH ? "��" : args.key) + "\n";
        output += "����: " + (args.mode == ENCRYPT ? inputText : result) + "\n";
        output += "����: " + (args.mode == ENCRYPT ? result : inputText) + "\n";
        output += "����ʱ��: " + to_string(duration.count()) + " ΢��\n";

        // ������ļ������̨
        if (args.outputIsFile) {
            writeFile(args.output, output);
            cout << "������ɣ�����ѱ��浽 " << args.output << endl;
        }
        else {
            cout << output << endl;
        }

    }
    catch (const exception& e) {
        cerr << "����: " << e.what() << endl;
        cerr << "ʹ�� -h �� --help �鿴������Ϣ" << endl;
        return 1;
    }

    return 0;
}
