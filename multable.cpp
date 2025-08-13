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

// ֧�ֵĶ����������
enum CipherType {
    VIGENERE,      // ά����������
    BEAUFORT,      // ����������
    AUTO_KEY       // �Զ���Կ����
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

// ���������в���
Args parseArgs(int argc, char* argv[]) {
    Args args;
    args.mode = ENCRYPT; // Ĭ�ϼ���ģʽ
    args.cipher = VIGENERE; // Ĭ��ά����������
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
            if (cipher == "vigenere") args.cipher = VIGENERE;
            else if (cipher == "beaufort") args.cipher = BEAUFORT;
            else if (cipher == "auto") args.cipher = AUTO_KEY;
            else throw invalid_argument("��Ч����������: " + cipher);
        }
        else if (arg == "-k" || arg == "--key") {
            if (i + 1 >= argc) throw invalid_argument("ȱ����Կ����ֵ");
            args.key = argv[++i];
            // ��֤��Կ��������ĸ
            for (char c : args.key) {
                if (!isalpha(c)) {
                    throw invalid_argument("��Կֻ�ܰ�����ĸ");
                }
            }
            if (args.key.empty()) {
                throw invalid_argument("��Կ����Ϊ��");
            }
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
            cout << "�������ӽ��ܹ���" << endl;
            cout << "�÷�: " << argv[0] << " [ѡ��]" << endl;
            cout << "ѡ��:" << endl;
            cout << "  -m, --mode     ģʽ: encrypt(����) �� decrypt(����)��Ĭ��encrypt" << endl;
            cout << "  -c, --cipher   ��������: vigenere(ά������), beaufort(������), auto(�Զ���Կ)��Ĭ��vigenere" << endl;
            cout << "  -k, --key      ��Կ������Ϊ��ĸ�ַ���" << endl;
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

// ������Կ�����������ĳ���ƥ�����Կ���У���������ĸ��
string processKey(const string& key, const string& text, Mode mode, CipherType cipher) {
    string processedKey;
    // ���ȴ���ԭʼ��Կ��ת��Ϊ��д
    for (char c : key) {
        processedKey += toupper(c);
    }

    // �����Զ���Կ���룬����ʱ��Կ��ԭʼ��Կ+����
    if (cipher == AUTO_KEY && mode == ENCRYPT) {
        string plaintextUpper;
        for (char c : text) {
            if (isalpha(c)) {
                plaintextUpper += toupper(c);
            }
        }
        processedKey += plaintextUpper;
    }

    // �������ı�����ĸ������ͬ���ȵ���Կ
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

        // �����Զ���Կ���룬����ʱ��̬������Կ
        if (cipher == AUTO_KEY && mode == DECRYPT && i < textLetters.length() - 1) {
            // ����ʱ��ʹ���ѽ��ܵ��ַ���Ϊ������Կ
            extendedKey += toupper(textLetters[i]);
            keyLength++;
        }
    }

    return extendedKey;
}

// ά�������������
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
            ciphertext += c; // ����ĸ�ַ�����
        }
    }

    return ciphertext;
}

// ά�������������
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
            plaintext += c; // ����ĸ�ַ�����
        }
    }

    return plaintext;
}

// �������������/���ܣ�����������ļ��ܺͽ����㷨��ͬ��
string beaufortCipher(const string& text, const string& key, Mode mode) {
    string result;
    string extendedKey = processKey(key, text, mode, BEAUFORT);
    int keyIndex = 0;

    for (char c : text) {
        if (isalpha(c)) {
            char base = isupper(c) ? 'A' : 'a';
            int keyShift = extendedKey[keyIndex] - 'A';
            int textVal = c - base;

            // ���������빫ʽ��C = (K - P) mod 26
            int resultVal = (keyShift - textVal + 26) % 26;
            result += (char)(resultVal + base);
            keyIndex++;
        }
        else {
            result += c; // ����ĸ�ַ�����
        }
    }

    return result;
}

// �Զ���Կ�������
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
            ciphertext += c; // ����ĸ�ַ�����
        }
    }

    return ciphertext;
}

// �Զ���Կ�������
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
        case VIGENERE:
            if (args.mode == ENCRYPT) {
                result = vigenereEncrypt(inputText, args.key);
            }
            else {
                result = vigenereDecrypt(inputText, args.key);
            }
            break;
        case BEAUFORT:
            // ����������ӽ����㷨��ͬ
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

        // ���������Ϣ
        string output;

        output += "��������: ";
        switch (args.cipher) {
        case VIGENERE: output += "ά����������\n"; break;
        case BEAUFORT: output += "����������\n"; break;
        case AUTO_KEY: output += "�Զ���Կ����\n"; break;
        }

        output += "����ģʽ: " + string(args.mode == ENCRYPT ? "����" : "����") + "\n";
        output += "��Կ: " + args.key + "\n";
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
