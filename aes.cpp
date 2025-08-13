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

// AES֧�ֵ���Կ����
enum KeyLength {
    AES_128,  // 128λ��Կ
    AES_192,  // 192λ��Կ
    AES_256   // 256λ��Կ
};

// AES����ģʽ
enum AESMode {
    ECB,    // �������뱾ģʽ
    CBC,    // �����������ģʽ
    CFB,    // ���뷴��ģʽ
    OFB,    // �������ģʽ
    CTR     // ������ģʽ
};

// ����ģʽ
enum OperationMode {
    ENCRYPT,
    DECRYPT
};

// �����в����ṹ��
struct Args {
    OperationMode opMode;
    AESMode aesMode;
    KeyLength keyLen;
    string key;       // ��Կ
    string iv;        // ��ʼ������
    string inputFile;
    string outputFile;
};

// AES���� - ����
const int ROUNDS[3] = { 10, 12, 14 }; // 128, 192, 256λ��Կ��Ӧ������

// S��
const uint8_t S_BOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// ��S��
const uint8_t INV_S_BOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon - �ֳ���
const uint32_t RCON[15] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000,
    0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000
};

// ���ߺ��������ֽ����
void xorBytes(uint8_t* dest, const uint8_t* src, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        dest[i] ^= src[i];
    }
}

// ���ߺ�����S���滻
void subBytes(uint8_t* state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = S_BOX[state[i]];
    }
}

// ���ߺ�������S���滻
void invSubBytes(uint8_t* state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = INV_S_BOX[state[i]];
    }
}

// ���ߺ���������λ
void shiftRows(uint8_t* state) {
    // �ڶ�������1λ
    uint8_t temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // ����������2λ
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // ����������3λ
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

// ���ߺ�����������λ
void invShiftRows(uint8_t* state) {
    // �ڶ�������1λ
    uint8_t temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // ����������2λ
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // ����������3λ
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// ������GF(2^8)�˷�
uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return p;
}

// ���ߺ������л��
void mixColumns(uint8_t* state) {
    uint8_t temp[16];

    for (int i = 0; i < 4; i++) {
        int col = i * 4;
        temp[col] = (uint8_t)(gmul(2, state[col]) ^ gmul(3, state[col + 1]) ^ state[col + 2] ^ state[col + 3]);
        temp[col + 1] = (uint8_t)(state[col] ^ gmul(2, state[col + 1]) ^ gmul(3, state[col + 2]) ^ state[col + 3]);
        temp[col + 2] = (uint8_t)(state[col] ^ state[col + 1] ^ gmul(2, state[col + 2]) ^ gmul(3, state[col + 3]));
        temp[col + 3] = (uint8_t)(gmul(3, state[col]) ^ state[col + 1] ^ state[col + 2] ^ gmul(2, state[col + 3]));
    }

    memcpy(state, temp, 16);
}

// ���ߺ��������л��
void invMixColumns(uint8_t* state) {
    uint8_t temp[16];

    for (int i = 0; i < 4; i++) {
        int col = i * 4;
        temp[col] = (uint8_t)(gmul(0x0e, state[col]) ^ gmul(0x0b, state[col + 1]) ^ gmul(0x0d, state[col + 2]) ^ gmul(0x09, state[col + 3]));
        temp[col + 1] = (uint8_t)(gmul(0x09, state[col]) ^ gmul(0x0e, state[col + 1]) ^ gmul(0x0b, state[col + 2]) ^ gmul(0x0d, state[col + 3]));
        temp[col + 2] = (uint8_t)(gmul(0x0d, state[col]) ^ gmul(0x09, state[col + 1]) ^ gmul(0x0e, state[col + 2]) ^ gmul(0x0b, state[col + 3]));
        temp[col + 3] = (uint8_t)(gmul(0x0b, state[col]) ^ gmul(0x0d, state[col + 1]) ^ gmul(0x09, state[col + 2]) ^ gmul(0x0e, state[col + 3]));
    }

    memcpy(state, temp, 16);
}

// ��Կ��չ����
void keyExpansion(const uint8_t* key, uint8_t* w, KeyLength keyLen) {
    int Nk = (keyLen == AES_128) ? 4 : (keyLen == AES_192) ? 6 : 8;
    int Nr = ROUNDS[keyLen];
    int i = 0;

    // ����ԭʼ��Կ����չ��Կ��ǰNk����
    while (i < Nk) {
        w[4 * i] = key[4 * i];
        w[4 * i + 1] = key[4 * i + 1];
        w[4 * i + 2] = key[4 * i + 2];
        w[4 * i + 3] = key[4 * i + 3];
        i++;
    }

    i = Nk;
    uint8_t temp[4];

    while (i < 4 * (Nr + 1)) {
        // ��ʱ�����洢ǰһ����
        temp[0] = w[4 * (i - 1)];
        temp[1] = w[4 * (i - 1) + 1];
        temp[2] = w[4 * (i - 1) + 2];
        temp[3] = w[4 * (i - 1) + 3];

        // ÿNk����ִ��һ��RotWord��SubWord
        if (i % Nk == 0) {
            // RotWord: ѭ������һ���ֽ�
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord: ��ÿ���ֽ�Ӧ��S��
            for (int j = 0; j < 4; j++) {
                temp[j] = S_BOX[temp[j]];
            }

            // ���ֳ������
            temp[0] ^= (RCON[i / Nk] >> 24) & 0xFF;
        }
        // ����AES-256��ÿNk+4���ֶ���ִ��һ��SubWord
        else if (keyLen == AES_256 && i % Nk == 4) {
            for (int j = 0; j < 4; j++) {
                temp[j] = S_BOX[temp[j]];
            }
        }

        // ������չ��Կ
        w[4 * i] = w[4 * (i - Nk)] ^ temp[0];
        w[4 * i + 1] = w[4 * (i - Nk) + 1] ^ temp[1];
        w[4 * i + 2] = w[4 * (i - Nk) + 2] ^ temp[2];
        w[4 * i + 3] = w[4 * (i - Nk) + 3] ^ temp[3];

        i++;
    }
}

// ����Կ��
void addRoundKey(uint8_t* state, const uint8_t* roundKey) {
    xorBytes(state, roundKey, 16);
}

// AES�������
void aesEncryptBlock(uint8_t* state, const uint8_t* w, KeyLength keyLen) {
    int Nr = ROUNDS[keyLen];

    // ��ʼ����Կ��
    addRoundKey(state, w);

    // ������ѭ��
    for (int round = 1; round < Nr; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, w + round * 16);
    }

    // ���һ�֣�û���л�ϣ�
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, w + Nr * 16);
}

// AES�������
void aesDecryptBlock(uint8_t* state, const uint8_t* w, KeyLength keyLen) {
    int Nr = ROUNDS[keyLen];

    // ��ʼ����Կ�ӣ�ʹ�����һ�ֵ���Կ��
    addRoundKey(state, w + Nr * 16);

    // ������ѭ��
    for (int round = Nr - 1; round > 0; round--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, w + round * 16);
        invMixColumns(state);
    }

    // ���һ�֣�û�����л�ϣ�
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, w);
}

// ���������в���
Args parseArgs(int argc, char* argv[]) {
    Args args;
    args.opMode = ENCRYPT; // Ĭ�ϼ���
    args.aesMode = ECB;    // Ĭ��ECBģʽ
    args.keyLen = AES_128; // Ĭ��128λ��Կ

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-m" || arg == "--mode") {
            if (i + 1 >= argc) throw invalid_argument("ȱ��ģʽ����ֵ");
            string mode = argv[++i];
            if (mode == "encrypt") args.opMode = ENCRYPT;
            else if (mode == "decrypt") args.opMode = DECRYPT;
            else throw invalid_argument("��Ч��ģʽ: " + mode);
        }
        else if (arg == "-a" || arg == "--aes-mode") {
            if (i + 1 >= argc) throw invalid_argument("ȱ��AESģʽ����ֵ");
            string mode = argv[++i];
            if (mode == "ecb") args.aesMode = ECB;
            else if (mode == "cbc") args.aesMode = CBC;
            else if (mode == "cfb") args.aesMode = CFB;
            else if (mode == "ofb") args.aesMode = OFB;
            else if (mode == "ctr") args.aesMode = CTR;
            else throw invalid_argument("��Ч��AESģʽ: " + mode);
        }
        else if (arg == "-l" || arg == "--key-length") {
            if (i + 1 >= argc) throw invalid_argument("ȱ����Կ���Ȳ���ֵ");
            string len = argv[++i];
            if (len == "128") args.keyLen = AES_128;
            else if (len == "192") args.keyLen = AES_192;
            else if (len == "256") args.keyLen = AES_256;
            else throw invalid_argument("��Ч����Կ����: " + len);
        }
        else if (arg == "-k" || arg == "--key") {
            if (i + 1 >= argc) throw invalid_argument("ȱ����Կ����ֵ");
            args.key = argv[++i];
            int keySize = (args.keyLen == AES_128) ? 16 : (args.keyLen == AES_192) ? 24 : 32;
            if (args.key.length() != keySize) {
                throw invalid_argument("��Կ������" + to_string(keySize) + "���ַ�");
            }
        }
        else if (arg == "-i" || arg == "--iv") {
            if (i + 1 >= argc) throw invalid_argument("ȱ�ٳ�ʼ����������ֵ");
            args.iv = argv[++i];
            if (args.iv.length() != 16) {
                throw invalid_argument("��ʼ������������16���ַ�");
            }
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
            cout << "AES�ӽ��ܹ���" << endl;
            cout << "�÷�: " << argv[0] << " [ѡ��]" << endl;
            cout << "ѡ��:" << endl;
            cout << "  -m, --mode       ģʽ: encrypt(����) �� decrypt(����)��Ĭ��encrypt" << endl;
            cout << "  -a, --aes-mode   AES����ģʽ: ecb, cbc, cfb, ofb, ctr��Ĭ��ecb" << endl;
            cout << "  -l, --key-length ��Կ����: 128, 192, 256��Ĭ��128" << endl;
            cout << "  -k, --key        ��Կ��������";
            cout << " 16(AES-128), 24(AES-192) �� 32(AES-256) ���ַ�" << endl;
            cout << "  -i, --iv         ��ʼ��������������16���ַ�(CBC/CFB/OFB/CTRģʽ��Ҫ)" << endl;
            cout << "  -f, --file       �����ļ�·��" << endl;
            cout << "  -o, --output     ����ļ�·��" << endl;
            cout << "  -h, --help       ��ʾ������Ϣ" << endl;
            exit(0);
        }
        else {
            throw invalid_argument("��Ч�Ĳ���: " + arg);
        }
    }

    // ��֤��Ҫ����
    if (args.inputFile.empty()) {
        throw invalid_argument("�����ṩ�����ļ�");
    }
    if (args.outputFile.empty()) {
        throw invalid_argument("�����ṩ����ļ�");
    }
    if (args.key.empty()) {
        throw invalid_argument("�����ṩ��Կ");
    }

    // ��֤��Կ����
    int keySize = (args.keyLen == AES_128) ? 16 : (args.keyLen == AES_192) ? 24 : 32;
    if (args.key.length() != keySize) {
        throw invalid_argument("��Կ������" + to_string(keySize) + "���ַ�");
    }

    // ��֤IV
    if ((args.aesMode == CBC || args.aesMode == CFB || args.aesMode == OFB || args.aesMode == CTR) && args.iv.empty()) {
        throw invalid_argument("CBC/CFB/OFB/CTRģʽ��Ҫ��ʼ������");
    }
    if (!args.iv.empty() && args.iv.length() != 16) {
        throw invalid_argument("��ʼ������������16���ַ�");
    }

    return args;
}

// ��ȡ�ļ�����
vector<uint8_t> readFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("�޷����ļ�: " + filename);
    }

    // ��ȡ�ļ���С
    file.seekg(0, ios::end);
    size_t size = file.tellg();
    file.seekg(0, ios::beg);

    // ��ȡ�ļ�����
    vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);

    return data;
}

// д���ļ�
void writeFile(const string& filename, const vector<uint8_t>& data) {
    ofstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("�޷���������ļ�: " + filename);
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// ������䣨PKCS#7��
vector<uint8_t> addPadding(const vector<uint8_t>& data) {
    size_t blockSize = 16;
    size_t paddingSize = blockSize - (data.size() % blockSize);
    vector<uint8_t> padded = data;

    for (size_t i = 0; i < paddingSize; i++) {
        padded.push_back(static_cast<uint8_t>(paddingSize));
    }

    return padded;
}

// �Ƴ����
vector<uint8_t> removePadding(const vector<uint8_t>& data) {
    if (data.empty()) {
        return data;
    }

    size_t paddingSize = data.back();
    if (paddingSize > data.size() || paddingSize > 16) {
        throw runtime_error("��Ч�����");
    }

    return vector<uint8_t>(data.begin(), data.end() - paddingSize);
}

// ECBģʽ����
vector<uint8_t> ecbEncrypt(const vector<uint8_t>& data, const uint8_t* w, KeyLength keyLen) {
    vector<uint8_t> padded = addPadding(data);
    vector<uint8_t> result;
    result.reserve(padded.size());

    uint8_t block[16];

    // ���鴦��
    for (size_t i = 0; i < padded.size(); i += 16) {
        // �������ݵ��飨�޸����Ͳ�ƥ�����⣩
        memset(block, 0, 16);
        size_t copySize = min(static_cast<size_t>(16), padded.size() - i);
        memcpy(block, &padded[i], copySize);

        // ���ܿ�
        aesEncryptBlock(block, w, keyLen);

        // �����ܺ�Ŀ���ӵ����
        result.insert(result.end(), block, block + 16);
    }

    return result;
}

// ECBģʽ����
vector<uint8_t> ecbDecrypt(const vector<uint8_t>& data, const uint8_t* w, KeyLength keyLen) {
    if (data.size() % 16 != 0) {
        throw runtime_error("�������ݳ��ȱ�����16�ı���");
    }

    vector<uint8_t> result;
    result.reserve(data.size());

    uint8_t block[16];

    // ���鴦��
    for (size_t i = 0; i < data.size(); i += 16) {
        // �������ݵ���
        memcpy(block, &data[i], 16);

        // ���ܿ�
        aesDecryptBlock(block, w, keyLen);

        // �����ܺ�Ŀ���ӵ����
        result.insert(result.end(), block, block + 16);
    }

    // �Ƴ����
    return removePadding(result);
}

// CBCģʽ����
vector<uint8_t> cbcEncrypt(const vector<uint8_t>& data, const uint8_t* w, KeyLength keyLen, const uint8_t* iv) {
    vector<uint8_t> padded = addPadding(data);
    vector<uint8_t> result;
    result.reserve(padded.size());

    uint8_t block[16];
    uint8_t prevBlock[16];
    memcpy(prevBlock, iv, 16);

    // ���鴦��
    for (size_t i = 0; i < padded.size(); i += 16) {
        // �������ݵ��鲢��ǰһ������޸����Ͳ�ƥ�����⣩
        memset(block, 0, 16);
        size_t copySize = min(static_cast<size_t>(16), padded.size() - i);
        memcpy(block, &padded[i], copySize);
        xorBytes(block, prevBlock, 16);

        // ���ܿ�
        aesEncryptBlock(block, w, keyLen);
        memcpy(prevBlock, block, 16);

        // �����ܺ�Ŀ���ӵ����
        result.insert(result.end(), block, block + 16);
    }

    return result;
}

// CBCģʽ����
vector<uint8_t> cbcDecrypt(const vector<uint8_t>& data, const uint8_t* w, KeyLength keyLen, const uint8_t* iv) {
    if (data.size() % 16 != 0) {
        throw runtime_error("�������ݳ��ȱ�����16�ı���");
    }

    vector<uint8_t> result;
    result.reserve(data.size());

    uint8_t block[16];
    uint8_t prevBlock[16];
    uint8_t decryptedBlock[16];

    memcpy(prevBlock, iv, 16);

    // ���鴦��
    for (size_t i = 0; i < data.size(); i += 16) {
        // �������ݵ���
        memcpy(block, &data[i], 16);

        // ���ܿ�
        memcpy(decryptedBlock, block, 16);
        aesDecryptBlock(decryptedBlock, w, keyLen);

        // ��ǰһ���������
        xorBytes(decryptedBlock, prevBlock, 16);
        memcpy(prevBlock, block, 16);

        // �����ܺ�Ŀ���ӵ����
        result.insert(result.end(), decryptedBlock, decryptedBlock + 16);
    }

    // �Ƴ����
    return removePadding(result);
}

// CFBģʽ�������ܺͽ�����ͬ��
vector<uint8_t> cfbProcess(const vector<uint8_t>& data, const uint8_t* w, KeyLength keyLen, const uint8_t* iv) {
    vector<uint8_t> result;
    result.reserve(data.size());

    uint8_t registerValue[16];
    uint8_t encryptedReg[16];
    memcpy(registerValue, iv, 16);

    // ���ֽڴ���
    for (uint8_t byte : data) {
        // ���ܼĴ�������
        memcpy(encryptedReg, registerValue, 16);
        aesEncryptBlock(encryptedReg, w, keyLen);

        // ȡ���ܽ���ĵ�һ���ֽ��������ֽ����
        uint8_t outputByte = byte ^ encryptedReg[0];
        result.push_back(outputByte);

        // ������λ�Ĵ���
        memmove(registerValue, registerValue + 1, 15);
        registerValue[15] = outputByte;
    }

    return result;
}

// OFBģʽ�������ܺͽ�����ͬ��
vector<uint8_t> ofbProcess(const vector<uint8_t>& data, const uint8_t* w, KeyLength keyLen, const uint8_t* iv) {
    vector<uint8_t> result;
    result.reserve(data.size());

    uint8_t registerValue[16];
    uint8_t encryptedReg[16];
    memcpy(registerValue, iv, 16);

    // ���ֽڴ���
    for (uint8_t byte : data) {
        // ���ܼĴ�������
        memcpy(encryptedReg, registerValue, 16);
        aesEncryptBlock(encryptedReg, w, keyLen);
        memcpy(registerValue, encryptedReg, 16);

        // ȡ���ܽ���ĵ�һ���ֽ��������ֽ����
        result.push_back(byte ^ encryptedReg[0]);
    }

    return result;
}

// CTRģʽ�������ܺͽ�����ͬ��
vector<uint8_t> ctrProcess(const vector<uint8_t>& data, const uint8_t* w, KeyLength keyLen, const uint8_t* iv) {
    vector<uint8_t> result;
    result.reserve(data.size());

    uint8_t counter[16];
    uint8_t encryptedCounter[16];
    memcpy(counter, iv, 16);

    // ���ֽڴ���
    for (size_t i = 0; i < data.size(); i++) {
        // ÿ���鿪ʼʱ���ܼ�����
        if (i % 16 == 0) {
            memcpy(encryptedCounter, counter, 16);
            aesEncryptBlock(encryptedCounter, w, keyLen);

            // ��������1�����ģʽ��
            for (int j = 15; j >= 0; j--) {
                if (++counter[j] != 0) {
                    break;
                }
            }
        }

        // ����Կ�����
        result.push_back(data[i] ^ encryptedCounter[i % 16]);
    }

    return result;
}

int main(int argc, char* argv[]) {
    try {
        // ���������в���
        Args args = parseArgs(argc, argv);

        // ��ȡ�����ļ�
        vector<uint8_t> inputData = readFile(args.inputFile);
        cout << "��ȡ�ļ�: " << args.inputFile << " (" << inputData.size() << " �ֽ�)" << endl;

        // ׼����Կ����չ��Կ
        int keySize = (args.keyLen == AES_128) ? 16 : (args.keyLen == AES_192) ? 24 : 32;
        uint8_t key[32];
        memcpy(key, args.key.data(), keySize);

        // ������չ��Կ��С
        int wSize = 4 * (ROUNDS[args.keyLen] + 1);
        uint8_t* w = new uint8_t[wSize * 4]; // ÿ����4�ֽ�
        keyExpansion(key, w, args.keyLen);

        // ׼����ʼ������
        uint8_t iv[16];
        if (!args.iv.empty()) {
            memcpy(iv, args.iv.data(), 16);
        }

        // ִ�мӽ��ܲ�������ʱ
        vector<uint8_t> outputData;
        auto start = high_resolution_clock::now();

        switch (args.aesMode) {
        case ECB:
            if (args.opMode == ENCRYPT) {
                outputData = ecbEncrypt(inputData, w, args.keyLen);
            }
            else {
                outputData = ecbDecrypt(inputData, w, args.keyLen);
            }
            break;
        case CBC:
            if (args.opMode == ENCRYPT) {
                outputData = cbcEncrypt(inputData, w, args.keyLen, iv);
            }
            else {
                outputData = cbcDecrypt(inputData, w, args.keyLen, iv);
            }
            break;
        case CFB:
            outputData = cfbProcess(inputData, w, args.keyLen, iv);
            break;
        case OFB:
            outputData = ofbProcess(inputData, w, args.keyLen, iv);
            break;
        case CTR:
            outputData = ctrProcess(inputData, w, args.keyLen, iv);
            break;
        }

        auto end = high_resolution_clock::now();
        auto duration = duration_cast<milliseconds>(end - start);

        // д������ļ�
        writeFile(args.outputFile, outputData);
        cout << "д���ļ�: " << args.outputFile << " (" << outputData.size() << " �ֽ�)" << endl;

        // �����Ϣ
        cout << "����: " << (args.opMode == ENCRYPT ? "����" : "����") << " ���" << endl;
        cout << "AESģʽ: ";
        switch (args.aesMode) {
        case ECB: cout << "ECB"; break;
        case CBC: cout << "CBC"; break;
        case CFB: cout << "CFB"; break;
        case OFB: cout << "OFB"; break;
        case CTR: cout << "CTR"; break;
        }
        cout << endl;
        cout << "��Կ����: " << (args.keyLen == AES_128 ? 128 : (args.keyLen == AES_192 ? 192 : 256)) << "λ" << endl;
        cout << "��ʱ: " << duration.count() << " ����" << endl;

        // �����ڴ�
        delete[] w;

    }
    catch (const exception& e) {
        cerr << "����: " << e.what() << endl;
        cerr << "ʹ�� -h �� --help �鿴������Ϣ" << endl;
        return 1;
    }

    return 0;
}
