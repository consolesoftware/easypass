#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <cstdlib>
#include <ctime>

// �ַ�������
const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string numbers = "0123456789";
const std::string symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?~";

// ��ʾ������Ϣ
void showHelp() {
    std::cout << "����������ʹ�÷���:\n";
    std::cout << "password_generator [ѡ��]\n\n";
    std::cout << "ѡ��:\n";
    std::cout << "  -l <����>   ָ�����볤�� (Ĭ��: 12)\n";
    std::cout << "  -u          ������д��ĸ\n";
    std::cout << "  -n          ��������\n";
    std::cout << "  -s          �����������\n";
    std::cout << "  -h          ��ʾ������Ϣ\n";
    std::cout << "\nʾ��:\n";
    std::cout << "  password_generator -l 16 -u -n -s   ����16λ������Сд��ĸ�����ֺ�������ŵ�����\n";
}

// ��������
std::string generatePassword(int length, bool useLowercase, bool useUppercase,
    bool useNumbers, bool useSymbols) {
    // ȷ������ʹ��һ���ַ�����
    if (!useLowercase && !useUppercase && !useNumbers && !useSymbols) {
        useLowercase = true; // Ĭ��ʹ��Сд��ĸ
    }

    // �����ַ���
    std::string charset;
    if (useLowercase) charset += lowercase;
    if (useUppercase) charset += uppercase;
    if (useNumbers) charset += numbers;
    if (useSymbols) charset += symbols;

    // ��ʼ�������������
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, charset.size() - 1);

    // ��������
    std::string password;
    for (int i = 0; i < length; ++i) {
        password += charset[distribution(generator)];
    }

    return password;
}

int main(int argc, char* argv[]) {
    // Ĭ�ϲ���
    int length = 12;
    bool useLowercase = true;  // Ĭ�ϰ���Сд��ĸ
    bool useUppercase = false;
    bool useNumbers = false;
    bool useSymbols = false;

    // ���������в���
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-l" && i + 1 < argc) {
            length = std::atoi(argv[++i]);
            if (length < 4) {  // ��С���볤������
                std::cerr << "����: ���볤�ȹ��̣����Զ�����Ϊ4\n";
                length = 4;
            }
        }
        else if (arg == "-u") {
            useUppercase = true;
        }
        else if (arg == "-n") {
            useNumbers = true;
        }
        else if (arg == "-s") {
            useSymbols = true;
        }
        else if (arg == "-h") {
            showHelp();
            return 0;
        }
        else {
            std::cerr << "δ֪ѡ��: " << arg << "\n";
            showHelp();
            return 1;
        }
    }

    // ���ɲ��������
    std::string password = generatePassword(length, useLowercase, useUppercase, useNumbers, useSymbols);
    std::cout << "���ɵ�����: " << password << "\n";

    return 0;
}
