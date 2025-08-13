#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <cstdlib>
#include <ctime>

// 字符集定义
const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string numbers = "0123456789";
const std::string symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?~";

// 显示帮助信息
void showHelp() {
    std::cout << "密码生成器使用方法:\n";
    std::cout << "password_generator [选项]\n\n";
    std::cout << "选项:\n";
    std::cout << "  -l <长度>   指定密码长度 (默认: 12)\n";
    std::cout << "  -u          包含大写字母\n";
    std::cout << "  -n          包含数字\n";
    std::cout << "  -s          包含特殊符号\n";
    std::cout << "  -h          显示帮助信息\n";
    std::cout << "\n示例:\n";
    std::cout << "  password_generator -l 16 -u -n -s   生成16位包含大小写字母、数字和特殊符号的密码\n";
}

// 生成密码
std::string generatePassword(int length, bool useLowercase, bool useUppercase,
    bool useNumbers, bool useSymbols) {
    // 确保至少使用一种字符类型
    if (!useLowercase && !useUppercase && !useNumbers && !useSymbols) {
        useLowercase = true; // 默认使用小写字母
    }

    // 构建字符集
    std::string charset;
    if (useLowercase) charset += lowercase;
    if (useUppercase) charset += uppercase;
    if (useNumbers) charset += numbers;
    if (useSymbols) charset += symbols;

    // 初始化随机数生成器
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, charset.size() - 1);

    // 生成密码
    std::string password;
    for (int i = 0; i < length; ++i) {
        password += charset[distribution(generator)];
    }

    return password;
}

int main(int argc, char* argv[]) {
    // 默认参数
    int length = 12;
    bool useLowercase = true;  // 默认包含小写字母
    bool useUppercase = false;
    bool useNumbers = false;
    bool useSymbols = false;

    // 解析命令行参数
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-l" && i + 1 < argc) {
            length = std::atoi(argv[++i]);
            if (length < 4) {  // 最小密码长度限制
                std::cerr << "警告: 密码长度过短，已自动设置为4\n";
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
            std::cerr << "未知选项: " << arg << "\n";
            showHelp();
            return 1;
        }
    }

    // 生成并输出密码
    std::string password = generatePassword(length, useLowercase, useUppercase, useNumbers, useSymbols);
    std::cout << "生成的密码: " << password << "\n";

    return 0;
}
