#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <algorithm>
#include <iomanip>
#include <numeric>
#include <cmath>
#include <set>
#include <iterator>

using namespace std;

// 命令行参数结构体
struct Args {
    string inputFile;
    string outputFile;
    int knownKeyLength; // 已知密钥长度，0表示自动检测
    bool showFrequency; // 是否显示频率分析结果
};

// 英语字母出现频率（来自统计数据）
const map<char, double> ENGLISH_FREQ = {
    {'a', 0.08167}, {'b', 0.01492}, {'c', 0.02782}, {'d', 0.04253},
    {'e', 0.12702}, {'f', 0.02228}, {'g', 0.02015}, {'h', 0.06966},
    {'i', 0.07507}, {'j', 0.00153}, {'k', 0.00772}, {'l', 0.04025},
    {'m', 0.02406}, {'n', 0.06749}, {'o', 0.07507}, {'p', 0.01929},
    {'q', 0.00095}, {'r', 0.05987}, {'s', 0.06327}, {'t', 0.09056},
    {'u', 0.02758}, {'v', 0.00978}, {'w', 0.02360}, {'x', 0.00150},
    {'y', 0.01974}, {'z', 0.00074}
};

// 解析命令行参数
Args parseArgs(int argc, char* argv[]) {
    Args args;
    args.knownKeyLength = 0;
    args.showFrequency = false;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-f" || arg == "--file") {
            if (i + 1 >= argc) throw invalid_argument("缺少输入文件参数值");
            args.inputFile = argv[++i];
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) throw invalid_argument("缺少输出文件参数值");
            args.outputFile = argv[++i];
        }
        else if (arg == "-l" || arg == "--length") {
            if (i + 1 >= argc) throw invalid_argument("缺少密钥长度参数值");
            args.knownKeyLength = stoi(argv[++i]);
            if (args.knownKeyLength <= 0) {
                throw invalid_argument("密钥长度必须为正数");
            }
        }
        else if (arg == "-v" || arg == "--verbose") {
            args.showFrequency = true;
        }
        else if (arg == "-h" || arg == "--help") {
            cout << "维吉尼亚密码破解工具" << endl;
            cout << "用法: " << argv[0] << " [选项]" << endl;
            cout << "选项:" << endl;
            cout << "  -f, --file      输入文件路径（密文）" << endl;
            cout << "  -o, --output    输出文件路径（破解结果）" << endl;
            cout << "  -l, --length    已知密钥长度（可选）" << endl;
            cout << "  -v, --verbose   显示频率分析结果" << endl;
            cout << "  -h, --help      显示帮助信息" << endl;
            exit(0);
        }
        else {
            throw invalid_argument("无效的参数: " + arg);
        }
    }

    if (args.inputFile.empty()) {
        throw invalid_argument("必须提供输入文件");
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

// 预处理文本：转为小写，去除非字母字符
string preprocessText(const string& text) {
    string result;
    for (char c : text) {
        if (isalpha(c)) {
            result += tolower(c);
        }
    }
    return result;
}

// 计算文本中字母出现频率
map<char, double> calculateFrequency(const string& text) {
    map<char, double> freq;
    int total = 0;

    // 初始化频率映射
    for (char c = 'a'; c <= 'z'; ++c) {
        freq[c] = 0.0;
    }

    // 统计出现次数
    for (char c : text) {
        if (isalpha(c)) {
            freq[tolower(c)]++;
            total++;
        }
    }

    // 计算频率
    if (total > 0) {
        for (auto& pair : freq) {
            pair.second /= total;
        }
    }

    return freq;
}

// 显示频率分析结果
void displayFrequency(const map<char, double>& freq) {
    cout << "字符频率分析结果：" << endl;
    cout << "---------------------" << endl;
    for (const auto& pair : freq) {
        cout << setw(2) << pair.first << ": "
            << setw(6) << fixed << setprecision(4) << pair.second
            << " (" << setw(3) << (int)(pair.second * 100) << "%)" << endl;
    }
    cout << "---------------------" << endl << endl;
}

// 按频率排序字符（从高到低）
vector<char> getSortedByFrequency(const map<char, double>& freq) {
    vector<pair<char, double>> freqVec(freq.begin(), freq.end());
    sort(freqVec.begin(), freqVec.end(),
        [](const pair<char, double>& a, const pair<char, double>& b) {
            return a.second > b.second;
        });

    vector<char> result;
    for (const auto& pair : freqVec) {
        result.push_back(pair.first);
    }
    return result;
}

// 计算两个频率分布的相似度（越低越相似）
double calculateFrequencyDistance(const map<char, double>& freq1, const map<char, double>& freq2) {
    double distance = 0.0;
    for (char c = 'a'; c <= 'z'; ++c) {
        distance += pow(freq1.at(c) - freq2.at(c), 2);
    }
    return distance;
}

// 提取重复序列及其位置
vector<pair<string, vector<int>>> findRepeatedSequences(const string& text, int minLength = 3) {
    map<string, vector<int>> sequences;

    // 查找所有长度至少为minLength的重复序列
    for (int len = minLength; len <= text.length() / 2; ++len) {
        for (int i = 0; i <= (int)text.length() - len; ++i) {
            string seq = text.substr(i, len);
            sequences[seq].push_back(i);
        }
    }

    // 过滤掉只出现一次的序列
    vector<pair<string, vector<int>>> result;
    for (const auto& entry : sequences) {
        if (entry.second.size() >= 2) {
            result.push_back(entry);
        }
    }

    return result;
}

// 计算最大公约数
int gcd(int a, int b) {
    while (b) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// 计算多个数的最大公约数
int gcdOfList(const vector<int>& numbers) {
    if (numbers.empty()) return 0;
    int result = numbers[0];
    for (size_t i = 1; i < numbers.size(); ++i) {
        result = gcd(result, numbers[i]);
        if (result == 1) break; // GCD不会小于1
    }
    return result;
}

// 使用卡西斯基试验估计密钥长度
vector<int> estimateKeyLengths(const string& text, int maxLength = 20) {
    // 找到重复的序列
    auto repeatedSeqs = findRepeatedSequences(text);

    // 计算重复序列之间的距离
    vector<int> distances;
    for (const auto& seq : repeatedSeqs) {
        const vector<int>& positions = seq.second;
        for (size_t i = 1; i < positions.size(); ++i) {
            int distance = positions[i] - positions[i - 1];
            if (distance > 0) {
                distances.push_back(distance);
            }
        }
    }

    if (distances.empty()) {
        // 如果没有找到重复序列，返回可能的长度范围
        vector<int> result;
        for (int i = 2; i <= maxLength; ++i) {
            result.push_back(i);
        }
        return result;
    }

    // 计算所有距离的最大公约数及其因子
    map<int, int> divisorCounts;
    for (int d : distances) {
        for (int i = 2; i <= min(d, maxLength); ++i) {
            if (d % i == 0) {
                divisorCounts[i]++;
            }
        }
    }

    // 按出现次数排序可能的密钥长度
    vector<pair<int, int>> sortedLengths(divisorCounts.begin(), divisorCounts.end());
    sort(sortedLengths.begin(), sortedLengths.end(),
        [](const pair<int, int>& a, const pair<int, int>& b) {
            return a.second > b.second;
        });

    // 提取结果
    vector<int> result;
    for (const auto& len : sortedLengths) {
        result.push_back(len.first);
    }

    // 如果结果不足，补充一些可能的长度
    while (result.size() < 5 && result.back() < maxLength) {
        int next = result.back() + 1;
        if (find(result.begin(), result.end(), next) == result.end()) {
            result.push_back(next);
        }
    }

    return result;
}

// 将文本按密钥长度分组
vector<string> groupTextByKeyLength(const string& text, int keyLength) {
    vector<string> groups(keyLength);
    for (size_t i = 0; i < text.length(); ++i) {
        groups[i % keyLength] += text[i];
    }
    return groups;
}

// 凯撒密码解密
string caesarDecrypt(const string& ciphertext, int shift) {
    string plaintext;
    shift = shift % 26;
    if (shift < 0) shift += 26;

    for (char c : ciphertext) {
        if (isalpha(c)) {
            char base = islower(c) ? 'a' : 'A';
            plaintext += (char)((c - base - shift + 26) % 26 + base);
        }
        else {
            plaintext += c;
        }
    }
    return plaintext;
}

// 确定单个凯撒密码的最佳移位
int findBestShift(const string& text) {
    map<char, double> freq = calculateFrequency(text);
    double minDistance = 1e9;
    int bestShift = 0;

    // 尝试所有可能的移位
    for (int shift = 0; shift < 26; ++shift) {
        // 生成该移位下的明文频率
        map<char, double> plaintextFreq;
        for (char c = 'a'; c <= 'z'; ++c) {
            char shifted = (c - 'a' + shift) % 26 + 'a';
            plaintextFreq[c] = freq[shifted];
        }

        // 计算与英语频率的相似度
        double distance = calculateFrequencyDistance(plaintextFreq, ENGLISH_FREQ);
        if (distance < minDistance) {
            minDistance = distance;
            bestShift = shift;
        }
    }

    return bestShift;
}

// 维吉尼亚密码解密
string vigenereDecrypt(const string& ciphertext, const string& key) {
    string plaintext;
    int keyLen = key.length();
    if (keyLen == 0) return ciphertext;

    for (size_t i = 0; i < ciphertext.length(); ++i) {
        char c = ciphertext[i];
        if (isalpha(c)) {
            char base = islower(c) ? 'a' : 'A';
            int keyShift = tolower(key[i % keyLen]) - 'a';
            plaintext += (char)((c - base - keyShift + 26) % 26 + base);
        }
        else {
            plaintext += c;
        }
    }

    return plaintext;
}

// 破解维吉尼亚密码
pair<string, string> crackVigenere(const string& ciphertext, int keyLength) {
    string processed = preprocessText(ciphertext);
    if (processed.empty()) {
        return make_pair("", "");
    }

    // 按密钥长度分组
    vector<string> groups = groupTextByKeyLength(processed, keyLength);

    // 确定每组的最佳移位（即密钥的每个字符）
    string key;
    for (const string& group : groups) {
        int shift = findBestShift(group);
        key += (char)('a' + shift);
    }

    // 使用找到的密钥解密
    string plaintext = vigenereDecrypt(ciphertext, key);

    return make_pair(plaintext, key);
}

int main(int argc, char* argv[]) {
    try {
        // 解析命令行参数
        Args args = parseArgs(argc, argv);

        // 读取密文
        string ciphertext = readFile(args.inputFile);
        cout << "已读取密文文件: " << args.inputFile << " (" << ciphertext.size() << " 字符)" << endl;

        // 预处理
        string processed = preprocessText(ciphertext);
        if (processed.empty()) {
            throw runtime_error("输入文件中没有有效的字母字符");
        }

        // 分析频率
        map<char, double> freq = calculateFrequency(processed);
        if (args.showFrequency) {
            displayFrequency(freq);
        }

        // 确定可能的密钥长度
        vector<int> possibleKeyLengths;
        if (args.knownKeyLength > 0) {
            possibleKeyLengths.push_back(args.knownKeyLength);
            cout << "使用已知密钥长度: " << args.knownKeyLength << endl;
        }
        else {
            possibleKeyLengths = estimateKeyLengths(processed);
            cout << "可能的密钥长度（按可能性排序）: ";
            for (size_t i = 0; i < min(5, (int)possibleKeyLengths.size()); ++i) {
                if (i > 0) cout << ", ";
                cout << possibleKeyLengths[i];
            }
            cout << endl;
        }

        // 尝试破解
        vector<pair<string, string>> results; // (明文, 密钥)
        int maxAttempts = args.knownKeyLength > 0 ? 1 : min(5, (int)possibleKeyLengths.size());

        cout << "开始破解，尝试" << maxAttempts << "种可能的密钥长度..." << endl;
        for (int i = 0; i < maxAttempts; ++i) {
            int keyLen = possibleKeyLengths[i];
            auto result = crackVigenere(ciphertext, keyLen);
            results.push_back(result);
            cout << "尝试密钥长度 " << keyLen << "，找到密钥: " << result.second << endl;
        }

        // 输出结果
        string output;
        for (size_t i = 0; i < results.size(); ++i) {
            output += "可能的结果 " + to_string(i + 1) + ":\n";
            output += "密钥: " + results[i].second + "\n";
            output += "明文:\n" + results[i].first + "\n\n";
        }

        if (!args.outputFile.empty()) {
            writeFile(args.outputFile, output);
            cout << "破解结果已保存到: " << args.outputFile << endl;
        }
        else {
            cout << "\n破解结果:\n" << output << endl;
        }

    }
    catch (const exception& e) {
        cerr << "错误: " << e.what() << endl;
        cerr << "使用 -h 或 --help 查看帮助信息" << endl;
        return 1;
    }

    return 0;
}
