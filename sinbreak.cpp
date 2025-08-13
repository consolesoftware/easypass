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
#include <iterator>

using namespace std;

// 支持的单表密码类型
enum CipherType {
    AUTO,       // 自动检测类型
    CAESAR,     // 凯撒密码
    AFFINE,     // 仿射密码
    SUBSTITUTION // 简单替换密码
};

// 命令行参数结构体
struct Args {
    CipherType cipherType;
    string inputFile;
    string outputFile;
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
    args.cipherType = AUTO;
    args.showFrequency = false;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-t" || arg == "--type") {
            if (i + 1 >= argc) throw invalid_argument("缺少密码类型参数值");
            string type = argv[++i];
            if (type == "auto") args.cipherType = AUTO;
            else if (type == "caesar") args.cipherType = CAESAR;
            else if (type == "affine") args.cipherType = AFFINE;
            else if (type == "substitution") args.cipherType = SUBSTITUTION;
            else throw invalid_argument("无效的密码类型: " + type);
        }
        else if (arg == "-f" || arg == "--file") {
            if (i + 1 >= argc) throw invalid_argument("缺少输入文件参数值");
            args.inputFile = argv[++i];
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) throw invalid_argument("缺少输出文件参数值");
            args.outputFile = argv[++i];
        }
        else if (arg == "-v" || arg == "--verbose") {
            args.showFrequency = true;
        }
        else if (arg == "-h" || arg == "--help") {
            cout << "单表密码破解工具" << endl;
            cout << "用法: " << argv[0] << " [选项]" << endl;
            cout << "选项:" << endl;
            cout << "  -t, --type      密码类型: auto(自动), caesar(凯撒), affine(仿射), substitution(替换)，默认auto" << endl;
            cout << "  -f, --file      输入文件路径（密文）" << endl;
            cout << "  -o, --output    输出文件路径（破解结果）" << endl;
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

// 破解凯撒密码
vector<pair<string, int>> crackCaesar(const string& ciphertext) {
    vector<pair<string, int>> candidates;
    string processed = preprocessText(ciphertext);
    map<char, double> cipherFreq = calculateFrequency(processed);

    // 尝试所有可能的移位
    for (int shift = 0; shift < 26; ++shift) {
        // 生成该移位下的明文频率
        map<char, double> plaintextFreq;
        for (char c = 'a'; c <= 'z'; ++c) {
            char shifted = (c - 'a' + shift) % 26 + 'a';
            plaintextFreq[c] = cipherFreq[shifted];
        }

        // 计算与英语频率的相似度
        double distance = calculateFrequencyDistance(plaintextFreq, ENGLISH_FREQ);
        candidates.emplace_back(caesarDecrypt(ciphertext, shift), shift);
    }

    // 按可能性排序（这里简单返回所有结果，实际应用中可按相似度排序）
    return candidates;
}

// 求最大公约数
int gcd(int a, int b) {
    while (b) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// 求模逆元（a关于m的逆元）
int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return -1; // 没有逆元
}

// 仿射密码解密：c = (a*p + b) mod 26，解密公式p = a^-1*(c - b) mod 26
string affineDecrypt(const string& ciphertext, int a, int b) {
    string plaintext;
    int aInv = modInverse(a, 26);

    if (aInv == -1) {
        throw invalid_argument("a的值不与26互质，无法解密");
    }

    for (char c : ciphertext) {
        if (isalpha(c)) {
            char base = islower(c) ? 'a' : 'A';
            int cVal = c - base;
            int pVal = (aInv * ((cVal - b + 26) % 26)) % 26;
            plaintext += (char)(pVal + base);
        }
        else {
            plaintext += c;
        }
    }
    return plaintext;
}

// 破解仿射密码
vector<pair<string, pair<int, int>>> crackAffine(const string& ciphertext) {
    vector<pair<string, pair<int, int>>> candidates;
    string processed = preprocessText(ciphertext);
    if (processed.empty()) {
        return candidates;
    }

    // 获取密文中频率最高的两个字符
    map<char, double> freq = calculateFrequency(processed);
    vector<char> topChars = getSortedByFrequency(freq);

    // 英语中最常见的两个字符
    vector<char> englishTop = { 'e', 't', 'a', 'o', 'i', 'n' };

    // 尝试可能的映射组合
    for (int i = 0; i < min(3, (int)topChars.size()); i++) {
        for (int j = 0; j < min(3, (int)englishTop.size()); j++) {
            if (i == j) continue;

            char c1 = topChars[i];    // 密文中最常见的字符
            char p1 = englishTop[j];  // 明文中最常见的字符（假设为'e'）

            for (int k = 1; k < min(3, (int)topChars.size()); k++) {
                if (k == i) continue;
                for (int l = 1; l < min(3, (int)englishTop.size()); l++) {
                    if (l == j) continue;

                    char c2 = topChars[k];    // 密文中第二常见的字符
                    char p2 = englishTop[l];  // 明文中第二常见的字符（假设为't'）

                    // 解方程组: 
                    // c1 = (a*p1 + b) mod 26
                    // c2 = (a*p2 + b) mod 26
                    int c1Val = c1 - 'a';
                    int p1Val = p1 - 'a';
                    int c2Val = c2 - 'a';
                    int p2Val = p2 - 'a';

                    int deltaP = (p1Val - p2Val + 26) % 26;
                    int deltaC = (c1Val - c2Val + 26) % 26;

                    int a = (deltaC * modInverse(deltaP, 26)) % 26;
                    if (a <= 0 || gcd(a, 26) != 1) {
                        continue;
                    }

                    int b = (c1Val - (a * p1Val) % 26 + 26) % 26;

                    // 生成解密结果
                    string plaintext = affineDecrypt(ciphertext, a, b);
                    candidates.emplace_back(plaintext, make_pair(a, b));
                }
            }
        }
    }

    // 去重
    sort(candidates.begin(), candidates.end());
    auto last = unique(candidates.begin(), candidates.end());
    candidates.erase(last, candidates.end());

    return candidates;
}

// 破解简单替换密码（基于频率映射）
string crackSubstitution(const string& ciphertext) {
    string processed = preprocessText(ciphertext);
    map<char, double> freq = calculateFrequency(processed);

    // 密文字符按频率排序
    vector<char> cipherSorted = getSortedByFrequency(freq);

    // 英语字符按频率排序
    vector<pair<char, double>> englishFreqVec(ENGLISH_FREQ.begin(), ENGLISH_FREQ.end());
    sort(englishFreqVec.begin(), englishFreqVec.end(),
        [](const pair<char, double>& a, const pair<char, double>& b) {
            return a.second > b.second;
        });

    vector<char> englishSorted;
    for (const auto& pair : englishFreqVec) {
        englishSorted.push_back(pair.first);
    }

    // 创建替换映射
    map<char, char> substitutionMap;
    for (size_t i = 0; i < cipherSorted.size(); i++) {
        if (i < englishSorted.size()) {
            substitutionMap[cipherSorted[i]] = englishSorted[i];
        }
        else {
            substitutionMap[cipherSorted[i]] = '?'; // 未知映射
        }
    }

    // 应用替换映射
    string plaintext;
    for (char c : ciphertext) {
        if (isalpha(c)) {
            bool isUpper = isupper(c);
            char lowerC = tolower(c);
            char mapped = substitutionMap[lowerC];
            plaintext += isUpper ? toupper(mapped) : mapped;
        }
        else {
            plaintext += c;
        }
    }

    return plaintext;
}

// 自动检测密码类型并破解
vector<string> autoCrack(const string& ciphertext) {
    vector<string> results;

    // 先尝试凯撒密码（最简单）
    auto caesarResults = crackCaesar(ciphertext);
    for (const auto& pair : caesarResults) {
        results.push_back("可能是凯撒密码（移位 " + to_string(pair.second) + "）:\n" + pair.first + "\n");
    }

    // 尝试仿射密码
    auto affineResults = crackAffine(ciphertext);
    for (const auto& pair : affineResults) {
        results.push_back("可能是仿射密码（a=" + to_string(pair.second.first) +
            ", b=" + to_string(pair.second.second) + "）:\n" + pair.first + "\n");
    }

    // 尝试替换密码
    string substitutionResult = crackSubstitution(ciphertext);
    results.push_back("可能是替换密码:\n" + substitutionResult + "\n");

    return results;
}

int main(int argc, char* argv[]) {
    try {
        // 解析命令行参数
        Args args = parseArgs(argc, argv);

        // 读取密文
        string ciphertext = readFile(args.inputFile);
        cout << "已读取密文文件: " << args.inputFile << " (" << ciphertext.size() << " 字符)" << endl;

        // 预处理并分析频率
        string processed = preprocessText(ciphertext);
        map<char, double> freq = calculateFrequency(processed);

        if (args.showFrequency) {
            displayFrequency(freq);
        }

        // 破解密码
        vector<string> results;
        cout << "开始破解..." << endl;

        switch (args.cipherType) {
        case CAESAR: {
            auto caesarResults = crackCaesar(ciphertext);
            for (size_t i = 0; i < min(5, (int)caesarResults.size()); i++) { // 显示最可能的5个结果
                results.push_back("凯撒密码（移位 " + to_string(caesarResults[i].second) + "）:\n" + caesarResults[i].first + "\n");
            }
            break;
        }
        case AFFINE: {
            auto affineResults = crackAffine(ciphertext);
            for (size_t i = 0; i < min(5, (int)affineResults.size()); i++) {
                results.push_back("仿射密码（a=" + to_string(affineResults[i].second.first) +
                    ", b=" + to_string(affineResults[i].second.second) + "）:\n" + affineResults[i].first + "\n");
            }
            break;
        }
        case SUBSTITUTION: {
            string substitutionResult = crackSubstitution(ciphertext);
            results.push_back("替换密码:\n" + substitutionResult + "\n");
            break;
        }
        case AUTO:
            results = autoCrack(ciphertext);
            break;
        }

        // 输出结果
        string output;
        for (const string& res : results) {
            output += res + "\n";
        }

        if (!args.outputFile.empty()) {
            writeFile(args.outputFile, output);
            cout << "破解结果已保存到: " << args.outputFile << endl;
        }
        else {
            cout << "\n破解结果:\n" << output << endl;
        }

        cout << "提示：替换密码的破解结果可能需要手动调整才能得到完全正确的明文" << endl;

    }
    catch (const exception& e) {
        cerr << "错误: " << e.what() << endl;
        cerr << "使用 -h 或 --help 查看帮助信息" << endl;
        return 1;
    }

    return 0;
}
