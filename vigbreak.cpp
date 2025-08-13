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

// �����в����ṹ��
struct Args {
    string inputFile;
    string outputFile;
    int knownKeyLength; // ��֪��Կ���ȣ�0��ʾ�Զ����
    bool showFrequency; // �Ƿ���ʾƵ�ʷ������
};

// Ӣ����ĸ����Ƶ�ʣ�����ͳ�����ݣ�
const map<char, double> ENGLISH_FREQ = {
    {'a', 0.08167}, {'b', 0.01492}, {'c', 0.02782}, {'d', 0.04253},
    {'e', 0.12702}, {'f', 0.02228}, {'g', 0.02015}, {'h', 0.06966},
    {'i', 0.07507}, {'j', 0.00153}, {'k', 0.00772}, {'l', 0.04025},
    {'m', 0.02406}, {'n', 0.06749}, {'o', 0.07507}, {'p', 0.01929},
    {'q', 0.00095}, {'r', 0.05987}, {'s', 0.06327}, {'t', 0.09056},
    {'u', 0.02758}, {'v', 0.00978}, {'w', 0.02360}, {'x', 0.00150},
    {'y', 0.01974}, {'z', 0.00074}
};

// ���������в���
Args parseArgs(int argc, char* argv[]) {
    Args args;
    args.knownKeyLength = 0;
    args.showFrequency = false;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-f" || arg == "--file") {
            if (i + 1 >= argc) throw invalid_argument("ȱ�������ļ�����ֵ");
            args.inputFile = argv[++i];
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) throw invalid_argument("ȱ������ļ�����ֵ");
            args.outputFile = argv[++i];
        }
        else if (arg == "-l" || arg == "--length") {
            if (i + 1 >= argc) throw invalid_argument("ȱ����Կ���Ȳ���ֵ");
            args.knownKeyLength = stoi(argv[++i]);
            if (args.knownKeyLength <= 0) {
                throw invalid_argument("��Կ���ȱ���Ϊ����");
            }
        }
        else if (arg == "-v" || arg == "--verbose") {
            args.showFrequency = true;
        }
        else if (arg == "-h" || arg == "--help") {
            cout << "ά�����������ƽ⹤��" << endl;
            cout << "�÷�: " << argv[0] << " [ѡ��]" << endl;
            cout << "ѡ��:" << endl;
            cout << "  -f, --file      �����ļ�·�������ģ�" << endl;
            cout << "  -o, --output    ����ļ�·�����ƽ�����" << endl;
            cout << "  -l, --length    ��֪��Կ���ȣ���ѡ��" << endl;
            cout << "  -v, --verbose   ��ʾƵ�ʷ������" << endl;
            cout << "  -h, --help      ��ʾ������Ϣ" << endl;
            exit(0);
        }
        else {
            throw invalid_argument("��Ч�Ĳ���: " + arg);
        }
    }

    if (args.inputFile.empty()) {
        throw invalid_argument("�����ṩ�����ļ�");
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

// Ԥ�����ı���תΪСд��ȥ������ĸ�ַ�
string preprocessText(const string& text) {
    string result;
    for (char c : text) {
        if (isalpha(c)) {
            result += tolower(c);
        }
    }
    return result;
}

// �����ı�����ĸ����Ƶ��
map<char, double> calculateFrequency(const string& text) {
    map<char, double> freq;
    int total = 0;

    // ��ʼ��Ƶ��ӳ��
    for (char c = 'a'; c <= 'z'; ++c) {
        freq[c] = 0.0;
    }

    // ͳ�Ƴ��ִ���
    for (char c : text) {
        if (isalpha(c)) {
            freq[tolower(c)]++;
            total++;
        }
    }

    // ����Ƶ��
    if (total > 0) {
        for (auto& pair : freq) {
            pair.second /= total;
        }
    }

    return freq;
}

// ��ʾƵ�ʷ������
void displayFrequency(const map<char, double>& freq) {
    cout << "�ַ�Ƶ�ʷ��������" << endl;
    cout << "---------------------" << endl;
    for (const auto& pair : freq) {
        cout << setw(2) << pair.first << ": "
            << setw(6) << fixed << setprecision(4) << pair.second
            << " (" << setw(3) << (int)(pair.second * 100) << "%)" << endl;
    }
    cout << "---------------------" << endl << endl;
}

// ��Ƶ�������ַ����Ӹߵ��ͣ�
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

// ��������Ƶ�ʷֲ������ƶȣ�Խ��Խ���ƣ�
double calculateFrequencyDistance(const map<char, double>& freq1, const map<char, double>& freq2) {
    double distance = 0.0;
    for (char c = 'a'; c <= 'z'; ++c) {
        distance += pow(freq1.at(c) - freq2.at(c), 2);
    }
    return distance;
}

// ��ȡ�ظ����м���λ��
vector<pair<string, vector<int>>> findRepeatedSequences(const string& text, int minLength = 3) {
    map<string, vector<int>> sequences;

    // �������г�������ΪminLength���ظ�����
    for (int len = minLength; len <= text.length() / 2; ++len) {
        for (int i = 0; i <= (int)text.length() - len; ++i) {
            string seq = text.substr(i, len);
            sequences[seq].push_back(i);
        }
    }

    // ���˵�ֻ����һ�ε�����
    vector<pair<string, vector<int>>> result;
    for (const auto& entry : sequences) {
        if (entry.second.size() >= 2) {
            result.push_back(entry);
        }
    }

    return result;
}

// �������Լ��
int gcd(int a, int b) {
    while (b) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// �������������Լ��
int gcdOfList(const vector<int>& numbers) {
    if (numbers.empty()) return 0;
    int result = numbers[0];
    for (size_t i = 1; i < numbers.size(); ++i) {
        result = gcd(result, numbers[i]);
        if (result == 1) break; // GCD����С��1
    }
    return result;
}

// ʹ�ÿ���˹�����������Կ����
vector<int> estimateKeyLengths(const string& text, int maxLength = 20) {
    // �ҵ��ظ�������
    auto repeatedSeqs = findRepeatedSequences(text);

    // �����ظ�����֮��ľ���
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
        // ���û���ҵ��ظ����У����ؿ��ܵĳ��ȷ�Χ
        vector<int> result;
        for (int i = 2; i <= maxLength; ++i) {
            result.push_back(i);
        }
        return result;
    }

    // �������о�������Լ����������
    map<int, int> divisorCounts;
    for (int d : distances) {
        for (int i = 2; i <= min(d, maxLength); ++i) {
            if (d % i == 0) {
                divisorCounts[i]++;
            }
        }
    }

    // �����ִ���������ܵ���Կ����
    vector<pair<int, int>> sortedLengths(divisorCounts.begin(), divisorCounts.end());
    sort(sortedLengths.begin(), sortedLengths.end(),
        [](const pair<int, int>& a, const pair<int, int>& b) {
            return a.second > b.second;
        });

    // ��ȡ���
    vector<int> result;
    for (const auto& len : sortedLengths) {
        result.push_back(len.first);
    }

    // ���������㣬����һЩ���ܵĳ���
    while (result.size() < 5 && result.back() < maxLength) {
        int next = result.back() + 1;
        if (find(result.begin(), result.end(), next) == result.end()) {
            result.push_back(next);
        }
    }

    return result;
}

// ���ı�����Կ���ȷ���
vector<string> groupTextByKeyLength(const string& text, int keyLength) {
    vector<string> groups(keyLength);
    for (size_t i = 0; i < text.length(); ++i) {
        groups[i % keyLength] += text[i];
    }
    return groups;
}

// �����������
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

// ȷ��������������������λ
int findBestShift(const string& text) {
    map<char, double> freq = calculateFrequency(text);
    double minDistance = 1e9;
    int bestShift = 0;

    // �������п��ܵ���λ
    for (int shift = 0; shift < 26; ++shift) {
        // ���ɸ���λ�µ�����Ƶ��
        map<char, double> plaintextFreq;
        for (char c = 'a'; c <= 'z'; ++c) {
            char shifted = (c - 'a' + shift) % 26 + 'a';
            plaintextFreq[c] = freq[shifted];
        }

        // ������Ӣ��Ƶ�ʵ����ƶ�
        double distance = calculateFrequencyDistance(plaintextFreq, ENGLISH_FREQ);
        if (distance < minDistance) {
            minDistance = distance;
            bestShift = shift;
        }
    }

    return bestShift;
}

// ά�������������
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

// �ƽ�ά����������
pair<string, string> crackVigenere(const string& ciphertext, int keyLength) {
    string processed = preprocessText(ciphertext);
    if (processed.empty()) {
        return make_pair("", "");
    }

    // ����Կ���ȷ���
    vector<string> groups = groupTextByKeyLength(processed, keyLength);

    // ȷ��ÿ��������λ������Կ��ÿ���ַ���
    string key;
    for (const string& group : groups) {
        int shift = findBestShift(group);
        key += (char)('a' + shift);
    }

    // ʹ���ҵ�����Կ����
    string plaintext = vigenereDecrypt(ciphertext, key);

    return make_pair(plaintext, key);
}

int main(int argc, char* argv[]) {
    try {
        // ���������в���
        Args args = parseArgs(argc, argv);

        // ��ȡ����
        string ciphertext = readFile(args.inputFile);
        cout << "�Ѷ�ȡ�����ļ�: " << args.inputFile << " (" << ciphertext.size() << " �ַ�)" << endl;

        // Ԥ����
        string processed = preprocessText(ciphertext);
        if (processed.empty()) {
            throw runtime_error("�����ļ���û����Ч����ĸ�ַ�");
        }

        // ����Ƶ��
        map<char, double> freq = calculateFrequency(processed);
        if (args.showFrequency) {
            displayFrequency(freq);
        }

        // ȷ�����ܵ���Կ����
        vector<int> possibleKeyLengths;
        if (args.knownKeyLength > 0) {
            possibleKeyLengths.push_back(args.knownKeyLength);
            cout << "ʹ����֪��Կ����: " << args.knownKeyLength << endl;
        }
        else {
            possibleKeyLengths = estimateKeyLengths(processed);
            cout << "���ܵ���Կ���ȣ�������������: ";
            for (size_t i = 0; i < min(5, (int)possibleKeyLengths.size()); ++i) {
                if (i > 0) cout << ", ";
                cout << possibleKeyLengths[i];
            }
            cout << endl;
        }

        // �����ƽ�
        vector<pair<string, string>> results; // (����, ��Կ)
        int maxAttempts = args.knownKeyLength > 0 ? 1 : min(5, (int)possibleKeyLengths.size());

        cout << "��ʼ�ƽ⣬����" << maxAttempts << "�ֿ��ܵ���Կ����..." << endl;
        for (int i = 0; i < maxAttempts; ++i) {
            int keyLen = possibleKeyLengths[i];
            auto result = crackVigenere(ciphertext, keyLen);
            results.push_back(result);
            cout << "������Կ���� " << keyLen << "���ҵ���Կ: " << result.second << endl;
        }

        // ������
        string output;
        for (size_t i = 0; i < results.size(); ++i) {
            output += "���ܵĽ�� " + to_string(i + 1) + ":\n";
            output += "��Կ: " + results[i].second + "\n";
            output += "����:\n" + results[i].first + "\n\n";
        }

        if (!args.outputFile.empty()) {
            writeFile(args.outputFile, output);
            cout << "�ƽ����ѱ��浽: " << args.outputFile << endl;
        }
        else {
            cout << "\n�ƽ���:\n" << output << endl;
        }

    }
    catch (const exception& e) {
        cerr << "����: " << e.what() << endl;
        cerr << "ʹ�� -h �� --help �鿴������Ϣ" << endl;
        return 1;
    }

    return 0;
}
