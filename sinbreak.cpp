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

// ֧�ֵĵ�����������
enum CipherType {
    AUTO,       // �Զ��������
    CAESAR,     // ��������
    AFFINE,     // ��������
    SUBSTITUTION // ���滻����
};

// �����в����ṹ��
struct Args {
    CipherType cipherType;
    string inputFile;
    string outputFile;
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
    args.cipherType = AUTO;
    args.showFrequency = false;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-t" || arg == "--type") {
            if (i + 1 >= argc) throw invalid_argument("ȱ���������Ͳ���ֵ");
            string type = argv[++i];
            if (type == "auto") args.cipherType = AUTO;
            else if (type == "caesar") args.cipherType = CAESAR;
            else if (type == "affine") args.cipherType = AFFINE;
            else if (type == "substitution") args.cipherType = SUBSTITUTION;
            else throw invalid_argument("��Ч����������: " + type);
        }
        else if (arg == "-f" || arg == "--file") {
            if (i + 1 >= argc) throw invalid_argument("ȱ�������ļ�����ֵ");
            args.inputFile = argv[++i];
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) throw invalid_argument("ȱ������ļ�����ֵ");
            args.outputFile = argv[++i];
        }
        else if (arg == "-v" || arg == "--verbose") {
            args.showFrequency = true;
        }
        else if (arg == "-h" || arg == "--help") {
            cout << "���������ƽ⹤��" << endl;
            cout << "�÷�: " << argv[0] << " [ѡ��]" << endl;
            cout << "ѡ��:" << endl;
            cout << "  -t, --type      ��������: auto(�Զ�), caesar(����), affine(����), substitution(�滻)��Ĭ��auto" << endl;
            cout << "  -f, --file      �����ļ�·�������ģ�" << endl;
            cout << "  -o, --output    ����ļ�·�����ƽ�����" << endl;
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

// �ƽ⿭������
vector<pair<string, int>> crackCaesar(const string& ciphertext) {
    vector<pair<string, int>> candidates;
    string processed = preprocessText(ciphertext);
    map<char, double> cipherFreq = calculateFrequency(processed);

    // �������п��ܵ���λ
    for (int shift = 0; shift < 26; ++shift) {
        // ���ɸ���λ�µ�����Ƶ��
        map<char, double> plaintextFreq;
        for (char c = 'a'; c <= 'z'; ++c) {
            char shifted = (c - 'a' + shift) % 26 + 'a';
            plaintextFreq[c] = cipherFreq[shifted];
        }

        // ������Ӣ��Ƶ�ʵ����ƶ�
        double distance = calculateFrequencyDistance(plaintextFreq, ENGLISH_FREQ);
        candidates.emplace_back(caesarDecrypt(ciphertext, shift), shift);
    }

    // ����������������򵥷������н����ʵ��Ӧ���пɰ����ƶ�����
    return candidates;
}

// �����Լ��
int gcd(int a, int b) {
    while (b) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// ��ģ��Ԫ��a����m����Ԫ��
int modInverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return -1; // û����Ԫ
}

// ����������ܣ�c = (a*p + b) mod 26�����ܹ�ʽp = a^-1*(c - b) mod 26
string affineDecrypt(const string& ciphertext, int a, int b) {
    string plaintext;
    int aInv = modInverse(a, 26);

    if (aInv == -1) {
        throw invalid_argument("a��ֵ����26���ʣ��޷�����");
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

// �ƽ��������
vector<pair<string, pair<int, int>>> crackAffine(const string& ciphertext) {
    vector<pair<string, pair<int, int>>> candidates;
    string processed = preprocessText(ciphertext);
    if (processed.empty()) {
        return candidates;
    }

    // ��ȡ������Ƶ����ߵ������ַ�
    map<char, double> freq = calculateFrequency(processed);
    vector<char> topChars = getSortedByFrequency(freq);

    // Ӣ��������������ַ�
    vector<char> englishTop = { 'e', 't', 'a', 'o', 'i', 'n' };

    // ���Կ��ܵ�ӳ�����
    for (int i = 0; i < min(3, (int)topChars.size()); i++) {
        for (int j = 0; j < min(3, (int)englishTop.size()); j++) {
            if (i == j) continue;

            char c1 = topChars[i];    // ������������ַ�
            char p1 = englishTop[j];  // ������������ַ�������Ϊ'e'��

            for (int k = 1; k < min(3, (int)topChars.size()); k++) {
                if (k == i) continue;
                for (int l = 1; l < min(3, (int)englishTop.size()); l++) {
                    if (l == j) continue;

                    char c2 = topChars[k];    // �����еڶ��������ַ�
                    char p2 = englishTop[l];  // �����еڶ��������ַ�������Ϊ't'��

                    // �ⷽ����: 
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

                    // ���ɽ��ܽ��
                    string plaintext = affineDecrypt(ciphertext, a, b);
                    candidates.emplace_back(plaintext, make_pair(a, b));
                }
            }
        }
    }

    // ȥ��
    sort(candidates.begin(), candidates.end());
    auto last = unique(candidates.begin(), candidates.end());
    candidates.erase(last, candidates.end());

    return candidates;
}

// �ƽ���滻���루����Ƶ��ӳ�䣩
string crackSubstitution(const string& ciphertext) {
    string processed = preprocessText(ciphertext);
    map<char, double> freq = calculateFrequency(processed);

    // �����ַ���Ƶ������
    vector<char> cipherSorted = getSortedByFrequency(freq);

    // Ӣ���ַ���Ƶ������
    vector<pair<char, double>> englishFreqVec(ENGLISH_FREQ.begin(), ENGLISH_FREQ.end());
    sort(englishFreqVec.begin(), englishFreqVec.end(),
        [](const pair<char, double>& a, const pair<char, double>& b) {
            return a.second > b.second;
        });

    vector<char> englishSorted;
    for (const auto& pair : englishFreqVec) {
        englishSorted.push_back(pair.first);
    }

    // �����滻ӳ��
    map<char, char> substitutionMap;
    for (size_t i = 0; i < cipherSorted.size(); i++) {
        if (i < englishSorted.size()) {
            substitutionMap[cipherSorted[i]] = englishSorted[i];
        }
        else {
            substitutionMap[cipherSorted[i]] = '?'; // δ֪ӳ��
        }
    }

    // Ӧ���滻ӳ��
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

// �Զ�����������Ͳ��ƽ�
vector<string> autoCrack(const string& ciphertext) {
    vector<string> results;

    // �ȳ��Կ������루��򵥣�
    auto caesarResults = crackCaesar(ciphertext);
    for (const auto& pair : caesarResults) {
        results.push_back("�����ǿ������루��λ " + to_string(pair.second) + "��:\n" + pair.first + "\n");
    }

    // ���Է�������
    auto affineResults = crackAffine(ciphertext);
    for (const auto& pair : affineResults) {
        results.push_back("�����Ƿ������루a=" + to_string(pair.second.first) +
            ", b=" + to_string(pair.second.second) + "��:\n" + pair.first + "\n");
    }

    // �����滻����
    string substitutionResult = crackSubstitution(ciphertext);
    results.push_back("�������滻����:\n" + substitutionResult + "\n");

    return results;
}

int main(int argc, char* argv[]) {
    try {
        // ���������в���
        Args args = parseArgs(argc, argv);

        // ��ȡ����
        string ciphertext = readFile(args.inputFile);
        cout << "�Ѷ�ȡ�����ļ�: " << args.inputFile << " (" << ciphertext.size() << " �ַ�)" << endl;

        // Ԥ��������Ƶ��
        string processed = preprocessText(ciphertext);
        map<char, double> freq = calculateFrequency(processed);

        if (args.showFrequency) {
            displayFrequency(freq);
        }

        // �ƽ�����
        vector<string> results;
        cout << "��ʼ�ƽ�..." << endl;

        switch (args.cipherType) {
        case CAESAR: {
            auto caesarResults = crackCaesar(ciphertext);
            for (size_t i = 0; i < min(5, (int)caesarResults.size()); i++) { // ��ʾ����ܵ�5�����
                results.push_back("�������루��λ " + to_string(caesarResults[i].second) + "��:\n" + caesarResults[i].first + "\n");
            }
            break;
        }
        case AFFINE: {
            auto affineResults = crackAffine(ciphertext);
            for (size_t i = 0; i < min(5, (int)affineResults.size()); i++) {
                results.push_back("�������루a=" + to_string(affineResults[i].second.first) +
                    ", b=" + to_string(affineResults[i].second.second) + "��:\n" + affineResults[i].first + "\n");
            }
            break;
        }
        case SUBSTITUTION: {
            string substitutionResult = crackSubstitution(ciphertext);
            results.push_back("�滻����:\n" + substitutionResult + "\n");
            break;
        }
        case AUTO:
            results = autoCrack(ciphertext);
            break;
        }

        // ������
        string output;
        for (const string& res : results) {
            output += res + "\n";
        }

        if (!args.outputFile.empty()) {
            writeFile(args.outputFile, output);
            cout << "�ƽ����ѱ��浽: " << args.outputFile << endl;
        }
        else {
            cout << "\n�ƽ���:\n" << output << endl;
        }

        cout << "��ʾ���滻������ƽ���������Ҫ�ֶ��������ܵõ���ȫ��ȷ������" << endl;

    }
    catch (const exception& e) {
        cerr << "����: " << e.what() << endl;
        cerr << "ʹ�� -h �� --help �鿴������Ϣ" << endl;
        return 1;
    }

    return 0;
}
