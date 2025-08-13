#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <fstream>

using namespace std;

// 大整数类，用于处理ECC中的大数字运算
class BigInt {
private:
    string value;

    // 辅助函数：移除前导零
    void removeLeadingZeros() {
        size_t start = 0;
        while (start < value.size() && value[start] == '0') {
            start++;
        }
        if (start == value.size()) {
            value = "0";
        }
        else {
            value = value.substr(start);
        }
    }

public:
    // 构造函数
    BigInt() : value("0") {}
    BigInt(const string& s) : value(s) { removeLeadingZeros(); }
    BigInt(unsigned long long n) : value(to_string(n)) {}

    // 转换为字符串
    string toString() const { return value; }

    // 比较运算符
    bool operator==(const BigInt& other) const {
        return value == other.value;
    }

    bool operator!=(const BigInt& other) const {
        return !(*this == other);
    }

    bool operator<(const BigInt& other) const {
        if (value.size() != other.value.size()) {
            return value.size() < other.value.size();
        }
        return value < other.value;
    }

    bool operator>(const BigInt& other) const {
        return other < *this;
    }

    bool operator<=(const BigInt& other) const {
        return !(*this > other);
    }

    bool operator>=(const BigInt& other) const {
        return !(*this < other);
    }

    // 加法
    BigInt operator+(const BigInt& other) const {
        string result;
        int i = value.size() - 1;
        int j = other.value.size() - 1;
        int carry = 0;

        while (i >= 0 || j >= 0 || carry > 0) {
            int sum = carry;
            if (i >= 0) sum += value[i--] - '0';
            if (j >= 0) sum += other.value[j--] - '0';

            carry = sum / 10;
            result.insert(result.begin(), (sum % 10) + '0');
        }

        return BigInt(result);
    }

    // 减法（假设*this >= other）
    BigInt operator-(const BigInt& other) const {
        string result;
        int i = value.size() - 1;
        int j = other.value.size() - 1;
        int borrow = 0;

        while (i >= 0 || j >= 0) {
            int diff = (i >= 0 ? value[i--] - '0' : 0) - borrow;
            if (j >= 0) diff -= other.value[j--] - '0';

            if (diff < 0) {
                diff += 10;
                borrow = 1;
            }
            else {
                borrow = 0;
            }

            result.insert(result.begin(), diff + '0');
        }

        return BigInt(result);
    }

    // 乘法
    BigInt operator*(const BigInt& other) const {
        if (*this == BigInt("0") || other == BigInt("0")) {
            return BigInt("0");
        }

        vector<int> result(value.size() + other.value.size(), 0);

        for (int i = value.size() - 1; i >= 0; i--) {
            int digit1 = value[i] - '0';
            for (int j = other.value.size() - 1; j >= 0; j--) {
                int digit2 = other.value[j] - '0';
                int product = digit1 * digit2;
                int p1 = i + j;
                int p2 = i + j + 1;
                int sum = product + result[p2];

                result[p1] += sum / 10;
                result[p2] = sum % 10;
            }
        }

        string resultStr;
        for (int digit : result) {
            if (!(resultStr.empty() && digit == 0)) {
                resultStr += to_string(digit);
            }
        }

        return BigInt(resultStr.empty() ? "0" : resultStr);
    }

    // 模运算
    BigInt operator%(const BigInt& mod) const {
        BigInt remainder("0");
        for (char c : value) {
            int digit = c - '0';
            remainder = remainder * BigInt("10") + BigInt(to_string(digit));

            if (remainder >= mod) {
                // 简单的减法实现，实际中可以更优化
                while (remainder >= mod) {
                    remainder = remainder - mod;
                }
            }
        }
        return remainder;
    }

    // 幂模运算: (base^exponent) % mod
    static BigInt powMod(const BigInt& base, const BigInt& exponent, const BigInt& mod) {
        if (mod == BigInt("1")) return BigInt("0");
        BigInt result("1");
        BigInt b = base % mod;
        BigInt e = exponent;

        while (e > BigInt("0")) {
            if (e % BigInt("2") == BigInt("1")) {
                result = (result * b) % mod;
            }
            e = e / BigInt("2");
            b = (b * b) % mod;
        }
        return result;
    }

    // 除法（整数除法）
    BigInt operator/(const BigInt& other) const {
        if (other == BigInt("0")) {
            throw runtime_error("Division by zero");
        }
        if (*this < other) {
            return BigInt("0");
        }

        string result;
        BigInt current;
        size_t i = 0;

        while (i < value.size()) {
            // 将下一位数字添加到当前值
            current = current * BigInt("10") + BigInt(string(1, value[i]));
            i++;

            // 找到最大的商数
            int q = 0;
            while (current >= other * BigInt(to_string(q + 1))) {
                q++;
            }

            result += to_string(q);
            current = current - other * BigInt(to_string(q));
        }

        return BigInt(result);
    }
};

// 椭圆曲线上的点
struct Point {
    BigInt x, y;
    bool isInfinity; // 无穷远点

    Point() : isInfinity(true) {}
    Point(const BigInt& x, const BigInt& y) : x(x), y(y), isInfinity(false) {}

    bool operator==(const Point& other) const {
        if (isInfinity && other.isInfinity) return true;
        if (isInfinity || other.isInfinity) return false;
        return x == other.x && y == other.y;
    }

    bool operator!=(const Point& other) const {
        return !(*this == other);
    }
};

// ECC参数 - 使用secp256k1曲线
struct ECCParams {
    // 曲线方程: y² = x³ + a*x + b
    BigInt a, b;
    // 有限域的阶
    BigInt p;
    // 基点
    Point G;
    // 基点的阶
    BigInt n;

    ECCParams() {
        // secp256k1参数
        a = BigInt("0");
        b = BigInt("7");
        p = BigInt("115792089237316195423570985008687907853269984665640564039457584007908834671663");
        G = Point(
            BigInt("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
            BigInt("32670510020758816978083085130507043184471273380659243275938904335757337482424")
        );
        n = BigInt("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    }
};

// ECC工具类
class ECC {
private:
    ECCParams params;

    // 计算椭圆曲线上两点之和
    Point addPoints(const Point& P, const Point& Q) const {
        if (P.isInfinity) return Q;
        if (Q.isInfinity) return P;
        if (P.x == Q.x && P.y != Q.y) return Point(); // 无穷远点

        BigInt lambda;

        if (P == Q) {
            // 点加倍
            BigInt numerator = (BigInt("3") * P.x * P.x + params.a) % params.p;
            BigInt denominator = (BigInt("2") * P.y) % params.p;
            lambda = multiplyMod(numerator, modInverse(denominator, params.p), params.p);
        }
        else {
            // 点相加
            BigInt numerator = (Q.y - P.y) % params.p;
            BigInt denominator = (Q.x - P.x) % params.p;
            lambda = multiplyMod(numerator, modInverse(denominator, params.p), params.p);
        }

        BigInt x3 = (lambda * lambda - P.x - Q.x) % params.p;
        BigInt y3 = (lambda * (P.x - x3) - P.y) % params.p;

        // 确保结果为正数
        if (x3 < BigInt("0")) x3 = x3 + params.p;
        if (y3 < BigInt("0")) y3 = y3 + params.p;

        return Point(x3, y3);
    }

    // 点乘运算（使用快速幂算法）
    Point multiplyPoint(const Point& P, const BigInt& scalar) const {
        Point result; // 无穷远点
        Point current = P;
        BigInt n = scalar;

        while (n > BigInt("0")) {
            if (n % BigInt("2") == BigInt("1")) {
                result = addPoints(result, current);
            }
            current = addPoints(current, current);
            n = n / BigInt("2");
        }

        return result;
    }

    // 模乘法
    BigInt multiplyMod(const BigInt& a, const BigInt& b, const BigInt& mod) const {
        return (a * b) % mod;
    }

    // 使用扩展欧几里得算法计算模逆 - 修复了const问题
    BigInt modInverse(const BigInt& a, const BigInt& mod) const {
        BigInt m0 = mod;
        BigInt a_copy = a;  // 使用局部副本，而不是修改参数
        BigInt mod_copy = mod;  // 使用局部副本，而不是修改参数
        BigInt y("0"), x("1");

        if (mod == BigInt("1"))
            return BigInt("0");

        while (a_copy > BigInt("1")) {
            BigInt q = a_copy / mod_copy;
            BigInt t = mod_copy;

            mod_copy = a_copy % mod_copy;
            a_copy = t;
            t = y;

            y = x - q * y;
            x = t;
        }

        if (x < BigInt("0"))
            x = x + m0;

        return x;
    }

    // 生成随机大整数
    BigInt generateRandom(const BigInt& max) const {
        srand(time(0) + rand()); // 增加随机性
        string result;
        int length = max.toString().size();

        // 生成与max同长度的随机数
        for (int i = 0; i < length; i++) {
            int digit = rand() % 10;
            result += to_string(digit);
        }

        BigInt randomNum(result);
        // 如果随机数大于max，则递归重新生成
        if (randomNum >= max) {
            return generateRandom(max);
        }

        return randomNum;
    }

public:
    ECC() : params(ECCParams()) {}

    // 生成密钥对
    pair<BigInt, Point> generateKeyPair() const {
        // 私钥是1到n-1之间的随机数
        BigInt privateKey = generateRandom(params.n - BigInt("1")) + BigInt("1");
        // 公钥是基点乘以私钥
        Point publicKey = multiplyPoint(params.G, privateKey);
        return { privateKey, publicKey };
    }

    // 加密
    pair<Point, Point> encrypt(const Point& publicKey, const string& plaintext) const {
        // 将明文转换为大整数
        BigInt m = stringToBigInt(plaintext);

        // 生成随机数k
        BigInt k = generateRandom(params.n - BigInt("1")) + BigInt("1");

        // 计算C1 = k * G
        Point C1 = multiplyPoint(params.G, k);

        // 计算C2 = m * G + k * publicKey
        Point kPublicKey = multiplyPoint(publicKey, k);
        Point mG = multiplyPoint(params.G, m);
        Point C2 = addPoints(mG, kPublicKey);

        return { C1, C2 };
    }

    // 解密
    string decrypt(const BigInt& privateKey, const Point& C1, const Point& C2) const {
        // 计算privateKey * C1
        Point privateKeyC1 = multiplyPoint(C1, privateKey);

        // 计算-mG = C2 - privateKey * C1
        Point negativePrivateKeyC1 = Point(privateKeyC1.x, (params.p - privateKeyC1.y) % params.p);
        Point mG = addPoints(C2, negativePrivateKeyC1);

        // 从点中提取明文（这里简化处理，实际应用需要更复杂的编码方案）
        BigInt m = mG.x;
        return bigIntToString(m);
    }

    // 将字符串转换为大整数
    BigInt stringToBigInt(const string& s) const {
        string result;
        for (char c : s) {
            // 将每个字符转换为3位数字
            stringstream ss;
            ss << setw(3) << setfill('0') << (int)c;
            result += ss.str();
        }
        return BigInt(result);
    }

    // 将大整数转换为字符串
    string bigIntToString(const BigInt& num) const {
        string s = num.toString();
        // 确保长度是3的倍数
        while (s.size() % 3 != 0) {
            s = "0" + s;
        }

        string result;
        for (size_t i = 0; i < s.size(); i += 3) {
            string sub = s.substr(i, 3);
            int val = stoi(sub);
            result += (char)val;
        }
        return result;
    }

    // 从字符串解析点
    Point parsePoint(const string& xStr, const string& yStr) const {
        if (xStr.empty() || yStr.empty()) {
            return Point(); // 无穷远点
        }
        return Point(BigInt(xStr), BigInt(yStr));
    }

    // 点转字符串
    string pointToString(const Point& p) const {
        if (p.isInfinity) {
            return "inf";
        }
        else {
            return p.x.toString() + "," + p.y.toString();
        }
    }
};

// 显示使用帮助
void printHelp() {
    cout << "ECC加密解密工具 (命令行版)" << endl;
    cout << "用法:" << endl;
    cout << "  ecc_cli.exe generate [私钥文件] [公钥文件] - 生成密钥对并保存到文件" << endl;
    cout << "  ecc_cli.exe encrypt [公钥文件] [明文文件] [密文文件] - 使用公钥加密" << endl;
    cout << "  ecc_cli.exe decrypt [私钥文件] [密文文件] [明文文件] - 使用私钥解密" << endl;
    cout << "  ecc_cli.exe help - 显示帮助信息" << endl;
}

// 读取文件内容
string readFile(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("无法打开文件: " + filename);
    }

    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return content;
}

// 写入文件内容
void writeFile(const string& filename, const string& content) {
    ofstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("无法写入文件: " + filename);
    }

    file << content;
}

// 保存密钥对
void saveKeyPair(const BigInt& privateKey, const Point& publicKey,
    const string& privateFile, const string& publicFile, ECC& ecc) {
    // 保存私钥
    writeFile(privateFile, privateKey.toString());

    // 保存公钥
    string publicKeyStr = ecc.pointToString(publicKey);
    writeFile(publicFile, publicKeyStr);
}

// 加载私钥
BigInt loadPrivateKey(const string& filename) {
    string content = readFile(filename);
    return BigInt(content);
}

// 加载公钥
Point loadPublicKey(const string& filename, ECC& ecc) {
    string content = readFile(filename);
    size_t commaPos = content.find(',');
    if (commaPos == string::npos) {
        throw runtime_error("无效的公钥格式");
    }

    string xStr = content.substr(0, commaPos);
    string yStr = content.substr(commaPos + 1);
    return ecc.parsePoint(xStr, yStr);
}

// 保存密文
void saveCiphertext(const Point& C1, const Point& C2, const string& filename, ECC& ecc) {
    string content = ecc.pointToString(C1) + "\n" + ecc.pointToString(C2);
    writeFile(filename, content);
}

// 加载密文
pair<Point, Point> loadCiphertext(const string& filename, ECC& ecc) {
    string content = readFile(filename);
    size_t newlinePos = content.find('\n');
    if (newlinePos == string::npos) {
        throw runtime_error("无效的密文格式");
    }

    string c1Str = content.substr(0, newlinePos);
    string c2Str = content.substr(newlinePos + 1);

    size_t comma1 = c1Str.find(',');
    size_t comma2 = c2Str.find(',');

    if (comma1 == string::npos || comma2 == string::npos) {
        throw runtime_error("无效的密文格式");
    }

    Point C1 = ecc.parsePoint(c1Str.substr(0, comma1), c1Str.substr(comma1 + 1));
    Point C2 = ecc.parsePoint(c2Str.substr(0, comma2), c2Str.substr(comma2 + 1));

    return { C1, C2 };
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            printHelp();
            return 1;
        }

        string command = argv[1];
        ECC ecc;

        if (command == "help") {
            printHelp();
        }
        else if (command == "generate") {
            if (argc != 4) {
                cerr << "用法错误: ecc_cli.exe generate [私钥文件] [公钥文件]" << endl;
                return 1;
            }

            cout << "正在生成密钥对..." << endl;
            auto keyPair = ecc.generateKeyPair();
            saveKeyPair(keyPair.first, keyPair.second, argv[2], argv[3], ecc);
            cout << "密钥对已生成并保存到文件:" << endl;
            cout << "私钥: " << argv[2] << endl;
            cout << "公钥: " << argv[3] << endl;
        }
        else if (command == "encrypt") {
            if (argc != 5) {
                cerr << "用法错误: ecc_cli.exe encrypt [公钥文件] [明文文件] [密文文件]" << endl;
                return 1;
            }

            cout << "正在加密..." << endl;
            Point publicKey = loadPublicKey(argv[2], ecc);
            string plaintext = readFile(argv[3]);
            auto ciphertext = ecc.encrypt(publicKey, plaintext);
            saveCiphertext(ciphertext.first, ciphertext.second, argv[4], ecc);
            cout << "加密完成，密文已保存到: " << argv[4] << endl;
        }
        else if (command == "decrypt") {
            if (argc != 5) {
                cerr << "用法错误: ecc_cli.exe decrypt [私钥文件] [密文文件] [明文文件]" << endl;
                return 1;
            }

            cout << "正在解密..." << endl;
            BigInt privateKey = loadPrivateKey(argv[2]);
            auto ciphertext = loadCiphertext(argv[3], ecc);
            string plaintext = ecc.decrypt(privateKey, ciphertext.first, ciphertext.second);
            writeFile(argv[4], plaintext);
            cout << "解密完成，明文已保存到: " << argv[4] << endl;
        }
        else {
            cerr << "未知命令: " << command << endl;
            printHelp();
            return 1;
        }
    }
    catch (const exception& e) {
        cerr << "错误: " << e.what() << endl;
        return 1;
    }

    return 0;
}
