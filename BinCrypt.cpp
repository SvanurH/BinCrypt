#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <windows.h>
#include <bcrypt.h>
#include <cctype>
#include <iomanip>
#pragma comment(lib, "bcrypt.lib")
const int AES_KEY_LEN = 32;
const int IV_LEN = 16;



const char* HeaderIncludeT = R"(
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <windows.h>
#include <bcrypt.h>
#include <cctype>
#pragma comment(lib, "bcrypt.lib")
const int AES_KEY_LEN = 32;
const int IV_LEN = 16;
)";

const char* Ipv4DeobfuscationT = R"(
std::vector<unsigned char> SplitIpv4(const std::string& ipv4) {
	std::vector<unsigned char> result;
	std::stringstream ss(ipv4);
	std::string item;

	while (std::getline(ss, item, '.')) {
		int num = std::stoi(item);
		if (num < 0 || num > 255) {
			// 不合法IPv4段，可以抛异常或返回空vector
			return {};
		}
		result.push_back(static_cast<unsigned char>(num));
	}
	// IPv4必须有4段
	if (result.size() != 4) {
		return {};
	}
	return result;
}
std::vector<unsigned char> Ipv4Deobfuscation(const std::vector<std::string> ipv4Array) {
	using namespace std;
	vector<unsigned char> result;
	for (size_t i = 0; i < ipv4Array.size(); i++) {
		for (unsigned char b : SplitIpv4(ipv4Array[i])) {
			result.push_back(b);
		}
	}
	return result;
}
)";

const char* Ipv6DeobfuscationT = R"(
std::vector<unsigned char> SplitIpv6(const std::string& ipv6) {
	std::vector<unsigned char> result(16, 0);
	size_t double_colon_pos = ipv6.find("::");
	std::vector<std::string> head_parts;
	std::vector<std::string> tail_parts;
	if (double_colon_pos == std::string::npos) {
		std::stringstream ss(ipv6);
		std::string part;
		while (std::getline(ss, part, ':')) {
			head_parts.push_back(part);
		}
		if (head_parts.size() != 8) {
			return {};
		}
	}
	else {
		std::string head = ipv6.substr(0, double_colon_pos);
		std::string tail = ipv6.substr(double_colon_pos + 2);
		if (!head.empty()) {
			std::stringstream ss(head);
			std::string part;
			while (std::getline(ss, part, ':')) {
				head_parts.push_back(part);
			}
		}
		if (!tail.empty()) {
			std::stringstream ss(tail);
			std::string part;
			while (std::getline(ss, part, ':')) {
				tail_parts.push_back(part);
			}
		}
		if (head_parts.size() + tail_parts.size() > 8) {
			return {};
		}
	}
	size_t index = 0;
	for (const auto& part : head_parts) {
		if (part.empty()) return {};
		unsigned int val;
		std::stringstream ss;
		ss << std::hex << part;
		ss >> val;
		if (val > 0xFFFF) return {};
		result[index++] = static_cast<unsigned char>((val >> 8) & 0xFF);
		result[index++] = static_cast<unsigned char>(val & 0xFF);
	}
	size_t zero_fill = 16 - (head_parts.size() + tail_parts.size()) * 2;
	index += zero_fill;
	for (const auto& part : tail_parts) {
		if (part.empty()) return {};
		unsigned int val;
		std::stringstream ss;
		ss << std::hex << part;
		ss >> val;
		if (val > 0xFFFF) return {};
		result[index++] = static_cast<unsigned char>((val >> 8) & 0xFF);
		result[index++] = static_cast<unsigned char>(val & 0xFF);
	}

	if (index != 16) {
		return {};
	}

	return result;
}
std::vector<unsigned char> Ipv6Deobfuscation(const std::vector<std::string> ipv6Array) {
	using namespace std;
	vector<unsigned char> result;
	for (size_t i = 0; i < ipv6Array.size(); i++) {
		for (unsigned char b : SplitIpv6(ipv6Array[i])) {
			result.push_back(b);
		}
	}
	return result;
}
)";

const char* AesDecryptT = R"(
bool AES_Decrypt(
	const std::vector<unsigned char>& key,
	const std::vector<unsigned char>& iv,
	const std::vector<unsigned char>& ciphertext,
	std::vector<unsigned char>& plaintext)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	NTSTATUS status;

	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (status != 0) return false;

	status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
		(PUCHAR)BCRYPT_CHAIN_MODE_CBC,
		sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (status != 0) return false;

	DWORD keyObjLen = 0, dataLen = 0;
	status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&keyObjLen, sizeof(keyObjLen), &dataLen, 0);
	std::vector<unsigned char> keyObj(keyObjLen);

	status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(),
		keyObjLen, (PUCHAR)key.data(), (ULONG)key.size(), 0);
	if (status != 0) return false;

	DWORD cbPlain = 0;
	status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
		NULL, (PUCHAR)iv.data(), (ULONG)iv.size(),
		NULL, 0, &cbPlain, BCRYPT_BLOCK_PADDING);
	if (status != 0) return false;

	plaintext.resize(cbPlain);

	status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
		NULL, (PUCHAR)iv.data(), (ULONG)iv.size(),
		plaintext.data(), cbPlain, &cbPlain,
		BCRYPT_BLOCK_PADDING);
	if (status != 0) {
		std::cout << "[-] status " << status << std::endl;
		return false;
	}

	plaintext.resize(cbPlain);

	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlg, 0);

	return true;
})";

const char* XorEncryptT = R"(
void XorEncrypt(std::vector<unsigned char>& data, unsigned char key) {
	for (size_t i = 0; i < data.size(); i++) {
		data[i] ^= key;
	}
}
)";

const char* StrDataT = R"(
const std::vector<std::string> ShellCode = {{ShellCode}};
)";

const char* BinDataT = R"(
const std::vector<unsigned char> ShellCode = {{ShellCode}};
)";

const char* XorDencryptCT = R"(
	std::vector<unsigned char> xorKeys = {{XorKeys}};
	for (unsigned char key : xorKeys) {
		XorEncrypt(buffer, key);
	}
)";

const char* AesDecryptCT = R"(
	std::vector<std::vector<unsigned char>> aesKeys = {{AesKeys}};
	std::vector<std::vector<unsigned char>> ivKeys = {{IvKeys}};
	for (size_t i = 0; i < aesKeys.size(); i++) {
		AES_Decrypt(aesKeys[i], ivKeys[i], buffer, buffer);
	}
)";

const char* Ipv4DeobfuscationCT = R"(
	buffer = Ipv4Deobfuscation(buffer1);
)";

const char* Ipv6DeobfuscationCT = R"(
	buffer = Ipv6Deobfuscation(buffer1);
)";

const char* MacDeobfuscationT = R"(
std::vector<unsigned char> MacDeobfuscation(const std::vector<std::string>& MacArray) {
    std::vector<unsigned char> result;
    result.reserve(MacArray.size() * 6);

    for (const auto& mac : MacArray) {
        unsigned int b[6] = {0};
        if (sscanf_s(mac.c_str(), "%2X-%2X-%2X-%2X-%2X-%2X",
                     &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
            for (int i = 0; i < 6; ++i) {
                result.push_back(static_cast<unsigned char>(b[i]));
            }
        }
    }
    return result;
}
)";

const char* MacDeobfuscationCT = R"(
	buffer = MacDeobfuscation(buffer1);
)";

const char* MainT = R"(
int main(){
	auto buffer1 = ShellCode;
	std::vector<unsigned char> buffer;
	{{Code}}
	for (unsigned char k:buffer) {
			printf("0x%02X ",k);
		}
	return 0;
}
)";


std::vector<unsigned char> ReadBinFile(const std::string& filePath) {
	using namespace std;
	cout << "[i] Reading ：" << filePath << endl;
	ifstream file(filePath, ios::binary | ios::ate);
	if (!file) {
		cerr << "[-] Faild To Open：" << filePath << endl;
		return {};
	}
	streamsize size = file.tellg();
	if (size <= 0) {
		cerr << "[-] File Is Too Small Or Empty：" << filePath << endl;
		return {};
	}
	file.seekg(0, ios::beg);
	vector<char> buffer(size);
	if (!file.read(buffer.data(), size)) {
		cerr << "[-] Faild To Read： " << filePath << endl;
		return {};
	}
	vector<unsigned char> ucBuffer(buffer.begin(), buffer.end());
	return ucBuffer;
}

bool WriteBinFile(const std::string& filepath, const std::vector<unsigned char>& data) {
	std::ofstream out(filepath, std::ios::binary);
	if (!out) {
		std::cerr << "无法打开文件进行写入: " << filepath << std::endl;
		return false;
	}

	// data.data() 返回指向数据首地址的指针，data.size() 返回大小
	out.write(reinterpret_cast<const char*>(data.data()), data.size());
	if (!out) {
		std::cerr << "写入文件失败\n";
		return false;
	}

	out.close();
	return true;
}

bool WriteStrFile(const std::string& filepath, const std::vector<std::string>& content) {
	std::ofstream out(filepath); // 默认是文本模式
	if (!out) {
		std::cerr << "无法打开文件进行写入: " << filepath << std::endl;
		return false;
	}

	for (const auto& line : content) {
		out << line << "\n"; // 每个字符串单独写入，并换行
		if (!out) {
			std::cerr << "写入文件失败\n";
			return false;
		}
	}

	return true;
}

void PrintHex(std::vector<unsigned char> data) {
	using namespace std;
	if (!data.empty()) {
		for (size_t i = 0; i < data.size(); ++i) {
			if (i % 16 == 0) {
				cout << endl;
				printf("\t");
			}
			printf("%02X ", static_cast<unsigned char>(data[i]));
		}
		cout << endl;
	}
}

void XorEncrypt(std::vector<unsigned char>& data, unsigned char key) {
	for (size_t i = 0; i < data.size(); i++) {
		data[i] ^= key;
	}
}

std::string GenerateIpv4(int a, int b, int c, int d) {
	char output[32];
	sprintf_s(output, "%d.%d.%d.%d", a, b, c, d);
	return std::string(output);
}

std::vector<std::string> GenerateIpv4Output(const std::vector<unsigned char>& data) {
	std::vector<std::string> result;
	if (data.empty()) {
		return result; // 空vector
	}

	size_t paddedSize = (data.size() + 3) / 4 * 4; // 补齐到4的倍数
	std::vector<unsigned char> temp = data;
	temp.resize(paddedSize, 0x00); // 补0

	for (size_t i = 0; i < temp.size(); i += 4) {
		result.push_back(GenerateIpv4(temp[i], temp[i + 1], temp[i + 2], temp[i + 3]));
	}
	return result;
}


std::string GenerateIpv6(
	int a1, int a2, int a3, int a4,
	int a5, int a6, int a7, int a8,
	int a9, int a10, int a11, int a12,
	int a13, int a14, int a15, int a16)
{
	char buffer[128];  // 足够大，避免溢出

	char output1[32], output2[32], output3[32], output4[32];

	sprintf_s(output1, "%02X%02X:%02X%02X", a1, a2, a3, a4);
	sprintf_s(output2, "%02X%02X:%02X%02X", a5, a6, a7, a8);
	sprintf_s(output3, "%02X%02X:%02X%02X", a9, a10, a11, a12);
	sprintf_s(output4, "%02X%02X:%02X%02X", a13, a14, a15, a16);
	sprintf_s(buffer, "%s:%s:%s:%s", output1, output2, output3, output4);

	return std::string(buffer);
}

std::vector<std::string> GenerateIpv6Output(const std::vector<unsigned char>& data) {
	std::vector<std::string> result;
	if (data.empty()) {
		return result;  // 空vector
	}

	// 补齐到16的倍数
	size_t paddedSize = (data.size() + 15) / 16 * 16;
	std::vector<unsigned char> temp = data;
	temp.resize(paddedSize, 0x00);  // 补0

	for (size_t i = 0; i < temp.size(); i += 16) {
		// 调用GenerateIpv6，注意传16个字节转换成int传参
		result.push_back(GenerateIpv6(
			temp[i], temp[i + 1], temp[i + 2], temp[i + 3],
			temp[i + 4], temp[i + 5], temp[i + 6], temp[i + 7],
			temp[i + 8], temp[i + 9], temp[i + 10], temp[i + 11],
			temp[i + 12], temp[i + 13], temp[i + 14], temp[i + 15]
		));
	}
	return result;
}

std::string GenerateMac(int a1, int a2, int a3, int a4, int a5, int a6) {
	char output[64];
	sprintf_s(output, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", a1, a2, a3, a4, a5, a6);
	std::string result(output);
	return result;
}

std::vector<std::string>GenerateMacOutput(const std::vector<unsigned char> data) {
	using namespace std;
	vector<string> result;
	if (data.empty()) {
		return result;
	}
	size_t paddedSize = (data.size() + 5) / 6 * 6;
	std::vector<unsigned char> temp = data;
	temp.resize(paddedSize, 0x00);  // 补0
	for (size_t i = 0; i < temp.size(); i += 6) {
		result.push_back(GenerateMac(temp[i], temp[i + 1], temp[i + 2], temp[i + 3], temp[i + 4], temp[i + 5]));
	}
	return result;
}


bool AES_Encrypt(
	const std::vector<unsigned char>& key,
	const std::vector<unsigned char>& iv,
	const std::vector<unsigned char>& plaintext,
	std::vector<unsigned char>& ciphertext)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	NTSTATUS status;

	// 打开 AES 算法
	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (status != 0) return false;

	// 设置 CBC 模式
	status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
		(PUCHAR)BCRYPT_CHAIN_MODE_CBC,
		sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (status != 0) return false;

	// 获取 Key 对象长度
	DWORD keyObjLen = 0, dataLen = 0;
	status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&keyObjLen, sizeof(keyObjLen), &dataLen, 0);
	std::vector<unsigned char> keyObj(keyObjLen);

	// 生成 AES Key
	status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(),
		keyObjLen, (PUCHAR)key.data(), (ULONG)key.size(), 0);
	if (status != 0) return false;

	// 计算密文缓冲区大小
	DWORD cbCipher = 0;
	status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
		NULL, (PUCHAR)iv.data(), (ULONG)iv.size(),
		NULL, 0, &cbCipher, BCRYPT_BLOCK_PADDING);
	if (status != 0) return false;

	ciphertext.resize(cbCipher);

	// 执行加密
	status = BCryptEncrypt(hKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
		NULL, (PUCHAR)iv.data(), (ULONG)iv.size(),
		ciphertext.data(), cbCipher, &cbCipher,
		BCRYPT_BLOCK_PADDING);
	if (status != 0) return false;

	ciphertext.resize(cbCipher);

	// 清理
	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlg, 0);

	return true;
}


bool GenerateRandomBytes(std::vector<unsigned char>& buffer) {
	if (buffer.empty()) return false;
	NTSTATUS status = BCryptGenRandom(
		nullptr,  // 默认 RNG 句柄
		buffer.data(),
		static_cast<ULONG>(buffer.size()),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG
	);
	if (status != 0) {
		printf("[-] BCryptGenRandom failed, status=0x%08X\n", status);
		return false;
	}
	return true;
}

std::string GetArgValue(int argc, char* argv[], const std::string& key) {
	for (int i = 0; i < argc - 1; ++i) {
		if (key == argv[i]) {
			return argv[i + 1];
		}
	}
	return "";
}

bool HasArg(int argc, char* argv[], const std::string& key) {
	for (int i = 0; i < argc; ++i) {
		if (key == argv[i]) {
			return true;
		}
	}
	return false;
}

bool IsInteger(const std::string& s) {
	if (s.empty()) return false;
	size_t start = 0;
	if (s[0] == '-' || s[0] == '+') start = 1;
	if (start == s.size()) return false;  // 只有符号，没有数字

	for (size_t i = start; i < s.size(); ++i) {
		if (!std::isdigit(s[i])) return false;
	}
	return true;
}

std::vector<unsigned char> CycleXor(std::vector<unsigned char> data, int num, std::vector<unsigned char>& oKeys) {
	using namespace std;
	vector<unsigned char> keys(num);
	if (!GenerateRandomBytes(keys)) {
		printf("[-] Generate Xor Keys Error \n");
		return {};
	}
	vector<unsigned char> buffer = data;
	for (size_t i = 0; i < keys.size(); i++) {
		printf("\t\t%dth Xor Encrypt\n", (int)i + 1);
		printf("[i] %dth Encryption,Key is:  0x%02X \n", (int)i + 1, keys[i]);
		XorEncrypt(buffer, keys[i]);
		PrintHex(buffer);
		printf("------------------------------------------------\n");
	}
	oKeys = keys;
	return buffer;
}

std::vector<unsigned char> CycleAes(std::vector<unsigned char> data, int num, std::vector<std::vector<unsigned char>>& oKeys, std::vector<std::vector<unsigned char>>& oIvs) {
	using namespace std;
	vector<vector<unsigned char>> keys(num, vector<unsigned char>(AES_KEY_LEN, 0));
	vector<vector<unsigned char>> ivs(num, vector<unsigned char>(IV_LEN, 0));

	for (int i = 0; i < num; i++) {
		printf("\t\t%dth Aes Encrypt\n", (int)i + 1);
		if (!GenerateRandomBytes(keys[i])) {
			printf("[-] Generate Aes Key Error\n");
			return {};
		}
		if (!GenerateRandomBytes(ivs[i])) {
			printf("[-] Generate Aes IV Error\n");
			return {};
		}
		printf("[i] %dth Key is: ", i + 1);
		PrintHex(keys[i]);
		printf("[i] %dth Iv is: ", i + 1);
		PrintHex(ivs[i]);
		vector<unsigned char>iv = ivs[i];
		vector<unsigned char> ciphertext;
		if (!AES_Encrypt(keys[i], iv, data, ciphertext)) {
			printf("[-] AES Encryption failed at round %d\n", i + 1);
			return {};
		}
		printf("[i] Encrypt: ");
		PrintHex(ciphertext);
		printf("------------------------------------------------\n");
		data = ciphertext;
	}
	oKeys = keys;
	oIvs = ivs;

	// 返回最终加密结果
	return data;
}

bool WriteStringToFile(const std::string& filename, const std::string& content) {
	std::ofstream ofs(filename, std::ios::out | std::ios::trunc);
	if (!ofs.is_open()) {
		std::cerr << "无法打开文件: " << filename << std::endl;
		return false;
	}
	ofs << content;
	return true;
}

std::vector<unsigned char> XorHandle(int argc, char* argv[], std::vector<unsigned char> data, std::vector<unsigned char>& oKeys) {
	bool useXor = HasArg(argc, argv, "-xor");
	if (useXor) {
		std::string xorValue = GetArgValue(argc, argv, "-xor");
		if (!IsInteger(xorValue)) {
			printf("[-] Param Value Error: \"-xor <num>\"\n");
			return {};
		}
		int xorNum = std::stoi(xorValue);
		return CycleXor(data, xorNum, oKeys);
	}
	return {};
}

std::vector<unsigned char> AesHandle(int argc, char* argv[], std::vector<unsigned char> data, std::vector<std::vector<unsigned char>>& oKeys, std::vector<std::vector<unsigned char>>& oIvs) {
	bool useAes = HasArg(argc, argv, "-aes");
	if (useAes) {
		std::string aesValue = GetArgValue(argc, argv, "-aes");
		if (!IsInteger(aesValue)) {
			printf("[-] ParamValue Error: \"-aes <num>\"\n");
			return {};
		}
		int aesNum = std::stoi(aesValue);
		return CycleAes(data, aesNum, oKeys, oIvs);
	}
	return {};
}

std::vector<std::string> ObfHandle(int argc, char* argv[], std::vector<unsigned char> data) {
	bool useObf = HasArg(argc, argv, "-obf");
	std::string obfMode = GetArgValue(argc, argv, "-obf");
	std::vector<std::string> output;
	if (!useObf) {
		return {};
	}
	if (obfMode == "ipv4") {
		output = GenerateIpv4Output(data);
	}
	else if (obfMode == "ipv6") {
		output = GenerateIpv6Output(data);
	}
	else if (obfMode == "mac") {
		output = GenerateMacOutput(data);
	}
	else {
		return {};
	}
	printf("\t\tobf Mode: %s\n", obfMode.c_str());
	for (std::string c : output) {
		printf("\t%s\n", c.c_str());
	}
	return output;
}

template <typename T>
std::string FormatArray(const std::vector<T>& data) {
	std::ostringstream oss;
	oss << "{";
	for (size_t i = 0; i < data.size(); ++i) {
		if constexpr (std::is_same_v<T, std::string>) {
			// 字符串类型加引号
			oss << "\"" << data[i] << "\"";
		}
		else if constexpr (std::is_same_v<T, unsigned char> || std::is_same_v<T, char>) {
			// 字节类型 0xXX 格式
			oss << "0x" << std::hex << std::uppercase
				<< std::setw(2) << std::setfill('0')
				<< static_cast<int>(static_cast<unsigned char>(data[i]))
				<< std::dec;
		}
		else if constexpr (std::is_same_v<T, bool>) {
			// 布尔类型 true / false
			oss << (data[i] ? "true" : "false");
		}
		else if constexpr (std::is_same_v<T, std::vector<unsigned char>>) {
			// 嵌套的字节数组
			oss << FormatArray(data[i]);
		}
		else if constexpr (std::is_same_v<T, std::vector<T>>) {
			// 泛化递归（理论上可以支持无限嵌套）
			oss << FormatArray(data[i]);
		}
		else {
			// 其他类型直接输出
			oss << data[i];
		}
		if (i != data.size() - 1) {
			oss << ",";
		}
	}
	oss << "}";
	return oss.str();
}

void ReplaceAll(std::string& str, const std::string& from, const std::string& to) {
	size_t pos = 0;
	while ((pos = str.find(from, pos)) != std::string::npos) {
		str.replace(pos, from.length(), to);
		pos += to.length();
	}
}

template <typename T>
void Decrypted(int argc, char* argv[], std::vector<T> data, std::vector<unsigned char> oKeys, std::vector<std::vector<unsigned char>> oAKeys, std::vector<std::vector<unsigned char>> oIvs) {
	std::reverse(oKeys.begin(), oKeys.end());
	std::reverse(oAKeys.begin(), oAKeys.end());
	std::reverse(oIvs.begin(), oIvs.end());
	std::string buffer = "";
	std::string mainBuffer = MainT;
	std::string codeBuffer = "";
	buffer += HeaderIncludeT;
	if (std::is_same_v < T, std::string>) {
		buffer += StrDataT;
		ReplaceAll(buffer, "{{ShellCode}}", FormatArray(data));
	}
	else if (std::is_same_v<T, unsigned char>) {
		buffer += BinDataT;
		ReplaceAll(buffer, "{{ShellCode}}", FormatArray(data));
	}

	if (HasArg(argc, argv, "-obf")) {
		std::string temp = GetArgValue(argc, argv, "-obf");
		if (temp == "ipv4") {
			buffer += Ipv4DeobfuscationT;
			codeBuffer += Ipv4DeobfuscationCT;
		}
		else if (temp == "ipv6") {
			buffer += Ipv6DeobfuscationT;
			codeBuffer += Ipv6DeobfuscationCT;
		}
		else if (temp == "mac") {
			buffer += MacDeobfuscationT;
			codeBuffer += MacDeobfuscationCT;
		}
	}
	else {
		codeBuffer += R"(
	buffer = buffer1;
)";
	}
	std::string secArg = argv[3];
	if (secArg == "-xor") {

		if (!oAKeys.empty()) {
			buffer += AesDecryptT;
			codeBuffer += AesDecryptCT;
			ReplaceAll(codeBuffer, "{{AesKeys}}", FormatArray(oAKeys));
			ReplaceAll(codeBuffer, "{{IvKeys}}", FormatArray(oIvs));
		}
		if (!oKeys.empty()) {
			buffer += XorEncryptT;
			codeBuffer += XorDencryptCT;
			ReplaceAll(codeBuffer, "{{XorKeys}}", FormatArray(oKeys));
		}

	}
	else if (secArg == "-aes") {
		if (!oKeys.empty()) {
			buffer += XorEncryptT;
			codeBuffer += XorDencryptCT;
			ReplaceAll(codeBuffer, "{{XorKeys}}", FormatArray(oKeys));
		}
		if (!oAKeys.empty()) {
			buffer += AesDecryptT;
			codeBuffer += AesDecryptCT;
			ReplaceAll(codeBuffer, "{{AesKeys}}", FormatArray(oAKeys));
			ReplaceAll(codeBuffer, "{{IvKeys}}", FormatArray(oIvs));
		}
	}

	ReplaceAll(mainBuffer, "{{Code}}", codeBuffer);
	std::string filename = "decrypted.cpp";
	WriteStringToFile(filename, buffer + mainBuffer);
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("[-] Less 2 Params\n");
		printf(R"(usage:
	-i <inputFile> -xor <num> -aes <num> -obf <ipv4,ipv6,mac> -o <outputFile>
eg:
	-i in.bin -xor 10 -aes 10 -obf ipv4 -o out.txt
warnning:
	If the obf parameter is not used, the file suffix remains unchanged.
)");
		return -1;
	}
	// ----------------------------------------------------------
	std::string inputFile = GetArgValue(argc, argv, "-i");
	if (inputFile.empty()) {
		printf("[-] You Must Input Target File \"-i <FileName>\" \n");
		return -1;
	}
	std::vector<unsigned char> data = ReadBinFile(inputFile);
	if (data.empty()) {
		printf("[-] Faild ReadBinFile: %s\n", inputFile.c_str());
		return -1;
	}
	printf("[+] Success ReadBinFile: %s\n", inputFile.c_str());
	printf("------------------------------------------------\n");
	// -----------------------------------------------------------
	std::vector<unsigned char> buffer;
	std::vector<unsigned char> buffer2;  // 临时判断
	std::string secArg = argv[3];

	std::vector<unsigned char> oKeys;
	std::vector<std::vector<unsigned char>> oAKeys;
	std::vector<std::vector<unsigned char>> oIvs;

	if (secArg == "-xor") {
		buffer = XorHandle(argc, argv, data, oKeys);
		buffer2 = AesHandle(argc, argv, buffer, oAKeys, oIvs);
		if (!buffer2.empty()) {  // 判断是否用了单个参数
			buffer = buffer2;
		}
	}
	else if (secArg == "-aes") {
		buffer = AesHandle(argc, argv, data, oAKeys, oIvs);
		buffer2 = XorHandle(argc, argv, buffer, oKeys);
		if (!buffer2.empty()) {  // 单个参数
			buffer = buffer2;
		}
	}
	// -----------------------------------------------------------
	std::vector<std::string> ObfString = ObfHandle(argc, argv, buffer);
	if (HasArg(argc, argv, "-obf")) {
		auto buffer3 = ObfString;
		Decrypted(argc, argv, buffer3, oKeys, oAKeys, oIvs);
	}
	else {
		auto buffer3 = buffer;
		Decrypted(argc, argv, buffer3, oKeys, oAKeys, oIvs);
	}
	// -----------------------------------------------------------
	std::string outputFile = GetArgValue(argc, argv, "-o");
	if (!outputFile.empty() && !HasArg(argc, argv, "-obf")) {
		WriteBinFile(outputFile, buffer);
	}
	else if (!outputFile.empty() && HasArg(argc, argv, "-obf")) {
		WriteStrFile(outputFile, ObfString);
	}
}
