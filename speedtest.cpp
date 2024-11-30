#include "speedtest.h"
void loadData8(std::vector<uint8_t>& data) {
    std::ifstream file("1kb2.bin", std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file." << std::endl;
        exit(0);
    }
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> Data(fileSize);
    if (!file.read(reinterpret_cast<char*>(Data.data()), fileSize)) {
        std::cerr << "Error: Cannot read file data." << std::endl;
        exit(0);
    }
    data = Data;
    file.close();
}

bool readBinaryFile(char buffer[1025]) {
    std::ifstream file("1kb.bin", std::ios::binary);

    // 检查文件是否成功打开
    if (!file) {
        std::cerr << "Error: Could not open file " << "1kb.bin" << std::endl;
        return false;
    }

    // 读取文件内容到缓冲区
    file.read(buffer, 1024);

    // 检查读取的字节数是否满足要求
    if (file.gcount() != 1024) {
        std::cerr << "Error: File size is not 1024 bytes." << std::endl;
        return false;
    }

    file.close();
    return true;
}
int main() {
    char data[1025] = { 0 }; // 用于存储文件内容的缓冲区
    std::vector<uint8_t> data8;
    loadData8(data8);
    readBinaryFile(data);
    std::cout << "           最小cpb   平均cpb     标准差" << std::endl;


    speed_original(data);
    speed_align(data);
    speed_unrolling(data);
    speed_all(data);
    speed_openssl((const unsigned char*)data);
    //speed_present(data8);
    //speed_present_s_I(data8);
    //speed_present_p_I(data8);
    //speed_present_sp_I(data8);
    //sbox_verify(data8);
    return 0;
}