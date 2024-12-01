#include "speedtest.h"

bool readBinaryFile(char buffer[1025]) {
    std::ifstream file("1kb.bin", std::ios::binary);

    // ����ļ��Ƿ�ɹ���
    if (!file) {
        std::cerr << "Error: Could not open file " << "1kb.bin" << std::endl;
        return false;
    }

    // ��ȡ�ļ����ݵ�������
    file.read(buffer, 1024);

    // ����ȡ���ֽ����Ƿ�����Ҫ��
    if (file.gcount() != 1024) {
        std::cerr << "Error: File size is not 1024 bytes." << std::endl;
        return false;
    }

    file.close();
    return true;
}
int main() {
    char data[1025] = { 0 }; // ���ڴ洢�ļ����ݵĻ�����
    readBinaryFile(data);
    std::cout << "           ��Сcpb   ƽ��cpb     ��׼��" << std::endl;


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