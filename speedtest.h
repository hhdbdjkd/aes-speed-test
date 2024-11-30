#ifndef _SPEEDTEST_H_
#define _SPEEDTEST_H_
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <intrin.h>
#include <cmath>
#include <functional>
#define loops 2000
#define len 1024

void speed_openssl(const unsigned char* data);

void speed_original(char* data);

void speed_all(char* data);

void speed_align(char* data);

void speed_detect(char* data);

void speed_unrolling(char* data);

void speed_present(const std::vector<uint8_t>& data);

void speed_present_s_I(const std::vector<uint8_t>& data);

void speed_present_p_I(const std::vector<uint8_t>& data);

void speed_present_sp_I(const std::vector<uint8_t>& data);

void sbox_verify(const std::vector<uint8_t>& data);

#endif