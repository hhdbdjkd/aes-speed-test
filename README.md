# AES 加密速度对比与优化

本项目是一个密码学实验，旨在对比 **libtomcrypt** 和 **OpenSSL** 的 AES 加密速度，并通过优化 **libtomcrypt** 的 AES 实现以提升加密性能。项目在Visual Studio运行

------

## 项目特点

1. **速度对比**：
   - 对比 **libtomcrypt** 和 **OpenSSL** 的 AES 加密性能。
   - 测试同等数据量下ECB加密模式的两个库的AES速度差异。
2. **优化 libtomcrypt AES**：
   - 分析 **libtomcrypt** 原始 AES 实现中的性能瓶颈。
   - 通过优化代码提高加密速度。
   - 提供优化前后的对比结果。
3. **详细的结果展示**：
   - 包括优化前后的性能数据。
   - 展示加密速度提升效果。



# AES Speed Comparison and Optimization

This repository contains a cryptographic experiment project focused on comparing the AES encryption speed between **libtomcrypt** and **OpenSSL**, and improving the AES implementation in **libtomcrypt** to enhance encryption performance.Running the Project in Visual Studio.

## Features

1. **Speed Comparison**:
   - Benchmark AES encryption performance using **libtomcrypt** and **OpenSSL**.
   - Evaluate speed differences under equal data sizes.
2. **Optimization of libtomcrypt AES**:
   - Analyze bottlenecks in the original **libtomcrypt** AES implementation.
   - Implement optimizations to improve the performance.
   - Benchmark and compare the results after optimization.
3. **Comprehensive Results**:
   - Provide detailed benchmarks, including before-and-after comparisons.
   -  illustrate performance improvements.

1. - 