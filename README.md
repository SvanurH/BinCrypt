# BinCrypt

一个简单的bin文件加密工具，内部支持xor、aes多次加密，ipv4、ipv6、mac地址混淆。

```
usage:
  BinCrypt.exe -i <inputFileName> -xor <num> -aes <num> -obf <ipv4、ipv6、mac> -o <outputFileName>
eg:
  BinCrypt.exe -i calc.bin -xor 10 -aes 10 -obf ipv4 -o out.txt
  BinCrypt.exe -i calc.bin -aes 20 -o out.bin
```
加密结束后会成功一个进行解密的C++文件
