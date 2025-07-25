# SM2 加密/解密模块

这是一个基于 OpenSSL 的 SM2 国密算法实现，提供了加密、解密和密钥生成功能。

## 特性

- **安全性**: 使用 OpenSSL 3.0+ 的 EVP API 实现 SM2 加密
- **内存安全**: 自动内存管理，防止内存泄漏
- **错误处理**: 完善的错误检查和处理机制
- **类型安全**: 统一的 C/Go 类型系统
- **测试覆盖**: 包含加密解密测试和错误处理测试

## 使用方法

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/linuxdeepin/go-lib/gm/sm2"
)

func main() {
    // 创建 SM2Helper 实例
    helper := sm2.NewHelper()
    if helper == nil {
        log.Fatal("failed to create SM2Helper")
    }
    defer helper.Release() // 确保释放资源
    
    // 生成密钥对
    pubKey, privKey, err := helper.GenPairKey()
    if err != nil {
        log.Fatal("failed to generate key pair:", err)
    }
    fmt.Printf("Public Key: %s\n", pubKey)
    fmt.Printf("Private Key: %s\n", privKey)
    
    // 加密数据
    plaintext := []byte("Hello, SM2!")
    ciphertext, err := helper.Encrypt(plaintext)
    if err != nil {
        log.Fatal("encryption failed:", err)
    }
    fmt.Printf("Encrypted: %x\n", ciphertext)
    
    // 解密数据
    decrypted, err := helper.Decrypt(ciphertext)
    if err != nil {
        log.Fatal("decryption failed:", err)
    }
    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

## 主要优化

### 1. 修复编译错误
- 修复了 Go 代码中变量名错误（使用了 `p` 而不是 `c`）
- 统一了 C 头文件和实现中的函数命名
- 添加了缺失的函数定义（`print_openssl_errors`, `log_print`）

### 2. 类型系统重构
- 将 `EC_KEY*` 统一为 `EVP_PKEY*` 类型
- 修复了 C 代码中的类型不匹配问题
- 使用了 OpenSSL 3.0+ 的现代 API

### 3. 内存管理改进
- 添加了 Go finalizer 防止内存泄漏
- 改进了 C 代码中的内存释放逻辑
- 使用正确的内存分配/释放函数

### 4. 错误处理增强
- 添加了完善的参数验证
- 改进了错误消息的可读性
- 添加了 OpenSSL 错误信息输出

### 5. API 安全性
- 添加了空指针检查
- 防止对已释放资源的操作
- 支持多次调用 `Release()` 方法

### 6. 测试覆盖
- 增加了更多测试用例（包括中文文本）
- 添加了错误处理测试
- 添加了边界条件测试

## 依赖要求

- OpenSSL 3.0+ (支持 SM2 算法)
- pkg-config
- C 编译器 (gcc/clang)

## 构建

```bash
go build .
```

## 测试

```bash
go test -v
```

## 注意事项

1. 确保系统安装了支持 SM2 的 OpenSSL 版本
2. 使用完毕后应调用 `Release()` 方法释放资源
3. 不要在多个 goroutine 中同时使用同一个 `SM2Helper` 实例 