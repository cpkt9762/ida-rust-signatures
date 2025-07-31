# 多平台架构设计文档 | Multi-Platform Architecture Design

## 架构概览 | Architecture Overview

多平台 Rust IDA 签名生成套件采用模块化的多平台架构设计，支持传统 x86_64 和现代 Solana eBPF 两大生态系统。

## 设计原则 | Design Principles

### 1. 平台隔离 | Platform Isolation
- 每个平台拥有独立的模块结构
- 平台间无直接依赖，避免交叉污染
- 统一的核心接口，一致的用户体验

### 2. 模块化设计 | Modular Design
- 清晰的功能分离：构建器、提取器、生成器
- 松耦合的模块关系，便于维护和扩展
- 插件化的平台支持，易于添加新平台

### 3. 用户完全控制 | User Full Control
- 手动参数选择，无自动化判断
- 详细的帮助信息和使用指导
- 透明的工作流程和错误报告

## 核心架构 | Core Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Interface                            │
│                  (src/cli/main.py)                         │
└─────────────────────┬───────────────────────────────────────┘
                      │
              ┌───────┴───────┐
              │               │
    ┌─────────▼─────────┐   ┌▼─────────────────┐
    │   x86_64 Platform │   │ Solana eBPF      │
    │                   │   │ Platform         │
    └─────────┬─────────┘   └┬─────────────────┘
              │               │
    ┌─────────▼─────────┐   ┌▼─────────────────┐
    │ Core Modules      │   │ Platform Modules │
    │ • config.py       │   │ • builders/      │
    │ • logger.py       │   │ • extractors/    │
    │ • exceptions.py   │   │ • generators/    │
    └───────────────────┘   │ • constants/     │
                            └──────────────────┘
```

## 平台架构详解 | Platform Architecture Details

### x86_64 平台架构

```
src/
├── builders/              # 构建器模块
│   ├── rust_builder.py   # Rust 项目编译管理
│   ├── dependency_resolver.py  # 依赖下载和解析
│   └── smart_recompiler.py     # RLIB 重编译 (三种方法)
├── extractors/            # 提取器模块
│   ├── rlib_extractor.py # RLIB 文件解压和对象文件提取
│   ├── debug_info_checker.py  # RLIB 调试信息检测
│   └── rust_type_extractor.py # Rust 类型信息提取
└── generators/            # 生成器模块
    ├── flair_generator.py        # FLAIR 工具集成
    ├── custom_pat_generator.py   # 自定义 PAT 文件生成
    ├── enhanced_pat_generator.py # 增强 PAT 生成器
    ├── collision_aware_generator.py # 碰撞检测生成器
    └── til_generator.py          # IDA .til 文件生成
```

### Solana eBPF 平台架构

```
src/platforms/solana_ebpf/
├── builders/                    # eBPF 构建器
│   ├── solana_toolchain.py     # Solana 工具链管理器
│   ├── crate_compiler.py       # eBPF 编译器
│   └── rlib_collector.py       # RLIB 收集器
├── extractors/                  # eBPF 提取器
│   ├── ebpf_elf_analyzer.py    # eBPF ELF 分析器
│   ├── function_extractor.py   # 函数提取器
│   └── solana_relocations.py   # 重定位处理器
├── generators/                  # eBPF 生成器
│   ├── solana_pat_generator.py # Solana PAT 生成器
│   ├── solana_til_generator.py # Solana TIL 生成器 (带 fallback)
│   └── version_merger.py       # 版本合并器
└── constants/                   # eBPF 常量定义
    ├── ebpf_opcodes.py         # eBPF 指令集常量
    ├── relocation_types.py     # 重定位类型定义
    └── solana_syscalls.py      # Solana 系统调用
```

## 数据流架构 | Data Flow Architecture

### x86_64 平台数据流

```
Rust Crates
    │
    ▼ (dependency_resolver.py)
Downloaded Sources
    │
    ▼ (rust_builder.py)
Compiled RLIB Files
    │
    ▼ (debug_info_checker.py)
Debug Quality Check
    │
    ▼ (rlib_extractor.py)
Object Files (.o)
    │
    ├▼ (rust_type_extractor.py)
    │ C++ Header Files
    │     │
    │     ▼ (til_generator.py)
    │   .til Files
    │
    └▼ (flair_generator.py)
      PAT Files
          │
          ▼ (FLAIR Tools)
        SIG Files
```

### Solana eBPF 平台数据流

```
Solana Crates
    │
    ▼ (solana_toolchain.py)
Toolchain Setup
    │
    ▼ (crate_compiler.py)
eBPF RLIB Files
    │
    ▼ (ebpf_elf_analyzer.py)
eBPF Functions
    │
    ├▼ (solana_pat_generator.py)
    │ .ebpf.pat Files
    │     │
    │     ▼ (FLAIR Tools)
    │   .ebpf.sig Files
    │
    └▼ (solana_til_generator.py)
      Fallback Headers
          │
          ▼ (IDAClang)
        .ebpf.til Files
```

## 关键设计决策 | Key Design Decisions

### 1. 平台命名空间

**决策**: 使用 CLI 命名空间区分平台
```bash
# x86_64 平台（默认）
python -m src.cli.main generate <crate>

# Solana eBPF 平台
python -m src.cli.main solana generate-pat <version>
```

**理由**: 
- 清晰的平台区分
- 向后兼容性
- 用户直观理解

### 2. 独立的配置系统

**决策**: 每个平台使用独立的配置文件
```
configs/
├── solana_ebpf.yaml     # Solana eBPF 专用配置
└── batch_libraries.yaml # 批量处理配置
```

**理由**:
- 避免配置冲突
- 平台特定的参数管理
- 便于维护和扩展

### 3. Fallback 机制设计

**决策**: 实现分层的 fallback 机制
1. 优先尝试标准方法 (DWARF 解析)
2. 失败时自动切换到 fallback (预定义类型)
3. 用户可见的状态报告

**理由**:
- 最大化成功率
- 用户体验友好
- 技术限制的优雅处理

## 扩展性设计 | Extensibility Design

### 新平台添加流程

1. **创建平台目录**:
   ```
   src/platforms/new_platform/
   ├── builders/
   ├── extractors/
   ├── generators/
   └── constants/
   ```

2. **实现核心接口**:
   - Builder: 编译和构建管理
   - Extractor: 文件分析和函数提取
   - Generator: 签名和类型库生成

3. **注册平台**:
   - 在 `src/platforms/__init__.py` 中注册
   - 在 CLI 中添加命令组

4. **配置支持**:
   - 创建平台专用配置文件
   - 实现配置验证和加载

### 模块扩展点

- **新的生成器**: 继承基础生成器接口
- **新的提取器**: 实现标准提取器协议
- **新的构建器**: 遵循构建器规范

## 性能考虑 | Performance Considerations

### 1. 并行处理
- 多文件批量处理
- 独立任务并发执行
- 合理的资源使用限制

### 2. 缓存策略
- 编译结果缓存
- 工具链下载缓存
- 签名生成结果缓存

### 3. 内存管理
- 大文件分块处理
- 及时清理临时文件
- 合理的内存使用监控

## 质量保证 | Quality Assurance

### 1. 测试策略
- 单元测试：核心功能模块
- 集成测试：平台工作流程
- 端到端测试：完整用户场景

### 2. 错误处理
- 分层的异常处理机制
- 详细的错误报告和建议
- 优雅的失败恢复

### 3. 日志系统
- 结构化的日志输出
- 可配置的日志级别
- 性能和调试信息跟踪

## 总结 | Summary

多平台架构设计实现了以下目标：

1. **功能完整性**: 支持两大主要 Rust 生态系统
2. **技术先进性**: 解决 eBPF DWARF 兼容性等前沿问题
3. **用户友好性**: 提供统一接口和清晰的使用指导
4. **可扩展性**: 为未来平台扩展奠定坚实基础
5. **工程质量**: 高内聚低耦合的模块化设计

这个架构为 Rust 逆向工程提供了全面的工具支持，并为区块链安全分析开辟了新的技术路径。