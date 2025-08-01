# 多平台 Rust IDA 签名生成套件 | Multi-Platform Rust IDA Signature Generator

A comprehensive multi-platform toolkit for generating IDA Pro FLIRT signatures and .til type libraries from Rust libraries, supporting both traditional x86_64 and modern Solana eBPF architectures for complete reverse engineering analysis.

## 🌟 核心特性 | Core Features

### 🏗️ 多平台架构支持 | Multi-Platform Architecture
- **x86_64 平台**: 传统 Rust 库的 FLIRT 签名和类型库生成
- **Solana eBPF 平台**: Solana 区块链生态的 eBPF 格式签名生成
- **统一 CLI 接口**: 通过平台命名空间区分不同架构
- **独立模块设计**: 每个平台拥有独立的构建、提取、生成管线

### 🎯 Solana eBPF 平台特性
- **Solana 工具链管理**: 自动下载和管理多版本 (1.18.16, 1.18.26, 2.1.21)
- **eBPF 编译器集成**: cargo-build-sbf 集成，生成 eBPF rlib 格式
- **完整算法移植**: 忠实移植 solana-ida-signatures-factory 核心算法
- **版本合并器**: 智能去重，版本范围命名，避免签名冲突
- **文件命名规范**: `name_version.ebpf.pat/sig` 格式，支持版本管理
- **Rust 标准库子库支持**: 自动生成 `core`、`std`、`alloc` 子库签名，支持精细化分析

### 🛡️ 智能碰撞处理系统
- **多种处理模式**: strict, accept, force, manual 四种模式
- **智能函数选择**: 优先非 `unlikely.` 函数，选择名称更短的版本
- **EXC 文件优化**: 使用 `+` 前缀标记最佳函数，删除其他碰撞
- **自动碰撞解析**: 显著减少手动干预，提高签名质量

### 📘 TIL 类型库生成
- **x86_64 DWARF 提取**: 从 RLIB 文件直接生成 IDA Pro 兼容的类型信息库
- **eBPF Fallback 机制**: 解决 eBPF DWARF 重定位类型兼容性问题
- **基础类型库**: 预定义 Solana 程序基本类型 (SolanaPubkey, AccountInfo 等)
- **手动重编译控制**: 三种用户指定的重编译方法，无自动检测干扰

### ⚙️ 高级功能
- **YAML 配置系统**: 灵活的批量处理配置，支持工具链版本映射
- **版本标记**: 自动版本标记防止跨版本碰撞
- **Rust 名称还原**: 集成 rust-demangler，签名中显示可读函数名
- **批量处理**: 多 RLIB 文件同时处理，进度跟踪
- **缓存优化**: 内置缓存避免重复编译和提取

### 🧩 子库系统 | Sublibrary System
- **自动子库生成**: 从主库 PAT 文件中自动提取 Rust 标准库子库 (core、std、alloc)
- **函数命名空间分离**: 基于 mangled name 前缀 (`_ZN4core`, `_ZN3std`, `_ZN5alloc`) 进行智能分类
- **版本继承机制**: 子库自动继承主库的工具链版本信息 (如 Solana 1.18.16 → Rust 1.75.0)
- **配置驱动**: 通过 `configs/batch_libraries.yaml` 定义父子库关系和批量处理规则
- **独立签名文件**: 每个子库生成独立的 `.pat` 和 `.sig` 文件，便于精细化分析

## 🚀 快速开始 | Quick Start

### 📦 安装配置 | Installation

#### 1. 安装 Rust 工具链 | Install Rust Toolchain
```bash
# 安装 Rust 1.84.1 (用于 x86_64 平台)
rustup install 1.84.1
rustup default 1.84.1
rustup target add x86_64-unknown-linux-gnu

# 安装 Solana 兼容的 Rust 版本 (用于 eBPF 平台)
rustup install 1.75.0
rustup install 1.79.0
```

#### 2. 安装 Python 依赖 | Install Python Dependencies
```bash
pip install -r requirements.txt
```

#### 3. 配置 IDA FLAIR 工具路径 | Configure IDA FLAIR Tools Path

**macOS**:
```bash
export FLAIR_DIR="/Applications/IDA Professional 9.1.app/Contents/MacOS/tools/flair"
```

**Windows**:
```cmd
# Command Prompt
set FLAIR_DIR="C:\Program Files\IDA Professional 9.1\tools\flair"

# PowerShell
$env:FLAIR_DIR="C:\Program Files\IDA Professional 9.1\tools\flair"
```

**Linux**:
```bash
# Common installation paths
export FLAIR_DIR="/opt/ida-pro/tools/flair"
# Or user installation
export FLAIR_DIR="$HOME/ida-pro/tools/flair"
```

### 🎯 基本使用 | Basic Usage

#### 🌐 Solana eBPF 平台使用 | Solana eBPF Platform Usage

```bash
# 1. 设置 Solana 工具链 | Setup Solana Toolchain
python -m src.cli.main solana setup-toolchain --version 1.18.16

# 2. 编译 solana-program crate | Compile solana-program crate
python -m src.cli.main solana compile-solana-program --version 1.18.16

# 3. 生成 PAT 文件 | Generate PAT file
python -m src.cli.main solana generate-pat --version 1.18.16

# 4. 生成 SIG 文件 | Generate SIG file  
python -m src.cli.main solana generate-sig --version 1.18.16

# 5. 生成 TIL 文件 (实验性) | Generate TIL file (Experimental)
python -m src.cli.main solana generate-til --version 1.18.16

# 6. 测试完整工作流 | Test complete workflow
python -m src.cli.main solana test-workflow --version 1.18.16

# 7. 合并多版本签名 | Merge multi-version signatures
python -m src.cli.main solana merge-versions --versions 1.18.16,1.18.26,2.1.21

# 8. 批量处理 (包含自动子库生成) | Batch processing (with automatic sublibrary generation)
python -m src.cli.main solana batch-libraries --config configs/batch_libraries.yaml
```

#### 📘 x86_64 平台使用 | x86_64 Platform Usage

##### Generate IDA .til Type Libraries (Recommended)
```bash
# Generate .til file from RLIB with manual recompilation control
python -m src.cli.main generate-til path/to/lib.rlib \
  --lib-name mylib \
  --version 1.0.0 \
  --recompile-method env_vars

# Check debug info quality first (optional)
python -m src.cli.main generate-til path/to/lib.rlib \
  --lib-name mylib \
  --check-only

# Example with test files
python -m src.cli.main generate-til \
  /Users/pingzi/Documents/jup/rust-x86_64-ida-signatures/data/signatures/rust_1_84_1_debug/libcore-96580b7e4b81524a.rlib \
  --lib-name core \
  --version 1.84.1 \
  --recompile-method cli_system
```

#### Generate Enhanced Signatures from RLIB Files
```bash
# Generate with all optimizations enabled
python -m src.cli.main generate-enhanced path/to/lib.rlib \
  --lib-name mylib \
  --version 1.0.0 \
  --version-tag

# Generate signatures for a popular Rust crate
python -m src.cli.main generate-enhanced \
  /path/to/target/release/deps/libserde-*.rlib \
  --lib-name serde \
  --version 1.0.210 \
  --version-tag
```

#### Generate Signatures for Popular Crates
```bash
# Basic generation with collision handling
python -m src.cli.main generate serde tokio clap --version 1.0 --version-tag

# Advanced generation with specific options
python -m src.cli.main generate reqwest \
  --generator collision-aware \
  --demangle \
  --prevent-collisions \
  --dedup \
  --multi-pass
```

#### Batch Processing
```bash
# Process all RLIB files in a directory
python -m src.cli.main batch-generate \
  --rlib-dir ./target/release/deps \
  --output-dir ./signatures

# Process specific pattern
python -m src.cli.main batch-generate \
  -d ./libs \
  -p "lib*.rlib" \
  --version-tag
```

#### Analysis and Validation
```bash
# Validate signatures with detailed analysis  
python -m src.cli.main validate data/signatures/pat/serde_1.0.210.pat

# Analyze and fix collisions
python -m src.cli.main analyze-collisions signatures.pat --fix

# Show system information
python -m src.cli.main info
```

## Architecture

### Core Components

- **`src/core/`**: Configuration management, logging, and exception handling
- **`src/builders/`**: Rust compilation and dependency resolution
- **`src/extractors/`**: RLIB archive and object file extraction
- **`src/generators/`**: FLAIR signature generation (primary) and custom implementation (fallback)
- **`src/cli/`**: Command-line interface and user interaction

### Data Flow

```
Rust Crates → Cargo Build → .rlib Files → Object Extraction → FLAIR Tools → IDA Signatures
```

### 🏗️ 多平台架构 | Multi-Platform Architecture

```
多平台 Rust IDA 签名生成套件 v2.0
├── x86_64 Platform          # 传统 x86_64 架构支持
│   ├── FLIRT 签名生成        # 标准 FLIRT 工具集成
│   ├── TIL 类型库生成        # DWARF 调试信息提取
│   └── 碰撞处理系统          # 智能碰撞解决
└── Solana eBPF Platform     # Solana 区块链架构支持  
    ├── eBPF 签名生成         # 专用 eBPF 算法移植
    ├── TIL Fallback 机制     # 兼容性后备方案
    └── 版本合并系统          # 多版本智能合并
```

### 📁 目录结构 | Directory Structure

```
rust-x86_64-ida-signatures/
├── src/                      # 源代码 | Source code
│   ├── core/                # 核心功能：配置、日志、异常
│   ├── builders/            # x86_64 构建器：编译和依赖解析
│   ├── extractors/          # x86_64 提取器：RLIB 和对象文件提取
│   ├── generators/          # x86_64 生成器：签名生成
│   ├── platforms/           # 🌐 多平台支持
│   │   └── solana_ebpf/     # Solana eBPF 平台实现
│   │       ├── builders/    # eBPF 构建器 (工具链管理、编译器)
│   │       ├── extractors/  # eBPF 提取器 (ELF 分析、函数提取)
│   │       ├── generators/  # eBPF 生成器 (PAT/SIG/TIL)
│   │       └── constants/   # eBPF 常量 (操作码、重定位、系统调用)
│   └── cli/                 # 统一命令行界面
├── data/                     # 工作数据
│   ├── signatures/          # x86_64 签名文件
│   ├── headers/             # x86_64 C++ 头文件 (.til 输入)
│   └── solana_ebpf/         # 🌐 Solana eBPF 数据目录
│       ├── toolchains/      # Solana 工具链存储
│       ├── crates/          # 编译的 crate 项目
│       ├── rlibs/           # eBPF rlib 文件
│       ├── headers/         # eBPF C++ 头文件
│       └── signatures/      # Solana 签名文件
│           ├── pat/         # .ebpf.pat 文件
│           └── sig/         # .ebpf.sig 文件
├── configs/                  # 配置文件
│   ├── solana_ebpf.yaml     # 🌐 Solana eBPF 配置
│   └── batch_libraries.yaml # 批量处理配置示例
└── tests/                    # 测试目录
    └── test_solana_integration.py  # 🧪 Solana 集成测试
```

## Configuration

### Environment Variables

- `RUST_VERSION`: Rust compiler version (default: 1.84.1)
- `TARGET_ARCH`: Target architecture (default: x86_64-unknown-linux-gnu)
- `FLAIR_DIR`: Path to IDA FLAIR tools directory (platform-specific, see installation)
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

#### Platform-Specific FLAIR_DIR Configuration

**macOS** (persistent):
```bash
echo 'export FLAIR_DIR="/Applications/IDA Professional 9.1.app/Contents/MacOS/tools/flair"' >> ~/.zshrc
source ~/.zshrc
```

**Windows** (persistent):
```cmd
# Set permanently via System Properties
setx FLAIR_DIR "C:\Program Files\IDA Professional 9.1\tools\flair"

# Or add to PowerShell profile
echo '$env:FLAIR_DIR="C:\Program Files\IDA Professional 9.1\tools\flair"' >> $PROFILE
```

**Linux** (persistent):
```bash
echo 'export FLAIR_DIR="/opt/ida-pro/tools/flair"' >> ~/.bashrc
source ~/.bashrc
```

### Configuration Files

Create custom configurations in `configs/`:

```yaml
# configs/my_crates.yaml
project_name: "my_rust_libs"
target: "x86_64-unknown-linux-gnu"

dependencies:
  serde: "1.0"
  tokio: "1.0"
  clap: "4.0"

build_config:
  profile: "release"
  debug_info: true
  optimization_level: 2
```

Use with:
```bash
python -m src.cli.main auto-generate --config configs/my_crates.yaml
```

## CLI Commands Reference

### Core Commands

#### `generate-til` - IDA Type Library Generation
Generate IDA Pro .til type library files from RLIB files with manual recompilation control.

```bash
python -m src.cli.main generate-til RLIB_PATH [OPTIONS]

Options:
  -n, --lib-name TEXT              Library name (required)
  -v, --version TEXT               Library version for tagging
  -o, --output-dir PATH            Output directory
  --check-only                     Only check debug info quality, don't generate
  --recompile-method [env_vars|config_file|cli_system]  Manual recompilation method if needed
  --help                           Show detailed help including recompilation methods
```

**Recompilation Methods:**
- `env_vars`: Environment variable method for local projects
- `config_file`: Configuration file method for persistent settings  
- `cli_system`: CLI system method for third-party crates

#### `generate-enhanced` - Enhanced Signature Generation
Generate high-quality signatures directly from RLIB files with all optimizations.

```bash
python -m src.cli.main generate-enhanced RLIB_PATH [OPTIONS]

Options:
  -n, --lib-name TEXT              Library name (required)
  -v, --version TEXT               Library version for tagging
  -o, --output-dir PATH            Output directory
  --demangle / --no-demangle       Enable Rust name demangling (default: True)
  --dedup / --no-dedup             Enable pattern deduplication (default: True)
  --prevent-collisions / --no-prevent-collisions  Enable collision prevention (default: True)
  --version-tag / --no-version-tag Add version tags to functions
  --multi-pass / --single-pass     Enable multi-pass optimization (default: True)
```

#### `generate` - Traditional Generation with Advanced Options
```bash
python -m src.cli.main generate CRATES... [OPTIONS]

Options:
  --generator [flair|custom|enhanced|collision-aware]  Generator type (default: collision-aware)
  --demangle / --no-demangle       Enable Rust name demangling (default: True)
  --prevent-collisions / --no-prevent-collisions      Enable collision prevention (default: True)
  --dedup / --no-dedup             Enable pattern deduplication (default: True)
  --version-tag / --no-version-tag Add version tags to functions
  --multi-pass / --single-pass     Enable multi-pass optimization (default: True)
```


### Analysis Commands

#### `analyze-collisions` - Pattern Collision Analysis
```bash
python -m src.cli.main analyze-collisions PAT_FILE [OPTIONS]

Options:
  --fix                Fix collisions by deduplication
  -o, --output PATH    Output file for fixed PAT
```

#### `validate` - Signature Validation
```bash
python -m src.cli.main validate SIGNATURE_FILE

Features:
- Function name quality analysis
- Version tag detection
- Collision detection for PAT files
- File integrity verification
```

### Batch Processing Commands

#### `batch-generate` - Process Multiple RLIB Files
```bash
python -m src.cli.main batch-generate [OPTIONS]

Options:
  -d, --rlib-dir PATH              Directory containing RLIB files (required)
  -o, --output-dir PATH            Output directory
  --version-tag / --no-version-tag Add version tags from filenames (default: True)
  -p, --pattern TEXT               File pattern to match (default: *.rlib)
```

### Solana eBPF Commands

#### `solana batch-libraries` - Batch Processing with Sublibrary Generation
```bash
python -m src.cli.main solana batch-libraries [OPTIONS]

Options:
  --config PATH                    YAML configuration file (default: configs/batch_libraries.yaml)
  --dry-run                        Show what would be processed without executing

Features:
- Automatic main library compilation and signature generation
- Automatic Rust standard library sublibrary extraction (core, std, alloc)
- Version inheritance from main library to sublibraries
- Progress tracking and error handling
```

#### `solana extract-sublibraries` - Extract Rust Standard Library Sublibraries
```bash
python -m src.cli.main solana extract-sublibraries PAT_FILE [OPTIONS]

Options:
  --rust-version TEXT              Rust version for sublibrary naming
  --components TEXT                Comma-separated components (default: core,std,alloc)
  -o, --output-dir PATH            Output directory

Features:
- Extracts functions based on mangled name prefixes
- Generates independent PAT and SIG files for each component
- Maintains function signatures and metadata
```

### Utility Commands

#### `info` - System Information
```bash
python -m src.cli.main info

Displays:
- Rust toolchain information
- FLAIR tools availability
- Configuration settings
- Dependencies status
```

#### `list-dependencies` - Show Downloaded Dependencies
```bash
python -m src.cli.main list-dependencies
```

#### `fetch-dependencies` - Download Dependencies
```bash
python -m src.cli.main fetch-dependencies [OPTIONS]

Options:
  --config PATH      Configuration file path
  --offline          Download sources for offline usage
  --deps-dir PATH    Custom dependencies directory
```

#### `cleanup` - Clean Temporary Files
```bash
python -m src.cli.main cleanup [--hours INTEGER]
```

## Advanced Usage

### Batch Processing

Process multiple crate sets:
```bash
for config in configs/*.yaml; do
    python -m src.cli.main auto-generate --config "$config"
done
```

### Custom Build Options

```bash
python -m src.cli.main generate tokio \
    --version 1.0 \
    --target x86_64-unknown-linux-gnu \
    --lib-name tokio_runtime \
    --keep-temp
```

### Debugging and Troubleshooting

Enable verbose logging:
```bash
python -m src.cli.main -v generate serde
```

Keep temporary files for inspection:
```bash
python -m src.cli.main generate reqwest --keep-temp
```

Clean up old artifacts:
```bash
python -m src.cli.main cleanup --hours 24
```

## Development

### Code Quality Standards

This project follows strict Python development standards:

- **Python 3.11+** with full type annotations
- **Google-style docstrings** for all public APIs
- **85% test coverage** requirement
- **Ruff** for formatting and linting
- **MyPy** for static type checking

### Development Setup

```bash
# Set up development environment
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Run quality checks
ruff check .
ruff format .
mypy src/
pytest --cov=src
```

### Testing

Run the test suite:
```bash
pytest                          # All tests
pytest tests/unit/             # Unit tests only
pytest -v --tb=short          # Verbose output
pytest --cov=src --cov-report=html  # Coverage report
```

## Troubleshooting

### Common Issues

1. **FLAIR tools not found**:
   
   **All platforms**:
   - Ensure IDA Pro is installed with FLAIR tools included
   - Verify the `FLAIR_DIR` environment variable is set correctly
   
   **macOS/Linux**:
   ```bash
   # Check if tools exist and are executable
   ls -la "$FLAIR_DIR"
   chmod +x "$FLAIR_DIR"/*
   ```
   
   **Windows**:
   ```cmd
   # Check if tools exist
   dir "%FLAIR_DIR%"
   # Ensure no spaces in path cause issues - use quotes
   set FLAIR_DIR="C:\Program Files\IDA Professional 9.1\tools\flair"
   ```
   
   **Common IDA Pro installation paths**:
   - macOS: `/Applications/IDA Professional 9.1.app/Contents/MacOS/tools/flair`
   - Windows: `C:\Program Files\IDA Professional 9.1\tools\flair`
   - Linux: `/opt/ida-pro/tools/flair` or `~/ida-pro/tools/flair`

2. **Rust compilation fails**:
   - Verify Rust 1.84.1 is installed: `rustc --version`
   - Check target availability: `rustup target list --installed`
   - Review dependency versions for compatibility

3. **No object files extracted**:
   - Check .rlib file generation in `data/compiled/rlibs/`
   - Verify ELF format with: `file path/to/object.o`
   - Review extraction logs for specific errors

### Debug Mode

Enable comprehensive debugging:
```bash
export LOG_LEVEL=DEBUG
python -m src.cli.main -v generate tokio --keep-temp
```

This will:
- Show detailed compilation output
- Preserve all temporary files
- Log every step of the process
- Provide full stack traces on errors

## Platform-Specific Notes

### Windows
- **Path separators**: Use forward slashes or escape backslashes in paths
- **PowerShell vs CMD**: PowerShell is recommended for better Unicode support
- **Antivirus**: Some antivirus software may interfere with RLIB extraction
- **Long paths**: Enable long path support if encountering path length issues

### Linux
- **Dependencies**: Install `build-essential` and `pkg-config` if not already present
- **Permissions**: Ensure execute permissions on FLAIR tools after installation
- **Wine compatibility**: IDA Pro running under Wine may work but is not officially supported

### macOS
- **Gatekeeper**: You may need to allow IDA Pro tools through System Preferences > Security
- **Homebrew**: Consider using Homebrew to manage Rust installation
- **Apple Silicon**: Use Rosetta 2 if running IDA Pro x86_64 version on M1/M2 Macs

## Real-World Applications

### Blockchain and DeFi Analysis
```bash
# Generate signatures for Solana ecosystem libraries
python -m src.cli.main generate solana-sdk solana-client --version 2.1.21
python -m src.cli.main generate-enhanced solana-account-decoder.rlib --lib-name solana_decoder

# Analyze Jupiter DEX protocol
python -m src.cli.main generate jupiter-amm-interface --version 0.4.6
```

### Web Development
```bash
# Popular web frameworks
python -m src.cli.main generate actix-web rocket --version-tag

# HTTP clients and serialization
python -m src.cli.main generate reqwest serde_json --version-tag
```

### Systems Programming
```bash
# Async runtime and utilities
python -m src.cli.main generate tokio async-std --version-tag

# CLI and configuration libraries
python -m src.cli.main generate clap config --version-tag
```

## ⚠️ 技术限制 | Technical Limitations

### 🌐 Solana eBPF 平台限制
- **DWARF 调试信息兼容性**: Solana eBPF 的 DWARF 调试信息使用了不同的重定位类型，标准 GNU binutils 工具（readelf、objdump 等）无法正确处理 eBPF 的重定位类型
- **类型提取限制**: RustTypeExtractor 无法正确解析 eBPF 的 DWARF 信息，因此 TIL 生成使用 fallback 机制
- **Fallback 解决方案**: 实现了预定义的 Solana 基本类型库，包含 `SolanaPubkey`、`SolanaAccountInfo` 等核心类型
- **IDAClang 兼容性**: IDAClang 不支持 `sbf-solana-solana` 目标架构，需要使用兼容架构生成 TIL 文件

### 📈 架构演进历程 | Architecture Evolution

#### v1.0 → v2.0 重大升级
- **架构升级**: 从单一 x86_64 平台升级为多平台架构
- **平台扩展**: 新增完整的 Solana eBPF 平台支持
- **碰撞处理优化**: 实现智能碰撞处理系统，显著减少手动干预
- **配置系统改进**: 引入 YAML 配置文件，支持批量处理和工具链版本映射
- **TIL 生成增强**: 添加 fallback 机制，提高跨平台兼容性
- **子库自动生成**: 实现 Rust 标准库子库 (core/std/alloc) 的自动提取和生成功能

#### 未来发展方向
- 改进 eBPF DWARF 解析器，支持 eBPF 特有的重定位类型
- 扩展到更多区块链平台 (Ethereum WASM, Cosmos, etc.)
- 增强 TIL 生成的类型覆盖率
- 优化批量处理性能

## 🤝 贡献指南 | Contributing

1. 遵循已建立的代码风格和架构模式
2. 确保所有测试通过，覆盖率保持在 85% 以上
3. 为任何新功能更新文档
4. 使用描述性的提交信息
5. 多平台功能需要在相应的 `src/platforms/` 目录下实现

## 📄 开源许可 | License

本项目专为逆向工程研究和分析目的而开发。