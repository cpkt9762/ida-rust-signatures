# Rust x86_64 IDA Signatures Generator

A comprehensive tool for generating IDA FLIRT signatures and .til type libraries from Rust libraries, designed for reverse engineering analysis of x86_64 binaries.

## Features

- **IDA .til类型库生成**: 从RLIB文件直接生成IDA Pro兼容的类型信息库文件
- **手动重编译控制**: 三种用户指定的重编译方法，无自动检测干扰
- **Automatic Rust Compilation**: Compiles Rust crates with optimized settings for signature generation
- **Collision-Aware Generation**: Intelligent collision prevention and resolution for high-quality signatures
- **Rust Name Demangling**: Integrated rust-demangler for readable function names in signatures
- **Version Tagging**: Automatic version tagging to prevent cross-version collisions
- **Dual Signature Generation**: Primary approach using IDA FLAIR tools, with enhanced custom implementation
- **Batch Processing**: Process multiple RLIB files simultaneously with progress tracking
- **Comprehensive Dependency Management**: Handles complex Rust dependency trees and version resolution
- **x86_64 Optimization**: Specifically tuned for x86_64-unknown-linux-gnu target architecture
- **Enhanced CLI Interface**: User-friendly command-line interface with advanced options and detailed statistics
- **Configuration Management**: Flexible YAML-based configuration system
- **Caching & Performance**: Built-in caching to avoid redundant compilation and extraction

## Quick Start

### Installation

1. **Install Rust 1.84.1**:
```bash
rustup install 1.84.1
rustup default 1.84.1
rustup target add x86_64-unknown-linux-gnu
```

2. **Install Python dependencies**:
```bash
pip install -r requirements.txt
```

3. **Configure IDA FLAIR tools path**:

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

### Basic Usage

#### Generate IDA .til Type Libraries (Recommended)
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

### Directory Structure

```
rust-x86_64-ida-signatures/
├── src/                     # Source code
│   ├── core/               # Configuration, logging, exceptions
│   ├── builders/           # Rust compilation and dependency resolution
│   ├── extractors/         # RLIB archive and object file extraction
│   ├── generators/         # Signature generation (enhanced generators)
│   └── cli/                # Enhanced command-line interface
├── data/                    # Working data
│   ├── projects/           # Rust project workspaces
│   ├── compiled/           # Build artifacts
│   ├── dependencies/       # Downloaded Rust crates
│   ├── headers/            # Generated C++ header files for .til generation
│   └── signatures/         # Generated signatures (organized by type)
│       ├── pat/            # PAT signature files
│       ├── sig/            # SIG signature files
│       ├── temp_objects/   # Temporary object files
│       └── rust_1_84_1_debug/  # Test RLIB files
│           ├── libcore-96580b7e4b81524a.rlib    # Rust Core library
│           ├── libstd-256c50b86215d2e7.rlib     # Rust Std library
│           └── liballoc-d67f1c7e30eebbd7.rlib   # Rust Alloc library
├── configs/                # Configuration files
└── logs/                   # Application logs
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

## Contributing

1. Follow the established code style and architecture patterns
2. Ensure all tests pass and coverage remains above 85%
3. Update documentation for any new features
4. Use descriptive commit messages

## License

This project is developed for reverse engineering research and analysis purposes.