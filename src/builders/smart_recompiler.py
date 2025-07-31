"""Smart RLIB recompiler with multiple compilation strategies.

This module provides intelligent recompilation of RLIB files with insufficient
debug information using various strategies including environment variables,
configuration files, and CLI integration.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from ..core.logger import LoggerMixin
from ..core.exceptions import BuildError, ValidationError
from ..extractors.debug_info_checker import (
    DebugInfoReport, RlibSourceInfo, ProjectStructureAnalysis, RecompileOption
)
from .rlib_manager import X86_64RlibManager


class RecompileResult:
    """重编译结果."""
    
    def __init__(self):
        self.success = False
        self.method_used = None  # 使用的重编译方法
        self.new_rlib_path = None  # 新生成的RLIB文件路径
        self.build_time_seconds = 0
        self.output_messages = []
        self.error_messages = []
        self.quality_improvement = 0  # 调试信息质量改进分数


class SmartRecompiler(LoggerMixin):
    """智能RLIB重编译器."""
    
    def __init__(self):
        super().__init__()
        self.supported_methods = ['env_vars', 'config_file', 'cli_system']
        self.rlib_manager = X86_64RlibManager()
    
    def recompile_rlib(
        self, 
        original_rlib_path: Path,
        debug_report: DebugInfoReport,
        method: str = "auto",
        auto_confirm: bool = False
    ) -> RecompileResult:
        """
        智能重编译RLIB文件以改善调试信息质量.
        
        Args:
            original_rlib_path: 原始RLIB文件路径
            debug_report: 调试信息分析报告
            method: 重编译方法 ('auto', 'env_vars', 'config_file', 'cli_system')
            auto_confirm: 是否自动确认执行
            
        Returns:
            RecompileResult包含重编译结果
            
        Raises:
            ValidationError: 如果输入参数无效
            BuildError: 如果重编译失败
        """
        # Skip file existence check for cli_system method (it downloads from crates.io)
        if method != "cli_system" and not original_rlib_path.exists():
            raise ValidationError(
                f"Original RLIB file not found: {original_rlib_path}",
                field_name="original_rlib_path",
                field_value=str(original_rlib_path)
            )
        
        if method not in ['auto'] + self.supported_methods:
            raise ValidationError(
                f"Unsupported recompile method: {method}",
                field_name="method",
                field_value=method
            )
        
        result = RecompileResult()
        
        try:
            # 自动选择最佳方法
            if method == "auto":
                selected_method = self._select_best_method(debug_report)
                self.logger.info(f"Auto-selected recompile method: {selected_method}")
            else:
                selected_method = method
            
            # 执行重编译
            if selected_method == "env_vars":
                result = self._recompile_with_env_vars(original_rlib_path, debug_report, auto_confirm)
            elif selected_method == "config_file":
                result = self._recompile_with_config_file(original_rlib_path, debug_report, auto_confirm)
            elif selected_method == "cli_system":
                result = self._recompile_with_cli_system(original_rlib_path, debug_report, auto_confirm)
            else:
                raise ValidationError(f"Unknown method selected: {selected_method}")
            
            result.method_used = selected_method
            
            # 验证重编译结果
            if result.success and result.new_rlib_path:
                self._verify_recompile_result(original_rlib_path, result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Recompilation failed: {e}")
            result.success = False
            result.error_messages.append(str(e))
            return result
    
    def _select_best_method(self, debug_report: DebugInfoReport) -> str:
        """根据分析报告自动选择最佳重编译方法."""
        if not debug_report.source_info:
            return "cli_system"  # 默认使用CLI系统
        
        source_info = debug_report.source_info
        
        # 本地项目优先使用环境变量方法
        if source_info.source_type == "local_project":
            if debug_report.project_analysis and debug_report.project_analysis.has_source_access:
                return "env_vars"  # 环境变量是最安全的方法
            else:
                return "config_file"  # 没有源码访问时使用配置文件
        
        # 第三方crate使用CLI系统
        elif source_info.source_type == "third_party":
            return "cli_system"
        
        # 未知来源也使用CLI系统
        else:
            return "cli_system"
    
    def _recompile_with_env_vars(
        self, 
        original_rlib_path: Path, 
        debug_report: DebugInfoReport,
        auto_confirm: bool
    ) -> RecompileResult:
        """使用环境变量方法重编译."""
        result = RecompileResult()
        
        if not debug_report.source_info or debug_report.source_info.source_type != "local_project":
            result.error_messages.append("Environment variable method requires local project")
            return result
        
        source_info = debug_report.source_info
        project_path = source_info.project_path
        
        if not project_path or not project_path.exists():
            result.error_messages.append(f"Project path not found: {project_path}")
            return result
        
        self.logger.info(f"Recompiling with environment variables in: {project_path}")
        
        try:
            import time
            start_time = time.time()
            
            # 准备环境变量
            env = os.environ.copy()
            env.update({
                'CARGO_PROFILE_RELEASE_DEBUG': 'true',
                'CARGO_PROFILE_RELEASE_LTO': 'false',
                'CARGO_PROFILE_RELEASE_CODEGEN_UNITS': '1',
                'CARGO_PROFILE_DEV_DEBUG': 'true',
                'RUSTFLAGS': '-C debuginfo=2 -C embed-bitcode=yes'
            })
            
            # 构建命令
            cmd = ['cargo', 'build']
            
            if source_info.target_arch:
                cmd.extend(['--target', source_info.target_arch])
            
            if source_info.build_profile == "release":
                cmd.append('--release')
            
            # 执行构建
            self.logger.debug(f"Executing: {' '.join(cmd)}")
            process = subprocess.run(
                cmd,
                cwd=project_path,
                env=env,
                capture_output=True,
                text=True,
                timeout=600  # 10分钟超时
            )
            
            result.build_time_seconds = time.time() - start_time
            result.output_messages = process.stdout.split('\n') if process.stdout else []
            
            if process.returncode == 0:
                # 查找新生成的RLIB文件
                self.logger.debug(f"Build succeeded, searching for RLIB. Source info: crate_name={source_info.crate_name}, target_arch={source_info.target_arch}, build_profile={source_info.build_profile}")
                new_rlib = self._find_generated_rlib(project_path, source_info)
                if new_rlib:
                    result.success = True
                    result.new_rlib_path = new_rlib
                    result.output_messages.append(f"✅ Successfully generated: {new_rlib}")
                else:
                    result.error_messages.append(f"Build succeeded but RLIB file not found for crate '{source_info.crate_name}'")
            else:
                result.error_messages = process.stderr.split('\n') if process.stderr else ['Build failed']
                self.logger.error(f"Build failed with return code {process.returncode}")
            
        except subprocess.TimeoutExpired:
            result.error_messages.append("Build timed out after 10 minutes")
        except Exception as e:
            result.error_messages.append(f"Build execution failed: {e}")
        
        return result
    
    def _recompile_with_config_file(
        self, 
        original_rlib_path: Path, 
        debug_report: DebugInfoReport,
        auto_confirm: bool
    ) -> RecompileResult:
        """使用配置文件方法重编译."""
        result = RecompileResult()
        
        if not debug_report.source_info or debug_report.source_info.source_type != "local_project":
            result.error_messages.append("Config file method requires local project")
            return result
        
        source_info = debug_report.source_info
        project_path = source_info.project_path
        
        if not project_path or not project_path.exists():
            result.error_messages.append(f"Project path not found: {project_path}")
            return result
        
        self.logger.info(f"Recompiling with config file in: {project_path}")
        
        try:
            import time
            start_time = time.time()
            
            # 创建.cargo/config.toml
            cargo_dir = project_path / ".cargo"
            cargo_dir.mkdir(exist_ok=True)
            
            config_file = cargo_dir / "config.toml"
            config_content = """[build]
rustflags = ["-C", "debuginfo=2", "-C", "embed-bitcode=yes"]

[profile.release]
debug = true
lto = false
codegen-units = 1

[profile.dev]
debug = true
opt-level = 0
"""
            
            # 备份现有配置（如果存在）
            backup_file = None
            if config_file.exists():
                backup_file = config_file.with_suffix('.toml.backup')
                config_file.rename(backup_file)
                result.output_messages.append(f"Backed up existing config to: {backup_file}")
            
            # 写入新配置
            config_file.write_text(config_content, encoding='utf-8')
            result.output_messages.append(f"Created debug-optimized config: {config_file}")
            
            try:
                # 执行构建
                cmd = ['cargo', 'build']
                
                if source_info.target_arch:
                    cmd.extend(['--target', source_info.target_arch])
                
                if source_info.build_profile == "release":
                    cmd.append('--release')
                
                self.logger.debug(f"Executing: {' '.join(cmd)}")
                process = subprocess.run(
                    cmd,
                    cwd=project_path,
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                
                result.build_time_seconds = time.time() - start_time
                result.output_messages.extend(process.stdout.split('\n') if process.stdout else [])
                
                if process.returncode == 0:
                    new_rlib = self._find_generated_rlib(project_path, source_info)
                    if new_rlib:
                        result.success = True
                        result.new_rlib_path = new_rlib
                        result.output_messages.append(f"✅ Successfully generated: {new_rlib}")
                    else:
                        result.error_messages.append("Build succeeded but RLIB file not found")
                else:
                    result.error_messages = process.stderr.split('\n') if process.stderr else ['Build failed']
                
            finally:
                # 恢复原配置
                if backup_file and backup_file.exists():
                    config_file.unlink(missing_ok=True)
                    backup_file.rename(config_file)
                    result.output_messages.append("Restored original config file")
                elif not backup_file:
                    # 删除我们创建的配置文件
                    config_file.unlink(missing_ok=True)
                    if not any(cargo_dir.iterdir()):  # 如果目录为空则删除
                        cargo_dir.rmdir()
                    result.output_messages.append("Cleaned up temporary config file")
            
        except subprocess.TimeoutExpired:
            result.error_messages.append("Build timed out after 10 minutes")
        except Exception as e:
            result.error_messages.append(f"Config file build failed: {e}")
        
        return result
    
    def _recompile_with_cli_system(
        self, 
        original_rlib_path: Path, 
        debug_report: DebugInfoReport,
        auto_confirm: bool
    ) -> RecompileResult:
        """使用CLI系统重编译."""
        result = RecompileResult()
        
        if not debug_report.source_info or not debug_report.source_info.crate_name:
            result.error_messages.append("CLI system method requires crate name")
            return result
        
        source_info = debug_report.source_info
        crate_name = source_info.crate_name
        
        self.logger.info(f"Recompiling {crate_name} using CLI system")
        
        try:
            import time
            from ..builders.dependency_resolver import DependencyResolver
            from ..builders.rust_builder import RustBuilder
            
            start_time = time.time()
            
            # 使用CLI的依赖管理系统
            resolver = DependencyResolver()
            
            # 创建临时项目
            dependencies = {crate_name: source_info.version or "latest"}
            # Use version in project name to match standard format
            version_str = source_info.version or "latest"
            project_name = f"{crate_name}-{version_str}"
            temp_project = resolver.create_dependency_project(
                project_name,
                dependencies,
                target=source_info.target_arch or "x86_64-unknown-linux-gnu"
            )
            
            result.output_messages.append(f"Created temporary project: {temp_project}")
            
            # 构建项目
            builder = RustBuilder(target=source_info.target_arch)
            deps_dir = builder.build_project(temp_project, profile="release")
            
            result.build_time_seconds = time.time() - start_time
            
            # 查找生成的RLIB文件
            rlib_pattern = f"lib{crate_name.replace('-', '_')}-*.rlib"
            rlib_files = list(deps_dir.glob(rlib_pattern))
            
            if rlib_files:
                # 选择最新的RLIB文件
                new_rlib = max(rlib_files, key=lambda x: x.stat().st_mtime)
                result.success = True
                result.new_rlib_path = new_rlib
                result.output_messages.append(f"✅ Successfully generated: {new_rlib}")
            else:
                result.error_messages.append(f"No RLIB files found matching pattern: {rlib_pattern}")
            
        except Exception as e:
            result.error_messages.append(f"CLI system build failed: {e}")
            self.logger.error(f"CLI system recompilation failed: {e}")
        
        return result
    
    def _find_generated_rlib(self, project_path: Path, source_info: RlibSourceInfo) -> Optional[Path]:
        """查找新生成的RLIB文件."""
        if not source_info.crate_name or not source_info.target_arch:
            return None
        
        profile = source_info.build_profile or "release"
        base_target_dir = project_path / "target" / source_info.target_arch / profile
        
        # 查找目录列表：deps和父目录
        search_dirs = [
            base_target_dir / "deps",
            base_target_dir
        ]
        
        crate_name = source_info.crate_name.replace('-', '_')
        
        # 查找模式：带hash和不带hash
        patterns = [
            f"lib{crate_name}-*.rlib",  # 带hash
            f"lib{crate_name}.rlib"     # 不带hash
        ]
        
        all_files = []
        for search_dir in search_dirs:
            if search_dir.exists():
                for pattern in patterns:
                    found_files = list(search_dir.glob(pattern))
                    all_files.extend(found_files)
                    self.logger.debug(f"Found {len(found_files)} files with pattern '{pattern}' in {search_dir}")
        
        if not all_files:
            self.logger.debug(f"No RLIB files found for crate '{crate_name}' in search directories")
            return None
        
        # 返回最新的文件
        latest_file = max(all_files, key=lambda x: x.stat().st_mtime)
        self.logger.debug(f"Selected latest RLIB file: {latest_file}")
        
        # 组织RLIB文件到标准位置和命名
        organized_rlib = self._organize_generated_rlib(latest_file, source_info)
        return organized_rlib or latest_file  # 如果组织失败，返回原始文件
    
    def _organize_generated_rlib(self, rlib_path: Path, source_info: RlibSourceInfo) -> Optional[Path]:
        """组织生成的RLIB文件到标准命名和位置.
        
        Args:
            rlib_path: 生成的RLIB文件路径
            source_info: RLIB源信息
            
        Returns:
            组织后的RLIB文件路径，如果失败返回None
        """
        try:
            # 确定库名和版本
            library_name = source_info.crate_name.replace('-', '_')
            version = getattr(source_info, 'version', None) or self._extract_version_from_original_rlib(rlib_path)
            
            if not version:
                # 如果无法确定版本，使用时间戳作为版本
                import time
                version = f"dev_{int(time.time())}"
                self.logger.warning(f"No version info available for {library_name}, using timestamp: {version}")
            
            # 使用RLIB管理器组织文件
            organized_path = self.rlib_manager.organize_rlib(
                rlib_path, 
                library_name, 
                version,
                source_info.crate_name  # 原始crate名用于目录组织
            )
            
            self.logger.info(f"Organized RLIB: {rlib_path.name} -> {organized_path.name}")
            return organized_path
            
        except Exception as e:
            self.logger.error(f"Failed to organize RLIB {rlib_path}: {e}")
            return None
    
    def _extract_version_from_original_rlib(self, rlib_path: Path) -> Optional[str]:
        """尝试从RLIB文件名或路径中提取版本信息.
        
        Args:
            rlib_path: RLIB文件路径
            
        Returns:
            提取的版本字符串，如果无法提取返回None
        """
        # 尝试从路径中查找版本信息
        path_parts = str(rlib_path).split('/')
        
        # 检查路径中是否包含版本信息（如 target/release, target/debug等）
        for part in path_parts:
            if part.startswith('rust-') and len(part) > 5:
                # 如果路径包含rust-1.75.0这样的信息
                potential_version = part[5:]  # 去掉'rust-'前缀
                if '.' in potential_version:
                    return potential_version
        
        # 尝试从环境变量获取Rust版本
        try:
            import subprocess
            result = subprocess.run(['rustc', '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # 输出格式类似: rustc 1.75.0 (82e1608df 2023-12-21)
                parts = result.stdout.split()
                if len(parts) >= 2:
                    return parts[1]  # 版本号
        except Exception:
            pass
        
        # 默认返回unknown
        return "unknown"
    
    def _verify_recompile_result(self, original_rlib_path: Path, result: RecompileResult):
        """验证重编译结果质量."""
        if not result.new_rlib_path or not result.new_rlib_path.exists():
            return
        
        try:
            # 使用调试信息检测器验证新RLIB的质量
            from ..extractors.debug_info_checker import RlibDebugInfoChecker
            
            checker = RlibDebugInfoChecker()
            
            # 检测原始文件质量
            original_report = checker.check_rlib_debug_info(original_rlib_path)
            original_score = original_report.quality_score
            
            # 检测新文件质量
            new_report = checker.check_rlib_debug_info(result.new_rlib_path)
            new_score = new_report.quality_score
            
            # 计算改进分数
            result.quality_improvement = new_score - original_score
            
            result.output_messages.append(
                f"Debug info quality: {original_score} → {new_score} "
                f"(improvement: +{result.quality_improvement})"
            )
            
            if result.quality_improvement > 0:
                self.logger.info(f"Quality improved by {result.quality_improvement} points")
            else:
                self.logger.warning("No quality improvement detected")
            
        except Exception as e:
            self.logger.warning(f"Failed to verify recompile result quality: {e}")
    
    def get_recompile_commands(self, debug_report: DebugInfoReport, method: str) -> List[str]:
        """
        获取指定方法的重编译命令列表（用于用户手动执行）.
        
        Args:
            debug_report: 调试信息分析报告
            method: 重编译方法
            
        Returns:
            命令列表
        """
        if not debug_report.recompile_options:
            return []
        
        for option in debug_report.recompile_options:
            if option.method == method:
                return option.commands
        
        return []
    
    def list_available_methods(self, debug_report: DebugInfoReport) -> List[Dict[str, Any]]:
        """
        列出可用的重编译方法.
        
        Args:
            debug_report: 调试信息分析报告
            
        Returns:
            可用方法的详细信息列表
        """
        methods = []
        
        if debug_report.recompile_options:
            for option in debug_report.recompile_options:
                methods.append({
                    'method': option.method,
                    'title': option.title,
                    'description': option.description,
                    'difficulty': option.difficulty,
                    'estimated_time': option.estimated_time,
                    'commands': option.commands
                })
        
        return methods