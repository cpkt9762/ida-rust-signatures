"""Command-line interface for Rust x86_64 IDA signatures generator.

This module provides the main CLI interface for generating IDA FLIRT signatures
from Rust crates with comprehensive command options and user-friendly output.
"""

import sys
from pathlib import Path
from typing import Dict, List, Optional

import click
import yaml

from ..builders.dependency_resolver import DependencyResolver, LocalDependencyManager
from ..builders.rust_builder import RustBuilder
from ..core.config import settings
from ..core.naming_utils import get_pat_filename, get_sig_filename, get_til_filename
from ..core.exceptions import SignatureError, ConfigValidationError, SubLibraryNotFoundError
from ..core.logger import setup_logging, get_logger
from ..core.config_loader import ConfigLoader
from ..extractors.rlib_extractor import RlibExtractor
from ..generators.flair_generator import FLAIRGenerator
from ..generators.custom_pat_generator import CustomPATGenerator
from ..generators.enhanced_pat_generator import EnhancedPATGenerator
from ..generators.collision_aware_generator import CollisionAwarePATGenerator, create_collision_aware_generator
from ..collision_prevention import CollisionPrevention

# Solana eBPF platform imports
from ..platforms.solana_ebpf.builders.solana_toolchain import SolanaToolchainManager
from ..platforms.solana_ebpf.builders.crate_compiler import SolanaProgramCompiler
from ..platforms.solana_ebpf.builders.rlib_collector import RlibCollector
from ..platforms.solana_ebpf.generators.solana_pat_generator import SolanaPATGenerator
from ..platforms.solana_ebpf.generators.version_merger import SolanaVersionMerger


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--output-dir', '-o', type=click.Path(), help='Output directory for signatures')
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.pass_context
def cli(ctx, verbose: bool, output_dir: Optional[str], config: Optional[str]):
    """Rust x86_64 IDA signatures generator.
    
    Generate IDA FLIRT signatures from Rust crates for reverse engineering analysis.
    """
    # Set up logging
    setup_logging(
        level="DEBUG" if verbose else settings.log_level,
        log_file=settings.log_file,
        verbose=verbose
    )
    
    # Create directories
    settings.create_directories()
    
    # Set up context
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    
    if output_dir:
        settings.output_dir = Path(output_dir)
        settings.output_dir.mkdir(parents=True, exist_ok=True)
    
    ctx.obj['output_dir'] = settings.output_dir
    
    if config:
        ctx.obj['config_file'] = Path(config)


@cli.command()
@click.option('--config', type=click.Path(exists=True), help='Configuration file path')
@click.option('--offline', is_flag=True, help='Download sources for offline usage')
@click.option('--deps-dir', type=click.Path(), help='Custom dependencies directory')
def fetch_dependencies(config: Optional[str], offline: bool, deps_dir: Optional[str]):
    """Fetch and download Solana dependencies to local directory.
    
    Downloads the source code of Solana dependencies (solana-sdk, solana-client, 
    solana-account-decoder) to the dependencies directory for offline usage.
    
    Example:
        fetch-dependencies --offline
        fetch-dependencies --config configs/solana.yaml --offline
    """
    logger = get_logger(__name__)
    
    # Load configuration
    if config:
        with open(config) as f:
            config_data = yaml.safe_load(f)
        dependencies = config_data.get('dependencies', {})
        project_name = config_data.get('project_name', 'solana_libs')
    else:
        # Default Solana dependencies
        dependencies = {
            "solana-sdk": "2.1",
            "solana-client": "2.1",
            "solana-account-decoder": "2.1"
        }
        project_name = "solana_libs"
    
    # Set custom dependencies directory if provided
    deps_directory = Path(deps_dir) if deps_dir else settings.dependencies_dir
    deps_directory.mkdir(parents=True, exist_ok=True)
    
    click.echo("📦 Fetching Solana dependencies...")
    click.echo(f"Target directory: {deps_directory}")
    click.echo(f"Dependencies: {dependencies}")
    
    try:
        if offline:
            # Download source code to local directory
            local_mgr = LocalDependencyManager(deps_directory)
            
            click.echo("\n🌐 Downloading source code from crates.io...")
            
            for crate_name, version in dependencies.items():
                click.echo(f"  📥 Downloading {crate_name} v{version}...")
                
                try:
                    crate_dir = local_mgr.download_crate_source(crate_name, version)
                    click.echo(f"     ✅ Downloaded to: {crate_dir}")
                    
                except Exception as e:
                    click.echo(f"     ❌ Failed: {e}")
                    logger.error(f"Failed to download {crate_name}: {e}")
        
        # Also create a Rust project to fetch registry dependencies
        click.echo("\n🔧 Setting up Rust project for dependency resolution...")
        
        resolver = DependencyResolver()
        project_dir = resolver.create_dependency_project(
            project_name, 
            dependencies
        )
        
        click.echo(f"✅ Rust project created at: {project_dir}")
        
        # Show summary
        click.echo(f"\n📊 Dependency fetch summary:")
        if offline:
            downloaded_dirs = list(deps_directory.glob("*-*"))
            click.echo(f"   - Source packages: {len(downloaded_dirs)}")
            
            for dir_path in downloaded_dirs:
                size_mb = sum(f.stat().st_size for f in dir_path.rglob('*') if f.is_file()) / (1024 * 1024)
                click.echo(f"     • {dir_path.name}: {size_mb:.1f} MB")
        
        click.echo(f"   - Rust project: {project_dir}")
        click.echo(f"   - Ready for compilation")
        
    except Exception as e:
        logger.exception("Dependency fetch failed")
        raise click.ClickException(f"Failed to fetch dependencies: {e}")


@cli.command()
@click.argument('crates', nargs=-1, required=True)
@click.option('--version', '-V', default='2.1', help='Crate version specification')
@click.option('--lib-name', '-n', help='Library name for signatures')
@click.option('--keep-temp', is_flag=True, help='Keep temporary build files')
@click.option('--target', help='Rust target architecture')
@click.option('--generator', type=click.Choice(['flair', 'custom', 'enhanced', 'collision-aware']), 
              default='collision-aware', help='Generator type to use')
@click.option('--demangle', is_flag=True, default=True, help='Enable Rust name demangling')
@click.option('--prevent-collisions', is_flag=True, default=True, help='Enable collision prevention')
@click.option('--dedup', is_flag=True, default=True, help='Enable pattern deduplication')
@click.option('--version-tag', is_flag=True, help='Add version tags to functions')
@click.option('--multi-pass', is_flag=True, default=True, help='Enable multi-pass optimization')
@click.pass_context
def generate(ctx, crates: tuple, version: str, lib_name: Optional[str], keep_temp: bool, 
             target: Optional[str], generator: str, demangle: bool, prevent_collisions: bool,
             dedup: bool, version_tag: bool, multi_pass: bool):
    """Generate signatures for specified crates.
    
    Examples:
        generate solana-sdk --version 2.1
        generate solana-sdk solana-client --lib-name solana_libs
        generate serde tokio --version 1.0
    """
    logger = get_logger(__name__)
    output_dir = ctx.obj['output_dir']
    
    if not lib_name:
        lib_name = '_'.join(crates)
    
    if target:
        original_target = settings.target_arch
        settings.target_arch = target
    
    logger.info(f"Generating signatures for: {', '.join(crates)}")
    logger.info(f"Version: {version}, Target: {settings.target_arch}")
    
    try:
        # Build dependencies
        dependencies = {crate: version for crate in crates}
        
        resolver = DependencyResolver()
        project_dir = resolver.create_dependency_project(
            f"sig_gen_{lib_name}",
            dependencies,
            settings.target_arch
        )
        
        builder = RustBuilder()
        deps_dir = builder.build_project(project_dir)
        
        # Extract object files
        extractor = RlibExtractor()
        object_files = []
        
        for crate in crates:
            rlib_pattern = f"lib{crate.replace('-', '_')}-*.rlib"
            rlib_files = list(deps_dir.glob(rlib_pattern))
            
            if not rlib_files:
                logger.warning(f"No .rlib files found for {crate}")
                continue
            
            for rlib_file in rlib_files:
                objects = extractor.extract_objects(rlib_file, output_dir / "objects" / crate)
                object_files.extend(objects)
        
        if not object_files:
            raise click.ClickException("No object files extracted")
        
        logger.info(f"Extracted {len(object_files)} object files")
        
        # Select and configure generator based on user choice
        click.echo(f"🔧 Using {generator} generator with options:")
        click.echo(f"   - Demangle: {demangle}")
        click.echo(f"   - Prevent collisions: {prevent_collisions}")
        click.echo(f"   - Deduplication: {dedup}")
        click.echo(f"   - Version tagging: {version_tag}")
        click.echo(f"   - Multi-pass: {multi_pass}")
        
        if generator == 'flair':
            gen = FLAIRGenerator()
            result = gen.generate_signature_set(
                object_files,
                output_dir,
                lib_name,
                lib_name
            )
        elif generator == 'custom':
            gen = CustomPATGenerator(
                demangle_rust_names=demangle,
                use_short_names=True
            )
            # For custom generator, we need to process RLIB files directly
            # This is a simplified implementation - would need adjustment for object files  
            pat_filename = get_pat_filename(lib_name, version, 'x86_64')
            result = {'pat': output_dir / pat_filename}
            click.echo("⚠️  Custom generator requires RLIB input, not object files")
        elif generator == 'enhanced':
            gen = EnhancedPATGenerator(
                demangle_names=demangle,
                use_short_names=True
            )
            # Enhanced generator also works with RLIB files
            pat_filename = get_pat_filename(lib_name, version, 'x86_64')
            result = {'pat': output_dir / pat_filename}
            click.echo("⚠️  Enhanced generator requires RLIB input, not object files")
        else:  # collision-aware
            # For collision-aware, we need to work with RLIB files
            # Let's find the RLIB files from the build
            rlib_files = []
            for crate in crates:
                rlib_pattern = f"lib{crate.replace('-', '_')}-*.rlib"
                if 'deps_dir' in locals():
                    rlib_matches = list(deps_dir.glob(rlib_pattern))
                    if rlib_matches:
                        rlib_files.extend(rlib_matches)
            
            if rlib_files:
                # Use the first RLIB for now (in real usage, might want to merge)
                gen = create_collision_aware_generator(
                    enable_prevention=prevent_collisions,
                    enable_deduplication=dedup,
                    enable_version_tagging=version_tag,
                    auto_resolve_collisions=True
                )
                
                result = gen.generate_signatures(
                    rlib_path=rlib_files[0],
                    output_dir=output_dir,
                    library_name=lib_name,
                    library_version=version if version_tag else None,
                    generate_sig=True,
                    multi_pass=multi_pass
                )
                
                # Show statistics
                if hasattr(gen, 'stats'):
                    click.echo("📊 Generation statistics:")
                    for key, value in gen.stats.items():
                        click.echo(f"   - {key}: {value}")
            else:
                click.echo("❌ No RLIB files found for collision-aware generator")
                result = {}
        
        if 'pat' in result:
            click.echo("✅ Signature generation completed successfully!")
            click.echo(f"   PAT file: {result['pat']}")
        
        if 'sig' in result:
            click.echo(f"   SIG file: {result['sig']}")
            
            # Validate generated signature
            if generator == 'flair':
                issues = gen.validate_signature_file(result['sig'])
                if issues:
                    click.echo("⚠️  Signature validation warnings:")
                    for issue in issues:
                        click.echo(f"   - {issue}")
                else:
                    click.echo("✅ Signature validation passed")
            
    except SignatureError as e:
        logger.error(f"Signature generation failed: {e}")
        raise click.ClickException(str(e))
        
    except Exception as e:
        logger.exception("Unexpected error during signature generation")
        raise click.ClickException(f"Unexpected error: {e}")
        
    finally:
        # Cleanup
        if not keep_temp and 'project_dir' in locals():
            import shutil
            try:
                shutil.rmtree(project_dir, ignore_errors=True)
                logger.debug(f"Cleaned up temporary project: {project_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temporary project: {e}")
        
        # Restore original target
        if target:
            settings.target_arch = original_target


@cli.command()
@click.argument('rlib_path', type=click.Path(exists=True))
@click.option('--lib-name', '-n', required=True, help='Library name for signatures')
@click.option('--version', '-v', help='Library version for tagging')
@click.option('--output-dir', '-o', type=click.Path(), help='Output directory')
@click.option('--demangle/--no-demangle', default=True, help='Enable Rust name demangling')
@click.option('--dedup/--no-dedup', default=True, help='Enable pattern deduplication')
@click.option('--prevent-collisions/--no-prevent-collisions', default=True, help='Enable collision prevention')
@click.option('--version-tag/--no-version-tag', default=False, help='Add version tags to functions')
@click.option('--multi-pass/--single-pass', default=True, help='Enable multi-pass optimization')
def generate_enhanced(rlib_path: str, lib_name: str, version: Optional[str], output_dir: Optional[str],
                     demangle: bool, dedup: bool, prevent_collisions: bool, version_tag: bool, multi_pass: bool):
    """Generate enhanced signatures from RLIB file with collision handling.
    
    This command uses the most advanced generator with all optimizations.
    
    Example:
        generate-enhanced path/to/lib.rlib --lib-name mylib --version 1.0.0
    """
    logger = get_logger(__name__)
    
    rlib_file = Path(rlib_path)
    if not rlib_file.exists():
        raise click.ClickException(f"RLIB file not found: {rlib_path}")
    
    out_dir = Path(output_dir) if output_dir else settings.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    
    click.echo(f"🚀 Generating enhanced signatures for: {rlib_file.name}")
    click.echo(f"📁 Output directory: {out_dir}")
    click.echo(f"🔧 Options:")
    click.echo(f"   - Library name: {lib_name}")
    click.echo(f"   - Version: {version or 'None'}")
    click.echo(f"   - Demangle: {demangle}")
    click.echo(f"   - Deduplication: {dedup}")
    click.echo(f"   - Collision prevention: {prevent_collisions}")
    click.echo(f"   - Version tagging: {version_tag}")
    click.echo(f"   - Multi-pass: {multi_pass}")
    
    try:
        # Create collision-aware generator with specified options
        generator = create_collision_aware_generator(
            enable_prevention=prevent_collisions,
            enable_deduplication=dedup,
            enable_version_tagging=version_tag,
            auto_resolve_collisions=True
        )
        
        # Configure base generator for demangling
        if hasattr(generator.base_generator, 'demangle_names'):
            generator.base_generator.demangle_names = demangle
        
        # Generate signatures
        click.echo("\n⚙️  Processing RLIB file...")
        result = generator.generate_signatures(
            rlib_path=rlib_file,
            output_dir=out_dir,
            library_name=lib_name,
            library_version=version if version_tag else None,
            generate_sig=True,
            multi_pass=multi_pass
        )
        
        # Report results
        click.echo("\n✅ Signature generation completed!")
        
        if 'pat' in result and result['pat'].exists():
            pat_size = result['pat'].stat().st_size
            click.echo(f"📄 PAT file: {result['pat']} ({pat_size:,} bytes)")
            
            # Count patterns
            with open(result['pat'], 'r') as f:
                pat_lines = f.readlines()
            pattern_count = sum(1 for line in pat_lines 
                              if line.strip() and not line.startswith(';') and not line.startswith('---'))
            click.echo(f"   Patterns: {pattern_count:,}")
        
        if 'sig' in result and result['sig'].exists():
            sig_size = result['sig'].stat().st_size
            click.echo(f"📄 SIG file: {result['sig']} ({sig_size:,} bytes)")
            click.echo(f"   Compression ratio: {pat_size/sig_size:.2f}:1")
        
        # Show statistics
        if hasattr(generator, 'stats') and generator.stats:
            click.echo("\n📊 Generation Statistics:")
            stats = generator.stats
            if 'total_functions' in stats:
                click.echo(f"   Total functions: {stats['total_functions']:,}")
            if 'deduplicated_functions' in stats and stats['deduplicated_functions'] > 0:
                click.echo(f"   Deduplicated: {stats['deduplicated_functions']:,}")
            if 'filtered_functions' in stats and stats['filtered_functions'] > 0:
                click.echo(f"   Filtered: {stats['filtered_functions']:,}")
            if 'collisions_prevented' in stats and stats['collisions_prevented'] > 0:
                click.echo(f"   Collisions prevented: {stats['collisions_prevented']:,}")
            if 'collisions_resolved' in stats and stats['collisions_resolved'] > 0:
                click.echo(f"   Collisions resolved: {stats['collisions_resolved']:,}")
            if 'version_tagged' in stats and version_tag:
                click.echo(f"   Version tagged: {stats['version_tagged']:,}")
        
        click.echo("\n🎯 Next steps:")
        click.echo("   1. Copy the .sig file to IDA Pro's sig/pc/ directory")
        click.echo("   2. In IDA Pro: File → Load file → FLIRT signature file")
        click.echo(f"   3. Select '{lib_name}' signature")
        
    except Exception as e:
        logger.exception("Enhanced signature generation failed")
        raise click.ClickException(f"Generation failed: {e}")


@cli.command()
@click.option('--config', type=click.Path(exists=True), help='Configuration file path')
def auto_generate_solana(config: Optional[str]):
    """Auto-generate signatures for Solana libraries.
    
    This command first fetches the dependencies and then generates signatures
    for the standard Solana library set.
    """
    logger = get_logger(__name__)
    
    # Load configuration
    if config:
        with open(config) as f:
            config_data = yaml.safe_load(f)
        dependencies = config_data.get('dependencies', {})
        project_name = config_data.get('project_name', 'solana_libs')
    else:
        dependencies = {
            "solana-sdk": "2.1",
            "solana-client": "2.1",
            "solana-account-decoder": "2.1"
        }
        project_name = "solana_libs"
    
    click.echo("🚀 Auto-generating Solana library signatures...")
    click.echo(f"Dependencies: {dependencies}")
    
    try:
        # Step 1: Fetch dependencies
        click.echo("\n📦 Step 1: Fetching dependencies...")
        local_mgr = LocalDependencyManager()
        
        for crate_name, version in dependencies.items():
            click.echo(f"  📥 Fetching {crate_name} v{version}...")
            try:
                crate_dir = local_mgr.download_crate_source(crate_name, version)
                click.echo(f"     ✅ Available at: {crate_dir}")
            except Exception as e:
                click.echo(f"     ⚠️  Download failed (will use registry): {e}")
        
        # Step 2: Create and build project
        click.echo("\n🔧 Step 2: Creating Rust project...")
        resolver = DependencyResolver()
        project_dir = resolver.create_dependency_project(project_name, dependencies)
        
        builder = RustBuilder()
        deps_dir = builder.build_project(project_dir)
        
        # Step 3: Extract all object files
        click.echo("\n📂 Step 3: Extracting object files...")
        extractor = RlibExtractor()
        all_rlibs = list(deps_dir.glob("*.rlib"))
        
        click.echo(f"Found {len(all_rlibs)} .rlib files to process")
        
        batch_results = extractor.batch_extract(all_rlibs, settings.output_dir / "objects")
        
        # Collect all object files
        all_objects = []
        for objects in batch_results.values():
            all_objects.extend(objects)
        
        if not all_objects:
            raise click.ClickException("No object files extracted")
        
        click.echo(f"Extracted {len(all_objects)} object files")
        
        # Step 4: Generate signatures using collision-aware generator
        click.echo("\n🎯 Step 4: Generating signatures with collision-aware generator...")
        
        # Find the main RLIB files
        main_rlibs = []
        for dep_name in dependencies.keys():
            lib_name = dep_name.replace('-', '_')
            rlib_pattern = f"lib{lib_name}-*.rlib"
            matches = list(deps_dir.glob(rlib_pattern))
            if matches:
                # Take the first match (should be only one)
                main_rlibs.append((dep_name, matches[0]))
        
        if not main_rlibs:
            raise click.ClickException("No main RLIB files found")
        
        click.echo(f"Found {len(main_rlibs)} main libraries to process")
        
        # Process each library separately with version tags
        all_results = []
        for lib_name, rlib_path in main_rlibs:
            click.echo(f"\n📦 Processing {lib_name}...")
            
            # Create collision-aware generator
            generator = create_collision_aware_generator(
                enable_prevention=True,
                enable_deduplication=True,
                enable_version_tagging=True,
                auto_resolve_collisions=True
            )
            
            # Get version from dependencies
            lib_version = dependencies.get(lib_name, "unknown")
            
            # Generate signatures
            try:
                result = generator.generate_signatures(
                    rlib_path=rlib_path,
                    output_dir=settings.output_dir,
                    library_name=lib_name.replace('-', '_'),
                    library_version=lib_version,
                    generate_sig=True,
                    multi_pass=True
                )
                
                all_results.append({
                    'library': lib_name,
                    'version': lib_version,
                    'result': result,
                    'stats': generator.stats if hasattr(generator, 'stats') else {}
                })
                
                if 'sig' in result and result['sig'].exists():
                    click.echo(f"   ✅ Generated: {result['sig'].name}")
                
            except Exception as e:
                click.echo(f"   ❌ Failed: {e}")
                logger.error(f"Failed to generate signatures for {lib_name}: {e}")
        
        # Summary
        click.echo("\n🎉 Solana signature generation completed!")
        click.echo("📊 Summary:")
        
        total_patterns = 0
        total_sig_size = 0
        
        for res in all_results:
            if 'sig' in res['result'] and res['result']['sig'].exists():
                sig_size = res['result']['sig'].stat().st_size
                total_sig_size += sig_size
                
                stats = res['stats']
                patterns = stats.get('total_functions', 0) - stats.get('deduplicated_functions', 0)
                total_patterns += patterns
                
                click.echo(f"   - {res['library']} v{res['version']}: {patterns:,} patterns, {sig_size:,} bytes")
        
        click.echo(f"\nTotal: {total_patterns:,} patterns in {total_sig_size:,} bytes")
        
        # Show dependency sources location
        deps_with_sources = list(settings.dependencies_dir.glob("*-*"))
        if deps_with_sources:
            click.echo(f"📁 Source dependencies available at:")
            for dep_dir in deps_with_sources:
                click.echo(f"   - {dep_dir}")
        
    except Exception as e:
        logger.exception("Auto-generation failed")
        raise click.ClickException(f"Auto-generation failed: {e}")


@cli.command()
@click.argument('pat_file', type=click.Path(exists=True))
@click.option('--fix', is_flag=True, help='Fix collisions by deduplication')
@click.option('--output', '-o', type=click.Path(), help='Output file for fixed PAT')
def analyze_collisions(pat_file: str, fix: bool, output: Optional[str]):
    """Analyze PAT file for potential collisions and duplicates.
    
    Example:
        analyze-collisions signatures.pat
        analyze-collisions signatures.pat --fix --output fixed.pat
    """
    from ..collision_prevention import CollisionPrevention
    
    pat_path = Path(pat_file)
    if not pat_path.exists():
        raise click.ClickException(f"PAT file not found: {pat_file}")
    
    click.echo(f"🔍 Analyzing PAT file: {pat_path}")
    
    # Create collision prevention analyzer
    analyzer = CollisionPrevention()
    
    # Read PAT file
    with open(pat_path, 'r') as f:
        lines = f.readlines()
    
    # Count total patterns
    pattern_lines = [line for line in lines 
                    if line.strip() and not line.startswith(';') and not line.startswith('---')]
    total_patterns = len(pattern_lines)
    
    click.echo(f"📊 Total patterns: {total_patterns:,}")
    
    # Analyze for duplicates
    pattern_hashes = {}
    duplicates = {}
    
    for line in pattern_lines:
        parts = line.strip().split()
        if len(parts) >= 6:
            # Extract pattern info
            pattern_data = parts[0]
            crc = parts[1]
            length = parts[2]
            func_name = parts[5]
            
            # Create hash
            pattern_hash = analyzer.pattern_hash([pattern_data, crc, length])
            
            if pattern_hash in pattern_hashes:
                if pattern_hash not in duplicates:
                    duplicates[pattern_hash] = [pattern_hashes[pattern_hash]]
                duplicates[pattern_hash].append((func_name, line))
            else:
                pattern_hashes[pattern_hash] = (func_name, line)
    
    # Report findings
    if duplicates:
        click.echo(f"\n⚠️  Found {len(duplicates)} duplicate pattern groups:")
        
        total_dups = sum(len(group) for group in duplicates.values())
        click.echo(f"   Total duplicate patterns: {total_dups}")
        click.echo(f"   Potential reduction: {total_dups:,} patterns ({total_dups/total_patterns*100:.1f}%)")
        
        # Show examples
        click.echo("\n📋 Example duplicates (showing first 5):")
        for i, (hash_val, dup_group) in enumerate(list(duplicates.items())[:5]):
            click.echo(f"\n   Pattern hash: {hash_val[:8]}...")
            click.echo(f"   Functions ({len(dup_group)}):")
            for func_name, _ in dup_group[:3]:  # Show first 3
                click.echo(f"     - {func_name}")
            if len(dup_group) > 3:
                click.echo(f"     ... and {len(dup_group) - 3} more")
    else:
        click.echo("\n✅ No duplicate patterns found!")
    
    # Fix if requested
    if fix:
        output_path = Path(output) if output else pat_path.with_suffix('.fixed.pat')
        
        click.echo(f"\n🔧 Fixing collisions...")
        
        # Keep only unique patterns
        seen_hashes = set()
        fixed_lines = []
        removed_count = 0
        
        for line in lines:
            if line.strip() and not line.startswith(';') and not line.startswith('---'):
                parts = line.strip().split()
                if len(parts) >= 6:
                    pattern_data = parts[0]
                    crc = parts[1]
                    length = parts[2]
                    
                    pattern_hash = analyzer.pattern_hash([pattern_data, crc, length])
                    
                    if pattern_hash not in seen_hashes:
                        seen_hashes.add(pattern_hash)
                        fixed_lines.append(line)
                    else:
                        removed_count += 1
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)
        
        # Write fixed file
        with open(output_path, 'w') as f:
            f.writelines(fixed_lines)
        
        click.echo(f"✅ Fixed PAT file written to: {output_path}")
        click.echo(f"   Removed {removed_count} duplicate patterns")
        click.echo(f"   Final pattern count: {total_patterns - removed_count:,}")


@cli.command()
def list_dependencies():
    """List downloaded dependencies in the dependencies directory."""
    deps_dir = settings.dependencies_dir
    
    if not deps_dir.exists():
        click.echo("❌ Dependencies directory does not exist")
        return
    
    # Find all downloaded crate directories
    crate_dirs = [d for d in deps_dir.iterdir() if d.is_dir() and '-' in d.name]
    
    if not crate_dirs:
        click.echo("📦 No dependencies found in dependencies directory")
        click.echo(f"Directory: {deps_dir}")
        click.echo("Run 'fetch-dependencies --offline' to download sources")
        return
    
    click.echo("📦 Downloaded dependencies:")
    click.echo(f"Location: {deps_dir}")
    click.echo("=" * 60)
    
    total_size = 0
    for crate_dir in sorted(crate_dirs):
        # Calculate directory size
        size = sum(f.stat().st_size for f in crate_dir.rglob('*') if f.is_file())
        total_size += size
        size_mb = size / (1024 * 1024)
        
        # Get basic info
        cargo_toml = crate_dir / "Cargo.toml"
        version_info = "unknown"
        
        if cargo_toml.exists():
            try:
                import toml
                cargo_data = toml.load(cargo_toml)
                version_info = cargo_data.get('package', {}).get('version', 'unknown')
            except Exception:
                pass
        
        click.echo(f"  📁 {crate_dir.name}")
        click.echo(f"     Version: {version_info}")
        click.echo(f"     Size: {size_mb:.1f} MB")
        click.echo()
    
    click.echo(f"Total: {len(crate_dirs)} crates, {total_size / (1024 * 1024):.1f} MB")


@cli.command()
@click.argument('signature_file', type=click.Path(exists=True))
def validate(signature_file: str):
    """Validate signature files.
    
    Check PAT or SIG files for validity and show statistics.
    """
    sig_path = Path(signature_file)
    
    if sig_path.suffix == '.sig':
        generator = FLAIRGenerator()
        issues = generator.validate_signature_file(sig_path)
        
        if issues:
            click.echo("❌ Signature file validation failed:")
            for issue in issues:
                click.echo(f"   - {issue}")
            sys.exit(1)
        else:
            size = sig_path.stat().st_size
            click.echo("✅ SIG file is valid")
            click.echo(f"   Size: {size:,} bytes")
            
    elif sig_path.suffix == '.pat':
        try:
            lines = sig_path.read_text(encoding='utf-8').splitlines()
            pattern_lines = [line for line in lines 
                           if line.strip() and not line.startswith(';') and not line.startswith('---')]
            pattern_count = len(pattern_lines)
            
            click.echo("✅ PAT file appears valid")
            click.echo(f"   Patterns: {pattern_count:,}")
            click.echo(f"   Total lines: {len(lines):,}")
            
            # Analyze function names
            demangled_count = 0
            version_tagged = 0
            rust_mangled = 0
            
            for line in pattern_lines:
                parts = line.split()
                if len(parts) >= 6:
                    func_name = parts[5]
                    
                    if func_name.startswith('_ZN') or func_name.startswith('_RNv'):
                        rust_mangled += 1
                    elif '::' in func_name:
                        demangled_count += 1
                    
                    if '@v' in func_name or '$SP$v' in func_name:
                        version_tagged += 1
            
            click.echo("\n📊 Function Name Analysis:")
            click.echo(f"   Rust mangled: {rust_mangled:,} ({rust_mangled/pattern_count*100:.1f}%)")
            click.echo(f"   Demangled: {demangled_count:,} ({demangled_count/pattern_count*100:.1f}%)")
            click.echo(f"   Version tagged: {version_tagged:,} ({version_tagged/pattern_count*100:.1f}%)")
            
            # Check for potential collisions
            from ..collision_prevention import CollisionPrevention
            analyzer = CollisionPrevention()
            
            pattern_hashes = set()
            duplicate_count = 0
            
            for line in pattern_lines:
                parts = line.split()
                if len(parts) >= 3:
                    pattern_hash = analyzer.pattern_hash(parts[:3])
                    if pattern_hash in pattern_hashes:
                        duplicate_count += 1
                    else:
                        pattern_hashes.add(pattern_hash)
            
            if duplicate_count > 0:
                click.echo(f"\n⚠️  Potential collisions detected:")
                click.echo(f"   Duplicate patterns: {duplicate_count:,}")
                click.echo(f"   Unique patterns: {len(pattern_hashes):,}")
                click.echo(f"   Consider using 'analyze-collisions' command for details")
            else:
                click.echo(f"\n✅ No duplicate patterns detected")
            
        except Exception as e:
            click.echo(f"❌ Failed to read PAT file: {e}")
            sys.exit(1)
            
    else:
        click.echo("❌ Unsupported file format (expected .sig or .pat)")
        sys.exit(1)


@cli.command()
@click.option('--rlib-dir', '-d', type=click.Path(exists=True), required=True, help='Directory containing RLIB files')
@click.option('--output-dir', '-o', type=click.Path(), help='Output directory for signatures')
@click.option('--version-tag/--no-version-tag', default=True, help='Add version tags from filenames')
@click.option('--pattern', '-p', default='*.rlib', help='File pattern to match')
def batch_generate(rlib_dir: str, output_dir: Optional[str], version_tag: bool, pattern: str):
    """Batch generate signatures for multiple RLIB files.
    
    Example:
        batch-generate --rlib-dir ./libs --output-dir ./sigs
        batch-generate -d /path/to/rlibs -p "solana*.rlib"
    """
    logger = get_logger(__name__)
    
    rlib_directory = Path(rlib_dir)
    if not rlib_directory.exists():
        raise click.ClickException(f"RLIB directory not found: {rlib_dir}")
    
    out_dir = Path(output_dir) if output_dir else settings.output_dir / "batch"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Find all RLIB files
    rlib_files = list(rlib_directory.glob(pattern))
    
    if not rlib_files:
        click.echo(f"❌ No RLIB files found matching pattern: {pattern}")
        return
    
    click.echo(f"🔍 Found {len(rlib_files)} RLIB files to process")
    click.echo(f"📁 Output directory: {out_dir}")
    
    # Process each RLIB
    success_count = 0
    failed_count = 0
    total_sig_size = 0
    
    for i, rlib_path in enumerate(rlib_files, 1):
        click.echo(f"\n[{i}/{len(rlib_files)}] Processing: {rlib_path.name}")
        
        # Extract library name and version from filename
        lib_name = rlib_path.stem
        if lib_name.startswith('lib'):
            lib_name = lib_name[3:]  # Remove 'lib' prefix
        
        # Try to extract version from filename (e.g., libname-1.2.3-hash.rlib)
        version = None
        if version_tag and '-' in lib_name:
            parts = lib_name.split('-')
            # Look for version-like patterns
            for part in parts[1:]:
                if any(c.isdigit() for c in part) and '.' in part:
                    version = part
                    lib_name = parts[0]
                    break
        
        try:
            # Create generator
            generator = create_collision_aware_generator(
                enable_prevention=True,
                enable_deduplication=True,
                enable_version_tagging=version_tag and version is not None,
                auto_resolve_collisions=True
            )
            
            # Generate signatures
            result = generator.generate_signatures(
                rlib_path=rlib_path,
                output_dir=out_dir,
                library_name=lib_name,
                library_version=version,
                generate_sig=True,
                multi_pass=True
            )
            
            if 'sig' in result and result['sig'].exists():
                sig_size = result['sig'].stat().st_size
                total_sig_size += sig_size
                success_count += 1
                click.echo(f"   ✅ Success: {result['sig'].name} ({sig_size:,} bytes)")
                
                # Show brief stats
                if hasattr(generator, 'stats'):
                    funcs = generator.stats.get('total_functions', 0)
                    dedup = generator.stats.get('deduplicated_functions', 0)
                    if funcs > 0:
                        click.echo(f"      Functions: {funcs - dedup:,} (dedup: {dedup})")
            else:
                failed_count += 1
                click.echo(f"   ❌ Failed: No SIG file generated")
                
        except Exception as e:
            failed_count += 1
            click.echo(f"   ❌ Failed: {str(e)}")
            logger.error(f"Failed to process {rlib_path}: {e}")
    
    # Summary
    click.echo("\n" + "=" * 60)
    click.echo("📊 BATCH GENERATION SUMMARY")
    click.echo("=" * 60)
    click.echo(f"✅ Successful: {success_count}")
    click.echo(f"❌ Failed: {failed_count}")
    click.echo(f"📏 Total SIG size: {total_sig_size:,} bytes ({total_sig_size/1024/1024:.1f} MB)")
    
    if success_count > 0:
        click.echo(f"\n📁 Output files in: {out_dir}")


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), required=True, 
              help='Configuration file path (batch_libraries.yaml)')
@click.option('--preset', '-p', help='Batch preset name to use')
@click.option('--library', '-l', help='Specific library to process')
@click.option('--version', '-v', help='Specific version to process')
@click.option('--solana-version', help='Override Solana toolchain version')
@click.option('--rust-version', help='Override Rust toolchain version')
@click.option('--include-sub-libraries/--no-sub-libraries', default=True,
              help='Include sub-libraries in processing')
@click.option('--validation-mode', type=click.Choice(['strict', 'lenient', 'auto']), 
              default='strict', help='Configuration validation mode')
@click.option('--dry-run', is_flag=True, help='Show what would be processed without executing')
def batch_config_generate(config: str, preset: Optional[str], library: Optional[str], 
                         version: Optional[str], solana_version: Optional[str], 
                         rust_version: Optional[str], include_sub_libraries: bool,
                         validation_mode: str, dry_run: bool):
    """Generate signatures using YAML configuration file.
    
    Process libraries and sub-libraries based on configuration file settings
    with support for toolchain overrides and batch presets.
    
    Examples:
        # Use a specific preset
        batch-config-generate -c configs/batch_libraries.yaml -p solana_1_18_16_complete
        
        # Process specific library with toolchain override
        batch-config-generate -c configs/batch_libraries.yaml -l solana_program_ebpf -v 1.18.16 --solana-version 1.18.16
        
        # Dry run to see what would be processed
        batch-config-generate -c configs/batch_libraries.yaml -p all_versions_matrix --dry-run
    """
    logger = get_logger(__name__)
    
    try:
        # Load and validate configuration
        config_loader = ConfigLoader(Path(config), validation_mode)
        config_data = config_loader.load_config()
        
        click.echo(f"✅ Configuration loaded from {config}")
        click.echo(f"📋 Validation mode: {validation_mode}")
        
        # Prepare toolchain overrides
        toolchain_overrides = {}
        if solana_version:
            toolchain_overrides['solana_version'] = solana_version
        if rust_version:
            toolchain_overrides['rust_version'] = rust_version
        
        if toolchain_overrides:
            click.echo(f"🔧 Toolchain overrides: {toolchain_overrides}")
        
        # Determine what to process
        libraries_to_process = []
        
        if preset:
            # Use batch preset
            preset_config = config_loader.get_batch_preset(preset)
            click.echo(f"📦 Using preset: {preset} - {preset_config.get('description', 'No description')}")
            
            # Get libraries from preset
            preset_libraries = preset_config.get('libraries', [])
            for lib_ref in preset_libraries:
                if isinstance(lib_ref, dict):
                    lib_name = lib_ref.get('library')
                    lib_versions = lib_ref.get('versions', [])
                    include_subs = lib_ref.get('include_sub_libraries', include_sub_libraries)
                    
                    for lib_version in lib_versions:
                        libraries_to_process.append({
                            'library': lib_name,
                            'version': lib_version,
                            'include_sub_libraries': include_subs
                        })
        
        elif library:
            # Process specific library
            if version:
                libraries_to_process.append({
                    'library': library,
                    'version': version,
                    'include_sub_libraries': include_sub_libraries
                })
            else:
                # Use all available versions
                versions = config_loader.get_library_versions(library)
                for lib_version in versions:
                    libraries_to_process.append({
                        'library': library,
                        'version': lib_version,
                        'include_sub_libraries': include_sub_libraries
                    })
        else:
            click.echo("❌ Must specify either --preset or --library")
            sys.exit(1)
        
        if not libraries_to_process:
            click.echo("❌ No libraries to process")
            sys.exit(1)
        
        click.echo(f"🎯 Processing {len(libraries_to_process)} library configurations")
        
        if dry_run:
            click.echo("\n🔍 Dry run - showing what would be processed:")
            for i, lib_config in enumerate(libraries_to_process, 1):
                click.echo(f"  [{i}] {lib_config['library']} v{lib_config['version']}")
                if lib_config['include_sub_libraries']:
                    click.echo(f"      + Include sub-libraries")
            click.echo("\n⚠️  Use without --dry-run to execute")
            return
        
        # Process each library
        success_count = 0
        failed_count = 0
        
        for i, lib_config in enumerate(libraries_to_process, 1):
            lib_name = lib_config['library']
            lib_version = lib_config['version']
            
            click.echo(f"\n[{i}/{len(libraries_to_process)}] Processing {lib_name} v{lib_version}")
            
            try:
                # Resolve library configuration with toolchain overrides
                resolved_config = config_loader.resolve_library_configuration(
                    lib_name, lib_version, toolchain_overrides
                )
                
                # Determine platform and delegate to appropriate processor
                platform = resolved_config.get('platform', 'x86_64')
                
                if platform == 'solana_ebpf':
                    success = _process_solana_library(resolved_config, lib_name, lib_version)
                else:
                    success = _process_x86_64_library(resolved_config, lib_name, lib_version)
                
                if success:
                    success_count += 1
                    click.echo(f"  ✅ {lib_name} v{lib_version} completed")
                else:
                    failed_count += 1
                    click.echo(f"  ❌ {lib_name} v{lib_version} failed")
                    
            except Exception as e:
                failed_count += 1
                click.echo(f"  ❌ {lib_name} v{lib_version} failed: {e}")
                logger.error(f"Failed to process {lib_name} v{lib_version}: {e}")
        
        # Summary
        click.echo(f"\n📊 Processing Summary:")
        click.echo(f"✅ Success: {success_count}")
        click.echo(f"❌ Failed: {failed_count}")
        
        if failed_count > 0:
            sys.exit(1)
            
    except ConfigValidationError as e:
        click.echo(f"❌ Configuration validation error: {e}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}")
        logger.error(f"Batch config generate failed: {e}")
        sys.exit(1)


def _process_solana_library(config: Dict, lib_name: str, lib_version: str) -> bool:
    """Process a Solana eBPF library configuration."""
    logger = get_logger(__name__)
    
    try:
        # Extract toolchain information
        resolved_toolchain = config.get('resolved_toolchain', {})
        solana_version = resolved_toolchain.get('solana_version', lib_version)
        
        # Initialize Solana toolchain and compiler
        toolchain_manager = SolanaToolchainManager()
        compiler = SolanaProgramCompiler(toolchain_manager)
        
        # Ensure toolchain is installed
        if not toolchain_manager.is_toolchain_installed(solana_version):
            click.echo(f"  📥 Installing Solana toolchain {solana_version}...")
            toolchain_manager.install_toolchain(solana_version)
        
        # Compile RLIB
        click.echo(f"  🔨 Compiling {lib_name} v{lib_version} to RLIB...")
        crate_name = config.get('crate_name', lib_name.replace('_ebpf', ''))
        rlib_path = compiler.compile_downloaded_crate(crate_name, lib_version, solana_version)
        
        # Generate PAT
        click.echo(f"  📝 Generating PAT file...")
        pat_generator = SolanaPATGenerator()
        pat_path = pat_generator.generate_pat_from_rlib(rlib_path)
        
        # Generate SIG if configured
        versions_config = config.get('versions', [])
        current_version_config = None
        for v in versions_config:
            if v.get('version') == lib_version:
                current_version_config = v
                break
        
        if current_version_config and current_version_config.get('generate', {}).get('sig', False):
            click.echo(f"  🔏 Generating SIG file...")
            try:
                from ..generators.flair_generator import FLAIRGenerator
                flair_gen = FLAIRGenerator()
                sig_output_path = pat_path.with_suffix('.sig')
                
                # Try multiple collision handling modes for better success rate
                collision_modes = ['accept', 'force', 'strict']
                sig_generated = False
                
                for mode in collision_modes:
                    try:
                        click.echo(f"    🔄 Trying collision mode: {mode}")
                        result = flair_gen.generate_sig_with_collision_handling(
                            pat_path, sig_output_path, lib_name, mode=mode
                        )
                        
                        if result and result.get('success'):
                            stats = result.get('stats', {})
                            functions_included = stats.get('functions_included', 'unknown')
                            functions_skipped = stats.get('functions_skipped', 0)
                            collisions_detected = stats.get('collisions_detected', 0)
                            
                            click.echo(f"    ✅ SIG generated with {mode} mode")
                            click.echo(f"    📊 Functions: {functions_included} included, {functions_skipped} skipped, {collisions_detected} collisions")
                            click.echo(f"    ✅ SIG: {sig_output_path}")
                            sig_generated = True
                            break
                    except Exception as mode_error:
                        click.echo(f"    ⚠️  Mode {mode} failed: {mode_error}")
                        continue
                
                if not sig_generated:
                    logger.warning(f"SIG generation failed with all collision modes")
                    click.echo(f"    ❌ SIG generation failed with all modes")
                
            except Exception as e:
                logger.warning(f"SIG generation failed: {e}")
                click.echo(f"    ❌ SIG generation failed: {e}")
        
        # Process sub-libraries if configured
        sub_libraries = config.get('include_sub_libraries', [])
        if sub_libraries:
            click.echo(f"  🔄 Processing {len(sub_libraries)} sub-libraries...")
            
            try:
                from ..platforms.solana_ebpf.generators.sublibrary_extractor import SubLibraryExtractor
                
                # Get rust version from toolchain mapping
                rust_version = resolved_toolchain.get('rust_version', '1.75.0')
                
                # Map configuration sub-library names to component names
                component_mapping = {
                    'rust_core_ebpf': 'core',
                    'rust_std_ebpf': 'std', 
                    'rust_alloc_ebpf': 'alloc'
                }
                
                # Convert sub-library names to component names
                components_to_extract = []
                for sub_lib in sub_libraries:
                    if sub_lib in component_mapping:
                        components_to_extract.append(component_mapping[sub_lib])
                    else:
                        logger.warning(f"Unknown sub-library: {sub_lib}")
                
                # Extract sub-libraries and generate SIGs with proper directory structure
                extractor = SubLibraryExtractor()
                
                # Check if SIG generation is enabled for this version
                generate_sig = current_version_config and current_version_config.get('generate', {}).get('sig', False)
                
                if generate_sig:
                    # Use the new comprehensive method
                    sub_results = extractor.extract_and_generate_sigs(
                        pat_path, rust_version, components_to_extract, install_to_ida=True
                    )
                    
                    sub_sig_count = 0
                    for component, result_dict in sub_results.items():
                        pat_path = result_dict.get('pat')
                        sig_path = result_dict.get('sig')
                        
                        if pat_path and pat_path.exists():
                            click.echo(f"    ✅ {component}: {pat_path}")
                            
                            if sig_path and sig_path.exists():
                                sub_sig_count += 1
                                click.echo(f"      ✅ SIG: {sig_path}")
                            else:
                                click.echo(f"      ⚠️  SIG generation failed for {component}")
                        else:
                            click.echo(f"    ❌ {component}: extraction failed")
                else:
                    # Only extract PAT files
                    sub_results = extractor.extract_sublibraries_from_pat(
                        pat_path, rust_version, components_to_extract
                    )
                    
                    sub_sig_count = 0
                    for component, sub_pat_path in sub_results.items():
                        if sub_pat_path and sub_pat_path.exists():
                            click.echo(f"    ✅ {component}: {sub_pat_path}")
                        else:
                            click.echo(f"    ❌ {component}: extraction failed")
                
                # Calculate success count based on result structure
                if generate_sig:
                    success_sub_count = sum(1 for result_dict in sub_results.values() 
                                          if result_dict.get('pat') is not None)
                else:
                    success_sub_count = sum(1 for path in sub_results.values() if path is not None)
                
                click.echo(f"    📊 Sub-libraries: {success_sub_count}/{len(sub_libraries)} PAT files generated")
                if sub_sig_count > 0:
                    click.echo(f"    📊 Sub-library SIGs: {sub_sig_count}/{success_sub_count} SIG files generated")
                    
            except Exception as sub_error:
                logger.warning(f"Sub-library processing failed: {sub_error}")
                click.echo(f"    ❌ Sub-library processing failed: {sub_error}")

        click.echo(f"    ✅ RLIB: {rlib_path}")
        click.echo(f"    ✅ PAT: {pat_path}")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to process Solana library {lib_name}: {e}")
        return False


def _process_x86_64_library(config: Dict, lib_name: str, lib_version: str) -> bool:
    """Process an x86_64 library configuration."""
    logger = get_logger(__name__)
    
    try:
        # For now, this is a placeholder for x86_64 processing
        # TODO: Implement x86_64 library processing based on config
        click.echo(f"  ⚠️  x86_64 platform processing not yet implemented")
        return False
        
    except Exception as e:
        logger.error(f"Failed to process x86_64 library {lib_name}: {e}")
        return False


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), required=True,
              help='Configuration file path')
@click.option('--library', '-l', required=True, help='Library name to compile')
@click.option('--version', '-v', help='Specific version to compile')
@click.option('--solana-version', help='Override Solana toolchain version')
@click.option('--rust-version', help='Override Rust toolchain version')
@click.option('--generate-rlib/--no-generate-rlib', default=True, help='Generate RLIB file')
@click.option('--generate-pat/--no-generate-pat', default=True, help='Generate PAT file')
@click.option('--generate-sig/--no-generate-sig', default=False, help='Generate SIG file')
@click.option('--generate-til/--no-generate-til', default=False, help='Generate TIL file')
@click.option('--cleanup/--no-cleanup', default=True, help='Clean up build artifacts')
def compile_single(config: str, library: str, version: Optional[str], 
                  solana_version: Optional[str], rust_version: Optional[str],
                  generate_rlib: bool, generate_pat: bool, generate_sig: bool, 
                  generate_til: bool, cleanup: bool):
    """Compile a single library from configuration.
    
    Examples:
        # Compile specific library version
        compile-single -c configs/batch_libraries.yaml -l solana_program_ebpf -v 1.18.16
        
        # Override toolchain version
        compile-single -c configs/batch_libraries.yaml -l solana_program_ebpf --solana-version 1.18.26
        
        # Generate only PAT file for testing
        compile-single -l solana_program_ebpf -v 1.18.16 --generate-pat --no-generate-sig --no-generate-til
    """
    logger = get_logger(__name__)
    
    try:
        # Load configuration
        config_loader = ConfigLoader(Path(config), "strict")
        config_data = config_loader.load_config()
        
        # Prepare toolchain overrides
        toolchain_overrides = {}
        if solana_version:
            toolchain_overrides['solana_version'] = solana_version
        if rust_version:
            toolchain_overrides['rust_version'] = rust_version
        
        # Determine version to use
        if not version:
            available_versions = config_loader.get_library_versions(library)
            if not available_versions:
                click.echo(f"❌ No versions found for library '{library}'")
                sys.exit(1)
            version = available_versions[0]
            click.echo(f"📌 Using version: {version}")
        
        # Resolve library configuration
        resolved_config = config_loader.resolve_library_configuration(
            library, version, toolchain_overrides
        )
        
        click.echo(f"🎯 Compiling single library: {library} v{version}")
        
        # Determine platform
        platform = resolved_config.get('platform', 'x86_64')
        click.echo(f"🏗️  Platform: {platform}")
        
        if platform == 'solana_ebpf':
            success = _compile_single_solana_library(
                resolved_config, library, version, 
                generate_rlib, generate_pat, generate_sig, generate_til, cleanup
            )
        else:
            click.echo("⚠️  x86_64 platform not yet supported in single compile mode")
            success = False
        
        if success:
            click.echo(f"✅ {library} v{version} compilation completed successfully")
        else:
            click.echo(f"❌ {library} v{version} compilation failed")
            sys.exit(1)
            
    except ConfigValidationError as e:
        click.echo(f"❌ Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Compilation failed: {e}")
        logger.error(f"Single compile failed: {e}")
        sys.exit(1)


def _compile_single_solana_library(config: Dict, lib_name: str, lib_version: str,
                                  generate_rlib: bool, generate_pat: bool, 
                                  generate_sig: bool, generate_til: bool, 
                                  cleanup: bool) -> bool:
    """Compile a single Solana library with specified generation options."""
    logger = get_logger(__name__)
    
    try:
        # Extract configuration
        resolved_toolchain = config.get('resolved_toolchain', {})
        solana_version = resolved_toolchain.get('solana_version', lib_version)
        
        click.echo(f"🔧 Using Solana toolchain: {solana_version}")
        
        # Initialize components
        toolchain_manager = SolanaToolchainManager()
        compiler = SolanaProgramCompiler(toolchain_manager)
        
        # Setup toolchain
        if not toolchain_manager.is_toolchain_installed(solana_version):
            click.echo(f"📥 Installing Solana toolchain {solana_version}...")
            toolchain_manager.install_toolchain(solana_version)
        
        rlib_path = None
        
        if generate_rlib:
            # Compile RLIB
            click.echo(f"🔨 Compiling RLIB...")
            crate_name = config.get('crate_name', lib_name.replace('_ebpf', ''))
            rlib_path = compiler.compile_downloaded_crate(crate_name, lib_version, solana_version, cleanup)
            click.echo(f"  ✅ RLIB: {rlib_path}")
        
        if generate_pat and rlib_path:
            # Generate PAT
            click.echo(f"📝 Generating PAT file...")
            pat_generator = SolanaPATGenerator()
            pat_path = pat_generator.generate_pat_from_rlib(rlib_path)
            click.echo(f"  ✅ PAT: {pat_path}")
            
            if generate_sig:
                # Generate SIG
                click.echo(f"🔏 Generating SIG file...")
                try:
                    from ..generators.flair_generator import FLAIRGenerator
                    flair_gen = FLAIRGenerator()
                    sig_output_path = pat_path.with_suffix('.sig')
                    
                    # Try multiple collision handling modes for better success rate
                    collision_modes = ['accept', 'force', 'strict']
                    sig_generated = False
                    
                    for mode in collision_modes:
                        try:
                            click.echo(f"  🔄 Trying collision mode: {mode}")
                            result = flair_gen.generate_sig_with_collision_handling(
                                pat_path, sig_output_path, library, mode=mode
                            )
                            
                            if result and result.get('success'):
                                stats = result.get('stats', {})
                                functions_included = stats.get('functions_included', 'unknown')
                                functions_skipped = stats.get('functions_skipped', 0)
                                collisions_detected = stats.get('collisions_detected', 0)
                                
                                click.echo(f"  ✅ SIG generated with {mode} mode")
                                click.echo(f"  📊 Functions: {functions_included} included, {functions_skipped} skipped, {collisions_detected} collisions")
                                click.echo(f"  ✅ SIG: {sig_output_path}")
                                sig_generated = True
                                break
                        except Exception as mode_error:
                            click.echo(f"  ⚠️  Mode {mode} failed: {mode_error}")
                            continue
                    
                    if not sig_generated:
                        logger.warning(f"SIG generation failed with all collision modes")
                        click.echo(f"  ❌ SIG generation failed with all modes")
                    
                except Exception as e:
                    click.echo(f"  ⚠️  SIG generation failed: {e}")
                    logger.warning(f"SIG generation failed: {e}")
        
        if generate_til and rlib_path:
            # TODO: Implement TIL generation for Solana eBPF
            click.echo(f"⚠️  TIL generation for Solana eBPF not yet implemented")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to compile single Solana library {lib_name}: {e}")
        return False


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), required=True,
              help='Configuration file path to validate')
@click.option('--validation-mode', type=click.Choice(['strict', 'lenient', 'auto']), 
              default='strict', help='Validation mode')
def validate_config(config: str, validation_mode: str):
    """Validate configuration file structure and references.
    
    Examples:
        validate-config -c configs/batch_libraries.yaml
        validate-config -c configs/batch_libraries.yaml --validation-mode lenient
    """
    logger = get_logger(__name__)
    
    try:
        click.echo(f"🔍 Validating configuration: {config}")
        click.echo(f"📋 Validation mode: {validation_mode}")
        
        # Load and validate configuration
        config_loader = ConfigLoader(Path(config), validation_mode)
        config_data = config_loader.load_config()
        
        # Display validation results
        click.echo(f"✅ Configuration is valid!")
        
        # Show summary
        libraries = config_data.get('libraries', {})
        batch_presets = config_data.get('batch_presets', {})
        
        click.echo(f"\n📊 Configuration Summary:")
        click.echo(f"   Libraries: {len(libraries)}")
        click.echo(f"   Batch presets: {len(batch_presets)}")
        
        # Show libraries
        if libraries:
            click.echo(f"\n📚 Available Libraries:")
            for lib_name, lib_config in libraries.items():
                lib_type = lib_config.get('library_type', 'unknown')
                platform = lib_config.get('platform', 'unknown')
                versions = config_loader.get_library_versions(lib_name)
                click.echo(f"   • {lib_name} ({lib_type}, {platform}) - {len(versions)} versions")
        
        # Show batch presets
        if batch_presets:
            click.echo(f"\n📦 Available Batch Presets:")
            for preset_name, preset_config in batch_presets.items():
                description = preset_config.get('description', 'No description')
                click.echo(f"   • {preset_name}: {description}")
        
    except ConfigValidationError as e:
        click.echo(f"❌ Configuration validation failed:")
        click.echo(f"   {e}")
        if e.suggestions:
            click.echo(f"   Suggestions: {', '.join(e.suggestions)}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Validation error: {e}")
        logger.error(f"Config validation failed: {e}")
        sys.exit(1)


@cli.command()
def info():
    """Show system and tool information."""
    click.echo("🔧 Rust x86_64 IDA Signatures Generator")
    click.echo("=" * 50)
    
    # System info
    click.echo("System Configuration:")
    click.echo(f"   Rust version: {settings.rust_version}")
    click.echo(f"   Target arch: {settings.target_arch}")
    click.echo(f"   Output dir: {settings.output_dir}")
    click.echo(f"   Workspace dir: {settings.workspace_dir}")
    click.echo(f"   Dependencies dir: {settings.dependencies_dir}")
    
    # Dependencies directory status
    if settings.dependencies_dir.exists():
        deps = list(settings.dependencies_dir.glob("*-*"))
        click.echo(f"   Downloaded deps: {len(deps)}")
    else:
        click.echo("   Downloaded deps: 0 (directory not found)")
    
    # FLAIR tools info
    try:
        generator = FLAIRGenerator()
        tool_info = generator.get_tool_info()
        
        click.echo("\nFLAIR Tools:")
        click.echo(f"   Directory: {tool_info['flair_dir']}")
        click.echo(f"   pelf: {tool_info.get('pelf_version', 'Unknown')}")
        click.echo(f"   sigmake: {tool_info.get('sigmake_version', 'Unknown')}")
        
    except Exception as e:
        click.echo(f"\n❌ FLAIR tools not available: {e}")
    
    # Rust toolchain info
    try:
        import subprocess
        result = subprocess.run(['rustc', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            click.echo(f"\nRust Toolchain:")
            click.echo(f"   {result.stdout.strip()}")
        
        result = subprocess.run(['rustup', 'target', 'list', '--installed'], capture_output=True, text=True)
        if result.returncode == 0:
            targets = result.stdout.strip().split('\n')
            click.echo(f"   Installed targets: {len(targets)}")
            if settings.target_arch in targets:
                click.echo(f"   ✅ Target {settings.target_arch} is available")
            else:
                click.echo(f"   ❌ Target {settings.target_arch} is NOT installed") 
                
    except Exception as e:
        click.echo(f"\n❌ Failed to get Rust info: {e}")


@cli.command()
@click.argument('rlib_path_or_name', type=str)
@click.option('--lib-name', '-n', help='Library name for .til file (auto-detected if not provided)')
@click.option('--version', '-v', help='Library version for tagging (auto-detected if not provided)')
@click.option('--target', default='x86_64-unknown-linux-gnu', help='Target architecture')
@click.option('--output-dir', '-o', type=click.Path(), help='Output directory for headers')
@click.option('--check-only', is_flag=True, help='Only check debug info, do not generate')
@click.option('--recompile-method', type=click.Choice(['env_vars', 'config_file', 'cli_system']), 
              help='Recompile RLIB with debug info using specified method: '
                   'env_vars (use environment variables, for local projects), '
                   'config_file (modify .cargo/config.toml, requires source access), '
                   'cli_system (use CLI dependency system, for third-party crates)')
@click.pass_context
def generate_til(ctx, rlib_path_or_name: str, lib_name: Optional[str], version: Optional[str], 
                target: str, output_dir: Optional[str], check_only: bool,
                recompile_method: Optional[str]):
    """Generate IDA Pro .til type library from RLIB file with manual recompilation option.

    This command generates .til files from RLIB files. If the RLIB lacks sufficient
    debug information, you can manually specify a recompilation method.

    Basic Usage:
        generate-til libcore.rlib --lib-name core --version 1.84.1

    Manual Recompilation Methods:
        
        env_vars - Use environment variables (best for local projects):
            generate-til libcore.rlib --lib-name core --recompile-method env_vars
            • Suitable for: Local Rust projects you can rebuild
            • Requires: Access to project source code and Cargo.toml
            • Method: Sets CARGO_PROFILE_*_DEBUG=true and RUSTFLAGS
        
        config_file - Modify .cargo/config.toml (persistent settings):
            generate-til libcore.rlib --lib-name core --recompile-method config_file  
            • Suitable for: Local projects needing persistent debug config
            • Requires: Write access to project .cargo/ directory
            • Method: Creates/modifies .cargo/config.toml with debug settings
        
        cli_system - Use CLI dependency system (for third-party crates):
            generate-til libcore.rlib --lib-name core --recompile-method cli_system
            • Suitable for: Third-party crates from crates.io
            • Requires: Internet access to download crate source
            • Method: Creates temporary project and builds with debug info

    Other Options:
        
        Check debug info only (no .til generation):
            generate-til libstd.rlib --lib-name std --check-only
    """
    from ..extractors.debug_info_checker import RlibDebugInfoChecker
    from ..extractors.rust_type_extractor import RustTypeExtractor
    from ..generators.til_generator import TilGenerator
    from ..core.smart_rlib_finder import SmartRlibFinder
    from ..builders.smart_recompiler import SmartRecompiler
    
    logger = get_logger(__name__)
    
    # Step 1: Smart RLIB discovery
    rlib_finder = SmartRlibFinder()
    
    # Try to find RLIB file intelligently
    search_result = rlib_finder.find_rlib(rlib_path_or_name, version, target)
    if not search_result:
        # If using cli_system method, we can work without existing RLIB
        if recompile_method == 'cli_system':
            click.echo(f"🔄 使用CLI系统方法从crates.io下载: {rlib_path_or_name}")
            # Create a fake search result to proceed with cli_system recompilation
            from pathlib import Path
            from ..core.smart_rlib_finder import RlibSearchResult
            search_result = RlibSearchResult(
                rlib_path=Path("/tmp/dummy.rlib"),  # Will be replaced during recompilation
                crate_name=rlib_path_or_name,
                version=version,
                project_path=Path("/tmp"),
                is_workspace=False,
                confidence=1.0
            )
        else:
            click.echo(f"❌ 无法找到RLIB文件: {rlib_path_or_name}")
            click.echo(f"💡 建议:")
            click.echo(f"   • 确认文件路径是否正确")
            click.echo(f"   • 对于crate名称，确认在data/dependencies/目录中存在相应项目")
            click.echo(f"   • 运行 'ls data/dependencies/' 查看可用的项目")
            click.echo(f"   • 或使用 '--recompile-method cli_system' 从crates.io重新下载")
            return
    
    # Use discovered information
    rlib_file = search_result.rlib_path
    detected_lib_name = lib_name or search_result.crate_name
    detected_version = version or search_result.version
    
    click.echo(f"🔍 Analyzing RLIB file: {rlib_file.name}")
    if search_result.confidence < 1.0:
        click.echo(f"🔍 Auto-discovered from: {rlib_path_or_name} (confidence: {search_result.confidence:.1%})")
    click.echo(f"📋 Library: {detected_lib_name} {detected_version or '(no version)'}")
    click.echo(f"🎯 Target: {target}")
    
    # Update variables for rest of function
    lib_name = detected_lib_name
    version = detected_version
    
    # 显示重编译方法（如果用户指定了）
    if recompile_method:
        method_descriptions = {
            'env_vars': '环境变量方法 - 适用于本地项目，通过环境变量临时启用调试信息',
            'config_file': '配置文件方法 - 适用于本地项目，修改.cargo/config.toml实现持久化配置', 
            'cli_system': 'CLI系统方法 - 适用于第三方crate，自动下载源码并编译'
        }
        click.echo(f"🔧 重编译方法: {recompile_method}")
        click.echo(f"   说明: {method_descriptions.get(recompile_method, '未知方法')}")
    
    try:
        # Step 1: Check RLIB debug information (skip if using cli_system with fake path)
        debug_checker = RlibDebugInfoChecker()
        if recompile_method == 'cli_system' and str(rlib_file) == "/tmp/dummy.rlib":
            # Create a minimal debug report to trigger recompilation
            from ..extractors.debug_info_checker import DebugInfoReport, RlibSourceInfo
            debug_report = DebugInfoReport()
            debug_report.quality_score = 0  # Force recompilation
            debug_report.has_dwarf = False
            debug_report.has_symbols = False
            debug_report.type_count = 0
            debug_report.struct_count = 0
            debug_report.source_info = RlibSourceInfo()
            debug_report.source_info.crate_name = detected_lib_name
            debug_report.source_info.version = detected_version
            debug_report.issues = ["Using cli_system method - direct from crates.io"]
        else:
            debug_report = debug_checker.check_rlib_debug_info(rlib_file)
        
        # Display debug info analysis
        click.echo(f"\n📊 调试信息质量评估:")
        click.echo(f"   评分: {debug_report.quality_score}/100")
        click.echo(f"   DWARF信息: {'✅' if debug_report.has_dwarf else '❌'}")
        click.echo(f"   符号表: {'✅' if debug_report.has_symbols else '❌'}")
        click.echo(f"   类型数量: {debug_report.type_count}")
        click.echo(f"   结构体数量: {debug_report.struct_count}")
        
        # Show issues if any
        if debug_report.issues:
            click.echo(f"\n⚠️ 发现问题:")
            for issue in debug_report.issues:
                click.echo(f"   • {issue}")
        
        # If debug info is insufficient, provide guidance
        if debug_report.quality_score < 60:
            click.echo(f"\n{debug_checker.generate_detailed_report(debug_report, rlib_file)}")
            
            if check_only:
                sys.exit(1)
            elif debug_report.quality_score < 40 and not recompile_method:
                click.echo("❌ 调试信息质量过低，无法生成.til文件")
                click.echo("💡 建议使用 --recompile-method 选项重新编译以获得调试信息")
                sys.exit(1)
        
        # 处理重编译（如果用户指定了）
        if recompile_method:
            click.echo(f"\n🔧 执行重编译...")
            
            # 检查是否有必要的源信息进行重编译
            if not debug_report.source_info:
                click.echo("❌ 无法执行重编译：缺少源信息")
                click.echo("💡 说明：重编译功能需要将来实现源检测支持")
                sys.exit(1)
            
            recompiler = SmartRecompiler()
            result = recompiler.recompile_rlib(rlib_file, debug_report, method=recompile_method)
            
            if result.success:
                click.echo(f"✅ 重编译成功: {result.new_rlib_path}")
                click.echo(f"   方法: {result.method_used}")
                click.echo(f"   耗时: {result.build_time_seconds:.1f}秒")
                # 使用新的RLIB文件继续生成.til
                rlib_file = result.new_rlib_path
            else:
                click.echo(f"❌ 重编译失败:")
                for error in result.error_messages:
                    click.echo(f"   • {error}")
                
                # 提供其他方法建议
                other_methods = [m for m in ['env_vars', 'config_file', 'cli_system'] if m != recompile_method]
                if other_methods:
                    click.echo(f"\n💡 可尝试其他重编译方法:")
                    for method in other_methods:
                        click.echo(f"   --recompile-method {method}")
                
                sys.exit(1)
        
        # If check-only mode, stop here
        if check_only:
            click.echo("✅ 调试信息检查完成")
            return
        
        # Step 2: Extract type information
        click.echo(f"\n🔧 提取类型信息...")
        type_extractor = RustTypeExtractor()
        extracted_types = type_extractor.extract_types_from_rlib(rlib_file)
        
        if not extracted_types:
            click.echo("❌ 未能提取到类型信息")
            sys.exit(1)
        
        click.echo(f"✅ 提取了 {len(extracted_types)} 个类型定义")
        
        # Step 3: Generate header files
        click.echo(f"\n📝 生成C++头文件...")
        version_str = version or "unknown"
        c_content, cpp_content = type_extractor.generate_header_content(
            lib_name, version_str, target
        )
        
        # Determine output directory
        if output_dir:
            headers_dir = Path(output_dir)
        else:
            headers_dir = settings.output_dir / "headers"
        
        # Create library-specific directory
        lib_dir = headers_dir / f"{lib_name}_{version_str.replace('.', '_')}" if version else headers_dir / lib_name
        lib_dir.mkdir(parents=True, exist_ok=True)
        
        # Write header files
        c_header_path = lib_dir / "types.h"
        cpp_header_path = lib_dir / "types.hpp"
        
        c_header_path.write_text(c_content, encoding='utf-8')
        cpp_header_path.write_text(cpp_content, encoding='utf-8')
        
        click.echo(f"✅ 生成头文件:")
        click.echo(f"   C版本: {c_header_path}")
        click.echo(f"   C++版本: {cpp_header_path}")
        
        # Step 4: Generate .til file using IDAClang
        click.echo(f"\n🚀 使用IDAClang生成.til文件...")
        til_generator = TilGenerator()
        
        til_result = til_generator.generate_til_to_ida_location(
            header_file=cpp_header_path,
            lib_name=lib_name,
            lib_version=version_str,
            target=target
        )
        
        # Display results
        click.echo(f"✅ .til文件生成成功!")
        click.echo(f"   文件: {til_result['til_file']}")
        click.echo(f"   描述: {til_result['description']}")
        
        if til_result['analysis']:
            analysis = til_result['analysis']
            click.echo(f"   📊 符号数: {analysis['symbols']}")
            click.echo(f"   结构体数: {analysis['structs']}")
            click.echo(f"   文件大小: {analysis['size_human']}")
        
        # Show warnings if any
        if til_result.get('warnings'):
            click.echo(f"\n⚠️ IDAClang警告:")
            click.echo(f"   {til_result['warnings']}")
        
        # Usage instructions
        click.echo(f"\n💡 使用方法:")
        click.echo(f"   在IDA Pro中: File → Load file → Type libraries...")
        click.echo(f"   或IDA会自动发现til/rust/目录中的类型库")
        click.echo(f"   分析Linux x64 Rust程序时，使用'{lib_name}'类型")
        
    except Exception as e:
        logger.exception("TIL generation failed")
        click.echo(f"❌ .til文件生成失败: {e}")
        sys.exit(1)


@cli.command()
@click.option('--hours', default=24, help='Remove files older than this many hours')
def cleanup(hours: int):
    """Clean up temporary files and old build artifacts."""
    from ..extractors.rlib_extractor import ObjectFileManager
    
    click.echo(f"🧹 Cleaning up files older than {hours} hours...")
    
    try:
        # Clean up extracted objects
        obj_manager = ObjectFileManager()
        removed_objects = obj_manager.cleanup_extracted_objects(hours)
        
        click.echo(f"✅ Cleanup completed:")
        click.echo(f"   Removed {removed_objects} old object files")
        
    except Exception as e:
        click.echo(f"❌ Cleanup failed: {e}")
        sys.exit(1)


# ============================================================================
# Solana eBPF Commands
# ============================================================================

@cli.group()
def solana():
    """Solana eBPF signature generation commands."""
    pass


@solana.command()
@click.option('--version', default='1.18.16', help='Solana toolchain version')
@click.option('--force', is_flag=True, help='Force reinstallation if already exists')
def setup_toolchain(version: str, force: bool):
    """Setup Solana toolchain for eBPF compilation.
    
    Downloads and installs the specified Solana toolchain version
    with cargo-build-sbf tool for eBPF compilation.
    
    Example:
        solana setup-toolchain --version 1.18.16
        solana setup-toolchain --version 1.18.16 --force
    """
    logger = get_logger(__name__)
    click.echo(f"🔧 Setting up Solana {version} toolchain...")
    
    try:
        toolchain_manager = SolanaToolchainManager()
        
        if not force and toolchain_manager.is_toolchain_installed(version):
            click.echo(f"✅ Solana {version} is already installed")
            toolchain_dir = toolchain_manager.get_toolchain_dir(version)
            click.echo(f"   Location: {toolchain_dir}")
            return
        
        # Install toolchain
        toolchain_dir = toolchain_manager.install_toolchain(version, force=force)
        
        # Verify installation
        verification = toolchain_manager.verify_installation(version)
        
        click.echo(f"✅ Solana {version} toolchain installed successfully!")
        click.echo(f"   Location: {toolchain_dir}")
        click.echo(f"   cargo-build-sbf: {'✅' if verification['cargo_build_sbf_executable'] else '❌'}")
        click.echo(f"   solana CLI: {'✅' if verification['solana_cli_exists'] else '❌'}")
        
    except Exception as e:
        logger.exception("Toolchain setup failed")
        raise click.ClickException(f"Failed to setup toolchain: {e}")


@solana.command()
@click.option('--crate-version', default='1.18.16', help='solana-program crate version')
@click.option('--solana-version', default='1.18.16', help='Solana toolchain version')
@click.option('--cleanup/--no-cleanup', default=True, help='Clean up build artifacts')
def compile_solana_program(crate_version: str, solana_version: str, cleanup: bool):
    """Compile solana-program crate to eBPF rlib.
    
    Creates a test project with solana-program dependency and compiles
    it to eBPF using cargo-build-sbf.
    
    Example:
        solana compile-solana-program --crate-version 1.18.16
        solana compile-solana-program --crate-version 1.18.16 --solana-version 1.18.16
    """
    logger = get_logger(__name__)
    click.echo(f"🏗️ Compiling solana-program {crate_version} with Solana {solana_version}...")
    
    try:
        # Ensure toolchain is available
        toolchain_manager = SolanaToolchainManager()
        if not toolchain_manager.is_toolchain_installed(solana_version):
            click.echo(f"⏳ Solana {solana_version} not found, installing...")
            toolchain_manager.install_toolchain(solana_version)
        
        # Compile crate
        compiler = SolanaProgramCompiler(toolchain_manager)
        rlib_path = compiler.compile_solana_program(
            version=crate_version,
            solana_version=solana_version,
            cleanup=cleanup
        )
        
        # Show results
        rlib_info = compiler.get_rlib_info(rlib_path)
        
        click.echo(f"✅ Compilation successful!")
        click.echo(f"   Output: {rlib_path}")
        click.echo(f"   Size: {rlib_info['size']} bytes")
        
        # Show rlib collection summary
        collector = RlibCollector()
        summary = collector.get_rlib_summary()
        click.echo(f"\n📊 Rlib Collection Summary:")
        click.echo(f"   Total crates: {summary['total_crates']}")
        click.echo(f"   Total rlibs: {summary['total_rlibs']}")
        click.echo(f"   Total size: {summary['total_size_mb']} MB")
        
    except Exception as e:
        logger.exception("Compilation failed")
        raise click.ClickException(f"Failed to compile: {e}")


@solana.command()
@click.argument('rlib_path', type=click.Path(exists=True))
@click.option('--output-dir', default=None, help='Output directory for PAT file')
def generate_pat(rlib_path: str, output_dir: Optional[str]):
    """Generate PAT file from Solana eBPF rlib.
    
    Analyzes the rlib file and generates a FLAIR PAT file
    using ported algorithms from solana-ida-signatures-factory.
    
    Example:
        solana generate-pat data/solana_ebpf/rlibs/solana-program/libsolana_program-1.18.16.rlib
        solana generate-pat path/to/lib.rlib --output-dir ./signatures
    """
    logger = get_logger(__name__)
    rlib_file = Path(rlib_path)
    
    click.echo(f"🎯 Generating PAT file from: {rlib_file.name}")
    
    try:
        generator = SolanaPATGenerator()
        
        # Generate PAT file
        output_path = None
        if output_dir:
            output_path = Path(output_dir) / f"{rlib_file.stem}.pat"
        
        pat_path = generator.generate_pat_from_rlib(rlib_file, output_path)
        
        # Validate and show statistics
        validation = generator.validate_pat_file(pat_path)
        stats = generator.get_pat_statistics(pat_path)
        
        click.echo(f"✅ PAT file generated: {pat_path}")
        click.echo(f"   Functions: {stats['total_functions']}")
        click.echo(f"   Functions with internals: {stats['functions_with_internals']}")
        click.echo(f"   Internal references: {stats['total_internal_refs']}")
        click.echo(f"   Average pattern length: {stats['avg_pattern_length']:.1f}")
        click.echo(f"   File size: {validation['file_size']:,} bytes")
        
        if not validation['valid']:
            click.echo(f"⚠️ Validation issues found")
        
    except Exception as e:
        logger.exception("PAT generation failed")
        raise click.ClickException(f"Failed to generate PAT: {e}")


@solana.command()
@click.argument('pat_file', type=click.Path(exists=True))
@click.option('--name', '-n', help='Signature name (default: from filename)')
@click.option('--collision-mode', type=click.Choice(['strict', 'accept', 'force', 'manual']), 
              default='strict', help='Collision handling mode: '
              'strict (fail on collision), accept (generate partial signatures), '
              'force (use sigmake -c to override), manual (generate EXC files)')
def generate_sig(pat_file: str, name: Optional[str], collision_mode: str):
    """Generate SIG file from PAT using sigmake.
    
    Uses the IDA FLAIR sigmake tool to convert PAT files
    to binary SIG format for use in IDA Pro.
    
    Collision handling modes:
    - strict: Fail on any collision (current behavior)
    - accept: Generate partial signatures, skip collisions 
    - force: Use sigmake -c to force generation with collisions
    - manual: Generate EXC files for manual collision resolution
    
    Example:
        solana generate-sig sigs/solana_program_1.18.16.ebpf.pat
        solana generate-sig sigs/anchor_lang_0.30.0.ebpf.pat --name "Anchor Lang v0.30"
        solana generate-sig sigs/solana_program_1.18.16.ebpf.pat --collision-mode accept
    """
    logger = get_logger(__name__)
    pat_path = Path(pat_file)
    
    if not name:
        name = pat_path.stem.replace('_', ' ').title()
    
    click.echo(f"📝 Generating SIG file from: {pat_path.name}")
    click.echo(f"   Signature name: {name}")
    click.echo(f"   Collision mode: {collision_mode}")
    
    try:
        from ..generators.flair_generator import FLAIRGenerator
        
        # Use existing FLAIR generator
        flair_gen = FLAIRGenerator()
        
        # Generate SIG file (handle .ebpf.pat -> .ebpf.sig)
        if pat_path.name.endswith('.ebpf.pat'):
            # Replace .ebpf.pat with .ebpf.sig
            sig_path = pat_path.with_name(pat_path.name.replace('.ebpf.pat', '.ebpf.sig'))
        else:
            sig_path = pat_path.with_suffix('.sig')
        
        # Handle collision modes
        if collision_mode == 'accept':
            # Accept mode: generate partial signatures, skip collisions
            sig_result = flair_gen.generate_sig_with_collision_handling(
                pat_path, sig_path, name, mode='accept'
            )
        elif collision_mode == 'force':
            # Force mode: use sigmake -c to override collisions
            sig_result = flair_gen.generate_sig_with_collision_handling(
                pat_path, sig_path, name, mode='force'
            )
        elif collision_mode == 'manual':
            # Manual mode: generate EXC files for user editing
            sig_result = flair_gen.generate_sig_with_collision_handling(
                pat_path, sig_path, name, mode='manual'
            )
        else:
            # Strict mode: fail on collision (original behavior)
            sig_result = flair_gen.generate_sig(pat_path, sig_path, name)
        
        success = sig_result is not None
        
        if success and sig_path.exists():
            click.echo(f"✅ SIG file generated: {sig_path}")
            click.echo(f"   Size: {sig_path.stat().st_size:,} bytes")
            
            # Show collision handling results
            if collision_mode != 'strict' and sig_result and 'stats' in sig_result:
                stats = sig_result['stats']
                if 'collisions_detected' in stats:
                    click.echo(f"   Collisions detected: {stats['collisions_detected']}")
                if 'functions_included' in stats:
                    click.echo(f"   Functions included: {stats['functions_included']}")
                if 'functions_skipped' in stats:
                    click.echo(f"   Functions skipped: {stats['functions_skipped']}")
            
            # Installation suggestion
            click.echo(f"\n💡 Installation:")
            click.echo(f"   Copy to IDA sig directory: sig/solana_ebpf/")
            click.echo(f"   Or load manually: File → Load file → FLIRT signature file")
            
            # Show manual mode specific instructions
            if collision_mode == 'manual' and sig_result and 'exc_files' in sig_result:
                click.echo(f"\n📝 Manual collision resolution:")
                for exc_file in sig_result['exc_files']:
                    click.echo(f"   Edit: {exc_file}")
                click.echo(f"   Then run: solana generate-sig {pat_file} --collision-mode force")
        else:
            if collision_mode == 'strict':
                raise Exception("SIG file generation failed")
            else:
                raise Exception(f"SIG file generation failed in {collision_mode} mode")
        
    except Exception as e:
        logger.exception("SIG generation failed")
        raise click.ClickException(f"Failed to generate SIG: {e}")


@solana.command()
@click.option('--input-folder', '-i', type=click.Path(exists=True), required=True,
              help='Folder containing PAT files')
@click.option('--lib-name', '-l', required=True, help='Library name to merge')
@click.option('--output-file', '-o', type=click.Path(), help='Output merged PAT file')
@click.option('--drop-duplicates/--keep-duplicates', default=True,
              help='Remove duplicate function patterns')
def merge_versions(input_folder: str, lib_name: str, output_file: Optional[str], 
                   drop_duplicates: bool):
    """Merge PAT files from different versions of a library.
    
    Combines PAT files from multiple versions of the same library,
    adds version tags to function names, and optionally removes duplicates.
    
    Example:
        solana merge-versions -i sigs/solana-program/ -l solana_program
        solana merge-versions -i sigs/anchor/ -l anchor_lang -o merged_anchor.ebpf.pat
    """
    logger = get_logger(__name__)
    input_dir = Path(input_folder)
    
    click.echo(f"🔗 Merging PAT files for: {lib_name}")
    click.echo(f"   Input directory: {input_dir}")
    click.echo(f"   Deduplication: {'✅' if drop_duplicates else '❌'}")
    
    try:
        merger = SolanaVersionMerger()
        
        # Find PAT files
        pat_files = merger.find_pat_files(input_dir, lib_name)
        if not pat_files:
            raise Exception(f"No PAT files found for {lib_name}")
        
        click.echo(f"   Found versions: {', '.join(v for v, _ in pat_files)}")
        
        # Determine output file
        if not output_file:
            output_file = input_dir.parent / "merged" / f"{lib_name}_merged.pat"
        else:
            output_file = Path(output_file)
        
        # Merge files
        success = merger.merge_pat_files(input_dir, lib_name, output_file, drop_duplicates)
        
        if success:
            # Show statistics
            stats = merger.get_merge_statistics(output_file)
            
            click.echo(f"✅ Merge completed: {output_file}")
            click.echo(f"   Total functions: {stats['total_functions']}")
            click.echo(f"   Versions merged: {stats['versions_found']}")
            click.echo(f"   File size: {stats['file_size']:,} bytes")
            
            if stats.get('version_distribution'):
                click.echo(f"\n📊 Version distribution:")
                for version, count in stats['version_distribution'].items():
                    click.echo(f"   {version}: {count} functions")
        else:
            raise Exception("Merge operation failed")
        
    except Exception as e:
        logger.exception("Version merge failed")
        raise click.ClickException(f"Failed to merge versions: {e}")


@solana.command()
def list_toolchains():
    """List installed Solana toolchains."""
    try:
        toolchain_manager = SolanaToolchainManager()
        versions = toolchain_manager.get_installed_versions()
        
        if versions:
            click.echo("📦 Installed Solana toolchains:")
            for version in versions:
                verification = toolchain_manager.verify_installation(version)
                status = "✅" if verification['cargo_build_sbf_executable'] else "❌"
                click.echo(f"   {status} {version}")
        else:
            click.echo("❌ No Solana toolchains installed")
            click.echo("💡 Run 'solana setup-toolchain' to install")
        
    except Exception as e:
        raise click.ClickException(f"Failed to list toolchains: {e}")


@solana.command()
def list_rlibs():
    """List compiled Solana rlib files."""
    try:
        collector = RlibCollector()
        rlibs_by_crate = collector.organize_rlibs_by_crate()
        
        if rlibs_by_crate:
            click.echo("📁 Compiled Solana rlib files:")
            for crate_name, rlibs in rlibs_by_crate.items():
                click.echo(f"\n📦 {crate_name}:")
                for rlib_path in rlibs:
                    metadata = collector.get_rlib_metadata(rlib_path)
                    size_mb = int(metadata['size']) / (1024 * 1024)
                    click.echo(f"   • {rlib_path.name} ({size_mb:.1f} MB)")
            
            # Show summary
            summary = collector.get_rlib_summary()
            click.echo(f"\n📊 Summary:")
            click.echo(f"   Total crates: {summary['total_crates']}")
            click.echo(f"   Total rlibs: {summary['total_rlibs']}")
            click.echo(f"   Total size: {summary['total_size_mb']} MB")
        else:
            click.echo("❌ No rlib files found") 
            click.echo("💡 Run 'solana compile-solana-program' to compile")
        
    except Exception as e:
        raise click.ClickException(f"Failed to list rlibs: {e}")


@solana.command("generate-til")
@click.option('--version', required=True, help='Solana program version (e.g., 1.18.16)')
@click.option('--solana-version', default='1.18.16', help='Solana toolchain version')
@click.option('--crate-name', default='solana-program', help='Crate name to generate TIL for')
@click.option('--force-recompile', is_flag=True, help='Force recompilation even if debug RLIB exists')
def solana_generate_til(version: str, solana_version: str, crate_name: str, force_recompile: bool):
    """Generate TIL file for Solana eBPF crate with debug information.
    
    This command compiles the specified Solana crate with debug symbols and generates
    an IDA Pro TIL (Type Information Library) file for enhanced reverse engineering.
    
    Examples:
        solana generate-til --version 1.18.16
        solana generate-til --version 1.18.26 --solana-version 1.18.26
        solana generate-til --version 1.18.16 --crate-name solana-program --force-recompile
    """
    logger = get_logger(__name__)
    click.echo(f"🔧 Generating TIL file for {crate_name} {version} (Solana {solana_version})")
    
    try:
        from ..platforms.solana_ebpf.generators.solana_til_generator import SolanaEbpfTilGenerator
        
        til_generator = SolanaEbpfTilGenerator()
        
        # Generate TIL file
        result = til_generator.generate_til_from_crate(
            crate_name=crate_name,
            version=version,
            solana_version=solana_version,
            force_recompile=force_recompile
        )
        
        # Display results
        click.echo(f"\n✅ TIL generation completed successfully!")
        click.echo(f"   📊 Debug quality score: {result['debug_score']}/100")
        click.echo(f"   📁 Debug RLIB: {result['debug_rlib']}")
        click.echo(f"   📄 Header file: {result['header_file']}")
        click.echo(f"   🎯 TIL file: {result['til_file']}")
        
        if result.get('analysis'):
            analysis = result['analysis']
            click.echo(f"   📈 TIL analysis: {analysis.get('symbols', 0)} symbols, "
                      f"{analysis.get('size_human', 'unknown')} size")
        
        click.echo(f"\n💡 The TIL file is ready for use in IDA Pro!")
        click.echo(f"   Location: {result['til_file']}")
        
    except Exception as e:
        logger.exception("TIL generation failed")
        raise click.ClickException(f"TIL generation failed: {e}")


@solana.command("batch-generate-til")
@click.option('-c', '--config', type=click.Path(exists=True), help='Batch configuration file')
@click.option('-p', '--preset', help='Preset name from configuration file')
@click.option('--solana-version', help='Override Solana toolchain version')
def solana_batch_generate_til(config: Optional[str], preset: Optional[str], solana_version: Optional[str]):
    """Batch generate TIL files for multiple Solana crates.
    
    Uses batch configuration system to generate TIL files for multiple crates
    with their respective versions and toolchain configurations.
    
    Examples:
        solana batch-generate-til -c configs/batch_libraries.yaml -p solana_1_18_16_complete
        solana batch-generate-til -c configs/batch_libraries.yaml --solana-version 1.18.26
    """
    logger = get_logger(__name__)
    
    if not config:
        raise click.ClickException("Configuration file is required for batch TIL generation")
    
    try:
        from ..platforms.solana_ebpf.generators.solana_til_generator import SolanaEbpfTilGenerator
        
        # Load configuration
        with open(config) as f:
            config_data = yaml.safe_load(f)
        
        # Extract batch preset if specified
        if preset:
            if 'batch_presets' not in config_data or preset not in config_data['batch_presets']:
                raise click.ClickException(f"Preset '{preset}' not found in configuration")
            
            preset_config = config_data['batch_presets'][preset]
            libraries = preset_config.get('libraries', [])
        else:
            # Use all libraries from configuration
            libraries = config_data.get('libraries', {})
        
        click.echo(f"🔧 Batch generating TIL files...")
        if preset:
            click.echo(f"   📋 Using preset: {preset}")
        click.echo(f"   📁 Config: {config}")
        
        til_generator = SolanaEbpfTilGenerator()
        
        # Prepare crates configuration for batch processing
        crates_config = {}
        
        if preset:
            # Process preset format
            for lib_config in libraries:
                lib_name = lib_config.get('library', '').replace('_ebpf', '')
                versions = lib_config.get('versions', [])
                
                for version in versions:
                    crate_name = lib_name.replace('_', '-')  # Convert to crate naming
                    crates_config[f"{crate_name}_{version}"] = {
                        'version': version,
                        'force_recompile': lib_config.get('force_recompile', False)
                    }
        else:
            # Process direct libraries format
            for lib_name, lib_config in libraries.items():
                if isinstance(lib_config, dict) and 'versions' in lib_config:
                    crate_name = lib_config.get('crate_name', lib_name.replace('_', '-'))
                    for version_config in lib_config['versions']:
                        version = version_config['version']
                        # Only generate TIL for versions that have til: true
                        if version_config.get('generate', {}).get('til', False):
                            crates_config[f"{crate_name}_{version}"] = {
                                'version': version,
                                'force_recompile': False
                            }
        
        if not crates_config:
            click.echo("⚠️ No crates configured for TIL generation")
            return
        
        # Override Solana version if specified
        solana_version_to_use = solana_version or config_data.get('default_toolchains', {}).get('solana_ebpf', {}).get('solana_version', '1.18.16')
        
        # Batch generate
        results = til_generator.batch_generate_til_files(crates_config, solana_version_to_use)
        
        # Display summary
        success_count = sum(1 for r in results.values() if r['success'])
        total_count = len(results)
        
        click.echo(f"\n📊 Batch TIL generation completed!")
        click.echo(f"   ✅ Successful: {success_count}/{total_count}")
        click.echo(f"   ❌ Failed: {total_count - success_count}")
        
        if success_count > 0:
            click.echo(f"\n✅ Successfully generated TIL files:")
            for crate_name, result in results.items():
                if result['success']:
                    til_path = result['result']['til_file']
                    debug_score = result['result']['debug_score']
                    click.echo(f"   • {crate_name}: {til_path} (debug: {debug_score}/100)")
        
        if total_count - success_count > 0:
            click.echo(f"\n❌ Failed TIL generations:")
            for crate_name, result in results.items():
                if not result['success']:
                    click.echo(f"   • {crate_name}: {result['error']}")
        
    except Exception as e:
        logger.exception("Batch TIL generation failed")
        raise click.ClickException(f"Batch TIL generation failed: {e}")


@solana.command()
@click.option('--version', default='1.18.16', help='solana-program version to test')
def test_workflow(version: str):
    """Test the complete Solana eBPF signature generation workflow.
    
    Performs a complete test of the workflow:
    1. Setup toolchain
    2. Compile solana-program 
    3. Generate PAT file
    4. Generate SIG file
    
    Example:
        solana test-workflow --version 1.18.16
    """
    logger = get_logger(__name__)
    click.echo(f"🧪 Testing complete Solana eBPF workflow with version {version}")
    
    try:
        # Step 1: Setup toolchain
        click.echo(f"\n1️⃣ Setting up toolchain...")
        toolchain_manager = SolanaToolchainManager()
        if not toolchain_manager.is_toolchain_installed(version):
            toolchain_manager.install_toolchain(version)
        click.echo(f"   ✅ Solana {version} ready")
        
        # Step 2: Compile solana-program
        click.echo(f"\n2️⃣ Compiling solana-program...")
        compiler = SolanaProgramCompiler(toolchain_manager)
        rlib_path = compiler.compile_solana_program(version, version, cleanup=True)
        click.echo(f"   ✅ Compiled: {rlib_path}")
        
        # Step 3: Generate PAT
        click.echo(f"\n3️⃣ Generating PAT file...")
        generator = SolanaPATGenerator()
        pat_path = generator.generate_pat_from_rlib(rlib_path)
        stats = generator.get_pat_statistics(pat_path)
        click.echo(f"   ✅ Generated: {pat_path} ({stats['total_functions']} functions)")
        
        # Step 4: Generate SIG (if FLAIR tools available)
        click.echo(f"\n4️⃣ Generating SIG file...")
        try:
            from ..generators.flair_generator import FLAIRGenerator
            flair_gen = FLAIRGenerator()
            # Handle .ebpf.pat -> .ebpf.sig
            if pat_path.name.endswith('.ebpf.pat'):
                # Replace .ebpf.pat with .ebpf.sig
                sig_path = pat_path.with_name(pat_path.name.replace('.ebpf.pat', '.ebpf.sig'))
            else:
                sig_path = pat_path.with_suffix('.sig')
            sig_result = flair_gen.generate_sig_with_collision_handling(
                pat_path, sig_path, f"Solana Program {version}", mode='accept'
            )
            success = sig_result is not None
            
            if success and sig_path.exists():
                click.echo(f"   ✅ Generated: {sig_path}")
            else:
                click.echo(f"   ❌ SIG generation failed")
        except Exception as e:
            click.echo(f"   ⚠️ SIG generation skipped: {e}")
        
        # Summary
        click.echo(f"\n🎉 Workflow test completed successfully!")
        click.echo(f"   PAT file: {pat_path}")
        if 'sig_path' in locals() and sig_path.exists():
            click.echo(f"   SIG file: {sig_path}")
        
    except Exception as e:
        logger.exception("Workflow test failed")
        raise click.ClickException(f"Workflow test failed: {e}")


@solana.command()
@click.option('--solana-version', default='1.18.16', help='Solana version for toolchain')
@click.option('--rust-version', default=None, help='Rust version (auto-detect if not specified)')
@click.option('--components', default='core,alloc,std', help='Components to compile (comma-separated)')
def test_stdlib(solana_version: str, rust_version: Optional[str], components: str):
    """Test Rust standard library component compilation for eBPF.
    
    Compiles individual Rust standard library components (core, std, alloc)
    to eBPF format for signature generation.
    
    Example:
        solana test-stdlib --solana-version 1.18.16
        solana test-stdlib --components core,alloc --solana-version 1.18.16
    """
    logger = get_logger(__name__)
    click.echo(f"🧪 Testing Rust stdlib compilation for Solana {solana_version}")
    
    try:
        from ..platforms.solana_ebpf.builders.rust_stdlib_compiler import RustStdLibraryCompiler
        
        # Initialize compiler
        stdlib_compiler = RustStdLibraryCompiler()
        
        # Auto-detect Rust version if not specified
        if rust_version is None:
            toolchain_info = stdlib_compiler.get_rust_toolchain_info(solana_version)
            rust_version = toolchain_info['rust_version']
            click.echo(f"🔧 Auto-detected Rust version: {rust_version}")
        
        # Parse components
        component_list = [c.strip() for c in components.split(',')]
        click.echo(f"📦 Components to compile: {', '.join(component_list)}")
        
        # Compile all components
        click.echo(f"\n🏗️ Compiling stdlib components...")
        results = stdlib_compiler.compile_all_components(
            rust_version, solana_version, component_list
        )
        
        # Display results
        click.echo(f"\n📊 Compilation Results:")
        success_count = 0
        for component, rlib_path in results.items():
            if rlib_path and rlib_path.exists():
                size_mb = rlib_path.stat().st_size / (1024 * 1024)
                click.echo(f"   ✅ {component}: {rlib_path.name} ({size_mb:.1f}MB)")
                success_count += 1
            else:
                click.echo(f"   ❌ {component}: compilation failed")
        
        # Generate PAT files for successful compilations
        if success_count > 0:
            click.echo(f"\n🎯 Generating PAT files...")
            from ..platforms.solana_ebpf.generators.solana_pat_generator import SolanaPATGenerator
            pat_generator = SolanaPATGenerator()
            
            for component, rlib_path in results.items():
                if rlib_path and rlib_path.exists():
                    try:
                        pat_path = pat_generator.generate_pat_from_rlib(rlib_path)
                        stats = pat_generator.get_pat_statistics(pat_path)
                        click.echo(f"   ✅ {component}: {pat_path.name} ({stats['total_functions']} functions)")
                    except Exception as e:
                        click.echo(f"   ⚠️ {component}: PAT generation failed - {e}")
        
        click.echo(f"\n🎉 Stdlib test completed!")
        click.echo(f"   Successful components: {success_count}/{len(component_list)}")
        
    except Exception as e:
        logger.exception("Stdlib test failed")
        raise click.ClickException(f"Stdlib test failed: {e}")


@solana.command()
@click.argument('main_pat_file', type=click.Path(exists=True))
@click.option('--version', default='1.75.0', help='Rust version for sublibrary naming')
@click.option('--components', default='core,std,alloc', help='Components to extract (comma-separated)')
@click.option('--generate-sig', is_flag=True, help='Also generate SIG files for extracted PAT files')
@click.option('--install-to-ida', is_flag=True, help='Automatically install SIG files to IDA Pro directory')
def extract_sublibraries(main_pat_file: str, version: str, components: str, generate_sig: bool, install_to_ida: bool):
    """Extract Rust standard library sublibraries from main library PAT file.
    
    This approach extracts sublibrary PAT files by filtering functions from the
    main library based on their mangled namespaces (core, std, alloc).
    
    Example:
        solana extract-sublibraries data/solana_ebpf/signatures/pat/solana_program_1_18_16_ebpf_ebpf.pat
        solana extract-sublibraries main.pat --version 1.75.0 --components core,alloc --generate-sig
    """
    logger = get_logger(__name__)
    click.echo(f"🔄 Extracting sublibraries from {main_pat_file}")
    
    try:
        from ..platforms.solana_ebpf.generators.sublibrary_extractor import SubLibraryExtractor
        
        # Initialize extractor
        extractor = SubLibraryExtractor()
        
        # Parse components
        component_list = [c.strip() for c in components.split(',')]
        click.echo(f"📦 Components to extract: {', '.join(component_list)}")
        
        # Get statistics first
        click.echo(f"\n📊 Analyzing main PAT file...")
        stats = extractor.get_extraction_statistics(Path(main_pat_file))
        for component, count in stats.items():
            if component != "total" and count > 0:
                click.echo(f"   {component}: {count} functions")
        click.echo(f"   Total functions: {stats['total']}")
        
        # Extract sublibraries with optional SIG generation
        if generate_sig:
            click.echo(f"\n🔄 Extracting sublibrary PAT and SIG files...")
            results = extractor.extract_and_generate_sigs(
                Path(main_pat_file), version, component_list, install_to_ida=install_to_ida
            )
            
            # Display results
            click.echo(f"\n📋 Extraction Results:")
            success_pat_count = 0
            success_sig_count = 0
            
            for component, result_dict in results.items():
                pat_path = result_dict.get('pat')
                sig_path = result_dict.get('sig')
                
                if pat_path and pat_path.exists():
                    size_kb = pat_path.stat().st_size / 1024
                    func_count = len(extractor.parse_pat_file(pat_path))
                    click.echo(f"   ✅ {component}: {pat_path.name} ({func_count} functions, {size_kb:.1f}KB)")
                    success_pat_count += 1
                    
                    if sig_path and sig_path.exists():
                        sig_size_kb = sig_path.stat().st_size / 1024
                        click.echo(f"      ✅ SIG: {sig_path.name} ({sig_size_kb:.1f}KB)")
                        success_sig_count += 1
                        
                        if install_to_ida:
                            click.echo(f"      📥 Installed to IDA Pro")
                    else:
                        click.echo(f"      ❌ SIG generation failed")
                else:
                    click.echo(f"   ❌ {component}: extraction failed")
            
            click.echo(f"\n📊 Summary: {success_pat_count}/{len(component_list)} PAT files, "
                      f"{success_sig_count}/{len(component_list)} SIG files")
        else:
            # Only extract PAT files
            click.echo(f"\n🔄 Extracting sublibrary PAT files...")
            results = extractor.extract_sublibraries_from_pat(
                Path(main_pat_file), version, component_list
            )
            
            # Display results
            click.echo(f"\n📋 Extraction Results:")
            success_count = 0
            for component, pat_path in results.items():
                if pat_path and pat_path.exists():
                    size_kb = pat_path.stat().st_size / 1024
                    func_count = len(extractor.parse_pat_file(pat_path))
                    click.echo(f"   ✅ {component}: {pat_path.name} ({func_count} functions, {size_kb:.1f}KB)")
                    success_count += 1
                else:
                    click.echo(f"   ❌ {component}: extraction failed")
            
            click.echo(f"\n📊 Summary: {success_count}/{len(component_list)} PAT files")
        
        # Validation
        click.echo(f"\n✅ Validation:")
        if generate_sig:
            # Extract PAT paths for validation from the results dict
            pat_results = {comp: result_dict.get('pat') for comp, result_dict in results.items()}
            validation_results = extractor.validate_sublibrary_extraction(Path(main_pat_file), pat_results)
            valid_count = sum(1 for valid in validation_results.values() if valid)
            click.echo(f"   Valid extractions: {valid_count}/{len(component_list)}")
            
            click.echo(f"\n🎉 Sublibrary extraction completed!")
            click.echo(f"   Successful extractions: {success_pat_count}/{len(component_list)}")
        else:
            validation_results = extractor.validate_sublibrary_extraction(Path(main_pat_file), results)
            valid_count = sum(1 for valid in validation_results.values() if valid)
            click.echo(f"   Valid extractions: {valid_count}/{len(component_list)}")
            
            click.echo(f"\n🎉 Sublibrary extraction completed!")
            click.echo(f"   Successful extractions: {success_count}/{len(component_list)}")
        
    except Exception as e:
        logger.exception("Sublibrary extraction failed")
        raise click.ClickException(f"Sublibrary extraction failed: {e}")


if __name__ == '__main__':
    cli()