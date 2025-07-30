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
from ..core.exceptions import SignatureError
from ..core.logger import setup_logging, get_logger
from ..extractors.rlib_extractor import RlibExtractor
from ..generators.flair_generator import FLAIRGenerator
from ..generators.custom_pat_generator import CustomPATGenerator
from ..generators.enhanced_pat_generator import EnhancedPATGenerator
from ..generators.collision_aware_generator import CollisionAwarePATGenerator, create_collision_aware_generator
from ..collision_prevention import CollisionPrevention


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
            result = {'pat': output_dir / f"{lib_name}.pat"}
            click.echo("⚠️  Custom generator requires RLIB input, not object files")
        elif generator == 'enhanced':
            gen = EnhancedPATGenerator(
                demangle_names=demangle,
                use_short_names=True
            )
            # Enhanced generator also works with RLIB files
            result = {'pat': output_dir / f"{lib_name}.pat"}
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


if __name__ == '__main__':
    cli()