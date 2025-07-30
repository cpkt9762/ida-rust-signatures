#!/usr/bin/env python3
"""
Setup script for ida-rust-signatures
Professional CLI toolkit for generating IDA Pro FLIRT signatures from Rust binaries
"""

from setuptools import setup, find_packages
import os

# Read README file
def read_readme():
    try:
        with open("README.md", "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return "Professional CLI toolkit for generating IDA Pro FLIRT signatures from Rust binaries"

# Read requirements
def read_requirements():
    try:
        with open("requirements.txt", "r", encoding="utf-8") as fh:
            requirements = []
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    requirements.append(line)
            return requirements
    except FileNotFoundError:
        return [
            "arpy>=2.3.0",
            "pyelftools>=0.29",
            "requests>=2.28.0",
            "packaging>=21.0",
            "colorama>=0.4.6",
            "click>=8.0.0",
            "pydantic>=2.0.0",
            "pydantic-settings>=2.0.0",
            "pyyaml>=6.0",
            "toml>=0.10.2",
            "rust-demangler>=0.1.0",
        ]

setup(
    name="ida-rust-signatures",
    version="1.0.0",
    author="cpkt9762",
    author_email="",
    description="Professional CLI toolkit for generating IDA Pro FLIRT signatures from Rust binaries",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/cpkt9762/ida-rust-signatures",
    project_urls={
        "Bug Reports": "https://github.com/cpkt9762/ida-rust-signatures/issues",
        "Source": "https://github.com/cpkt9762/ida-rust-signatures",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Reverse Engineering",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    keywords="ida-pro flirt signatures rust reverse-engineering binary-analysis",
    python_requires=">=3.11",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "ida-rust-sigs=src.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.toml", "*.md"],
    },
    zip_safe=False,
)