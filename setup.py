"""
Setup configuration for DiskForensics.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="diskforensics",
    version="1.0.0",
    author="Edward Marez",
    author_email="edward.marez@example.com",
    description="A professional disk image analysis tool for forensic investigations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/edwardmarez/diskforensics",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Legal Industry",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Filesystems",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "diskforensics=diskforensics.main:main",
        ],
    },
    keywords=[
        "forensics", "disk", "image", "analysis", "MBR", "GPT",
        "FAT32", "NTFS", "recovery", "timeline", "hash", "investigation"
    ],
)
