#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="cjwt",
    version="1.0.0",
    author="JWT Tools",
    author_email="info@example.com",
    description="A Swiss Army knife for JWT operations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cjwt",
    packages=find_packages(),
    py_modules=["cjwt"],
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "cjwt=cjwt:main",
        ],
    },
) 