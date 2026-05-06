from setuptools import setup, find_packages

setup(
    name="nexus-llm",
    version="0.1.0",
    description="NEXUS — Neural EXploitation Unified System for LLM Security",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="NEXUS Contributors",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests*", "scenarios*"]),
    py_modules=["cli"],
    install_requires=[
        "httpx>=0.27.0",
        "anthropic>=0.30.0",
        "openai>=1.35.0",
    ],
    extras_require={
        "dev": ["pytest", "pytest-cov", "black", "ruff"],
        "rich": ["rich>=13.0.0"],
    },
    entry_points={
        "console_scripts": [
            "nexus=cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="llm security red-team ai exploitation prompt-injection jailbreak",
)
