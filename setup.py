import setuptools

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()


__version__ = "0.0.0"

REPO_NAME = "mai-ddos"
AUTHOR_USER_NAME = "mpaul7"
PACKAGE_NAME = "ddos"
AUTHOR_EMAIL = "mpaul7@gmail.com"


setuptools.setup(
    name=PACKAGE_NAME,
    version=__version__,
    author="Manjinder",
    author_email=AUTHOR_EMAIL,
    description="DDoS Detection",
    long_description=long_description,
    long_description_content="text/markdown",
    url=f"https://github.com/{AUTHOR_USER_NAME}/{REPO_NAME}",
    project_urls={
        "Bug Tracker": f"https://github.com/{AUTHOR_USER_NAME}/{REPO_NAME}/issues",
    },
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "pandas>=1.3.0",
        "pyshark>=0.5.3",
        "scikit-learn>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "ddos=ddos.cli:cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "Operating System :: OS Independent",
    ],
)
