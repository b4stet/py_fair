from setuptools import setup, find_packages

with open("requirements.txt", encoding="utf-8") as f:
    requirements = f.read().splitlines()

entrypoints = """
[console_scripts]
py_facs=facs.cli:cli
"""

data = {
    'facs': ['data/*.yaml'],
}

setup(
    name='py_facs',
    version='0.1',
    author="b4stet",
    description="Forensic Automation and Cheat Sheets",
    url="https://github.com/b4stet/py_facs",
    packages=find_packages(),
    python_requires=">=3.6",
    install_requires=requirements,
    package_data=data,
    entry_points=entrypoints,
)
