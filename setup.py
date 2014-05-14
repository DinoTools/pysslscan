#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name="sslscan",
    version="0.1",
    license="LGPLv3+",
    description="Framework and command-line tool to scan SSL enabled services",
    zip_safe=False,
    author="PhiBo (DinoTools)",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
    ],
    install_requires=[
        "cryptography>0.4",
        "pyopenssl>=0.14",
        "six>=1.4.1"
    ],
    packages=find_packages(exclude=["*.tests", "*.tests.*"]),
    include_package_data=True,
    package_data={
        #"": ["README"],
    },
    entry_points="""
    [console_scripts]
    pysslscan = sslscan:run
    """
)
