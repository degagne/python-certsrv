import os
import imp

from setuptools import setup


version = imp.load_source("version", os.path.join("version.py")).version


setup(
    name="python-certsrv",
    version=version,
    install_requires=[
        "requests",
        "requests_ntlm3",
    ],
    author="Deric Degagne",
    author_email="deric.degagne@gmail.com",
    description="A Python client for the Active Directory Certificate Service Web Enrollment.",
    url="https://github.com/degagne/python-certsrv",
    keywords='ad adcs certsrv pki certificate',
    py_modules=['certsrv'],
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: MIT License",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.6",
)