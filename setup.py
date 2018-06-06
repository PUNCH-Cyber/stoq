import os
import re
import unittest

from setuptools import setup


def version():
    version_pattern = r"__version__\W*=\W*'([^']+)'"
    src = os.path.join(os.path.dirname(__file__), 'stoq/__init__.py')
    with open(src, "r") as f:
        v, = re.findall(version_pattern, f.read())
    return v

setup(
    name="stoq",
    version=version(),
    author="Marcus LaFerrera",
    author_email="marcus@punchcyber.com",
    description="A framework for simplifying analysis.",
    license="Apache License 2.0",
    url="https://github.com/PUNCH-Cyber/stoq",
    include_package_data=True,
    packages=['stoq'],
    install_requires=['beautifulsoup4',
                      'requests',
                      'requests[security]',
                      'python-magic',
                      'ssdeep',
                      'yara-python',
                      'python-json-logger'],
    keywords='malware-analysis, malware-analyzer, malware-detection, framework, automation',
    python_requires='>=3.4',
    test_suite='stoq.tests',
    entry_points= {
        'console_scripts': [ 'stoq=stoq.cli:main']
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Topic :: Utilities',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
