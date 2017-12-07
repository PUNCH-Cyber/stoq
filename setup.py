import os
import unittest

from setuptools import setup

# Ensure that the ssdeep library is built, otherwise install will fail
os.environ['BUILD_LIB'] = '1'

def stoq_tests():
    stoq_path = os.path.join(os.getcwd(), "stoq")
    test_path = os.path.join(stoq_path, "tests")
    test_suite = unittest.TestLoader().discover(test_path, pattern='*_tests.py')
    return test_suite

setup(
    name="stoq",
    version="0.13.0",
    author="Marcus LaFerrera",
    author_email="marcus@punchcyber.com",
    description="A framework for simplifying analysis.",
    license="Apache License 2.0",
    url="https://github.com/PUNCH-Cyber/stoq",
    include_package_data=True,
    packages=['stoq'],
    install_requires=['beautifulsoup4',
                      'requests',
                      'python-magic',
                      'ssdeep',
                      'yara-python',
                      'python-json-logger'],
    keywords='malware-analysis, malware-analyzer, malware-detection, framework, automation',
    python_requires='>=3.4',
    test_suite='setup.stoq_tests',
    classifiers=[
        'Development Status :: 4 - Beta',
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
