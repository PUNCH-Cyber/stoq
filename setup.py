import os

from setuptools import setup

# Ensure that the ssdeep library is built, otherwise install will fail
os.environ['BUILD_LIB'] = '1'

setup(
    name="stoq",
    version="0.12.0",
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
                      'yapsy',
                      'demjson',
                      'jinja2',
                      'yara-python',
                      'python-json-logger'],
)
