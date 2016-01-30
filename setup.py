import os

from setuptools import setup

# Ensure that the ssdeep library is built, otherwise install will fail
os.environ['BUILD_LIB'] = '1'

setup(
    name="stoq",
    version="0.9.8",
    author="Marcus LaFerrera",
    author_email="marcus@punchcyber.com",
    description="A framework for simplifying analysis.",
    license="Apache License 2.0",
    url="https://github.com/PUNCH-Cyber/stoq",
    packages=['stoq'],
    package_dir={'stoq': 'stoq-framework'},
    include_package_data=True,
    install_requires=['beautifulsoup4',
                      'requests',
                      'python-magic',
                      'ssdeep',
                      'lxml',
                      'yapsy',
                      'demjson',
                      'jinja2',
                      'Cython',
                      'yara-python'],
    dependency_links=['https://github.com/plusvic/yara-python/archive/v3.4.0.zip#egg=yara-python']
)
