<p align="center">
<img src="http://stoq.punchcyber.com/i/stoq.png" width="300"><br />
</p>

[![Build Status](https://travis-ci.org/PUNCH-Cyber/stoq.svg?branch=v2)](https://travis-ci.org/PUNCH-Cyber/stoq)

[![Coverage Status](https://coveralls.io/repos/github/PUNCH-Cyber/stoq/badge.svg?branch=v2)](https://coveralls.io/github/PUNCH-Cyber/stoq?branch=v2)

[![Documentation Status](https://readthedocs.org/projects/stoq-framework/badge/?version=documentation)](https://stoq-framework.readthedocs.io/en/documentation/)

# Overview

stoQ is a automation framework that helps to simplify the more mundane and
repetitive tasks an analyst is required to do. It allows analysts and
DevSecOps teams the ability to quickly transition from different data sources,
databases, decoders/encoders, and numerous other tasks. stoQ was designed to be
enterprise ready and scalable, while also being lean enough for individual security
researchers.

Learn more about what stoQ is in the [documentation section](https://stoq-framework.readthedocs.io/en/documentation/)

# Documentation

If you're interested in learning more about stoQ, to include how to develop your own plugins,
checkout the [full documentation](https://stoq-framework.readthedocs.io/).

# Installation

stoQ requires a minimum of python 3.6.

Installation via pip:

    $ pip install stoq-framework

Or, you can install the lastest master:

    $ git clone --single-branch -b v2 https://github.com/PUNCH-Cyber/stoq
    $ cd stoq && python3 setup.py install

# Plugins

stoQ currently has over 40 publicly available plugins. These plugins are
available separately in the [plugin repository](https://github.com/PUNCH-Cyber/stoq-plugins-public/tree/v2) and can be [easily installed](https://stoq-framework.readthedocs.io/en/documentation/user/installation.html#installing-plugins) from stoQ.

Don't see a plugin you need? Check out the [plugin](https://stoq-framework.readthedocs.io/en/documentation/dev/plugin_overview.html) documentation, or contact us.
