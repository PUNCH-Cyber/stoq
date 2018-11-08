<p align="center">
<img src="http://stoq.punchcyber.com/i/stoq.png" width="400"><br />
</p>

[![Build Status](https://travis-ci.org/PUNCH-Cyber/stoq.svg?branch=v2)](https://travis-ci.org/PUNCH-Cyber/stoq)
[![Coverage Status](https://coveralls.io/repos/github/PUNCH-Cyber/stoq/badge.svg?branch=v2)](https://coveralls.io/github/PUNCH-Cyber/stoq?branch=master)
[![Documentation Status](https://readthedocs.org/projects/stoq-framework/badge/?version=latest)](http://stoq-framework.readthedocs.io/en/latest/?badge=latest)

# Overview

stoQ is a automation framework that helps to simplify the more mundane and
repetitive tasks an analyst is required to do. It allows analysts and
DevSecOps teams the ability to quickly transition from different data sources,
databases, decoders/encoders, and numerous other tasks. stoQ was designed to be
enterprise ready and scalable, while also being lean enough for individual security
researchers.

Want to learn more? Read some of the [blog posts](https://medium.com/stoq) we've written to learn more.

- [Introduction to stoQ](https://medium.com/stoq/introduction-to-stoq-b163b3ec9e08)
- [stoQ and Enterprise e-mail](https://medium.com/stoq/know-thy-e-mail-613974084977)
- [Operationalizing Indicators](https://medium.com/stoq/operationalizing-indicators-84a2e12229d4)
- [stoQ with Suricata](https://medium.com/stoq/using-stoq-with-suricatas-file-extraction-capability-2d2ccc5b3077)

# Plugins

stoQ currently has over 40 publicly available plugins. These plugins are
available separately in the [plugin repository](https://github.com/PUNCH-Cyber/stoq-plugins-public/tree/v2)

Don't see a plugin you need? Check out the [plugin development](https://stoq-framework.readthedocs.io/en/latest/PluginDevelopment.html) documentation, or contact us.

# Installation and Documenation

stoQ requires a minimum of python 3.6.

Installation via pip:

    pip install stoq-framework

Or, you can install the lastest master:

    git clone --single-branch -b v2 https://github.com/PUNCH-Cyber/stoq
    cd stoq && python3 setup.py install

If you're interested in learning more about stoQ, to include how to develop your own plugins,
checkout the [full documentation](http://stoq-framework.readthedocs.io/).
