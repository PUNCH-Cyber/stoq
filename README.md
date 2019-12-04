<p align="center">
<img src="http://stoq.punchcyber.com/i/stoq.png" width="300"><br />
</p>

[![Join the community on Spectrum](https://withspectrum.github.io/badge/badge.svg)](https://spectrum.chat/stoq)

[![Build Status](https://travis-ci.org/PUNCH-Cyber/stoq.svg?branch=master)](https://travis-ci.org/PUNCH-Cyber/stoq)
[![Coverage Status](https://coveralls.io/repos/github/PUNCH-Cyber/stoq/badge.svg?branch=master)](https://coveralls.io/github/PUNCH-Cyber/stoq?branch=master)
[![Documentation Status](https://readthedocs.org/projects/stoq-framework/badge/?version=latest)](https://stoq-framework.readthedocs.io/en/latest/?badge=latest)
[![Docker Build](https://img.shields.io/docker/build/punchcyber/stoq.svg)](https://hub.docker.com/r/punchcyber/stoq/)
[![pypi](https://img.shields.io/pypi/v/stoq-framework.svg)](https://pypi.org/project/stoq-framework/)
[![License](https://img.shields.io/pypi/l/stoq-framework.svg)](https://pypi.org/project/stoq-framework/)

# Get Started

- [Documentation](https://stoq-framework.readthedocs.io/)
- [Installation](https://stoq-framework.readthedocs.io/en/latest/installation.html)
- [Plugin Repository](https://github.com/PUNCH-Cyber/stoq-plugins-public)
- [Plugin Documentation](https://stoq-framework.readthedocs.io/en/latest/dev/plugin_overview.html)

# Overview

stoQ is an automation framework that helps to simplify the mundane and repetitive
tasks an analyst is required to do. It enables analysts and DevSecOps teams to
quickly transition between different data sources, databases, decoders/encoders,
and numerous other tasks using enriched and consistent data structures. stoQ was
designed to be enterprise ready and scalable, while also being lean enough for
individual security researchers.

## Why use stoQ?

- Extremely lightweight and designed with simplicity in mind.
- Fully supports AsyncIO.
- A wide range of [publicly available plugins](https://github.com/PUNCH-Cyber/stoq-plugins-public).
- stoQ makes no assumptions about your workflow. Analysts decide everything, from where data
  originates, how it is scanned/decoded/processed, to where it is saved.
- Scalable in not only native/bare metal environments, but also using solutions such as
  Kubernetes, AWS Lambda, Google Cloud Functions, Azure Functions, and many more.
- Written to be easily and quickly extended. All you need is a plugin.
- Can be used in an enterprise environment or by individuals without the need for client/server
  infrastructure
- Over 95% of code is covered by unittests.
- All core functions and plugins leverage typing and are type-checked at commit.
- Actively developed since 2011, open source since 2015.
- Extensive up-to-date [documentation](https://stoq-framework.readthedocs.io/).

# History

stoQ was initially a collection of scripts that helped us solve problems we encountered
daily. These tasks, such as parsing an SMTP session, extracting attachments, scanning
them with a multitude of custom and open source tools, saving the results, and then
finally analyzing them took up an increasing amount of our team's resources. We spent
an ever increasing amount of time simply attempting to collect and extract data. This
took valuable resources away from our ability to actually find and analyze adversaries
targeting our networks.

We grew tired of being the hamster in a wheel and decided to do something about it.
In 2011, we began development of a framework that would not only tackle the problem
above, but also allow us to quickly change the flow of data and automated analytics,
quickly pivot to new databases to house the results, and simply be able to respond
to the adversaries changing their tactics, techniques, and procedures (TTPs).

Most importantly, our focus was to build a tool that would allow us to do what we
love to do -- defend networks from adversaries that are determined, focused, and relentless.

In 2015, after stoQ had been matured in multiple large scale operational networks, we
decided to open source our work in hopes of helping the wider Network Defense community.
Since then, we've been constantly enhancing stoQ thanks to the feedback and contributions
from the community of stoQ users.

