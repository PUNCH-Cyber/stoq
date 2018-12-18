.. _faq:

Frequently Asked Questions
==========================


- **What is the difference between stoQ v1 and v2?**

    The basic workflow and concept between the two versions are nearly similar, but under the hood a lot has changed. Version 2 of stoQ was a complete rewrite filled with lots of lessons learned, optimizations, and best practices. Additionally, we made the decision to ensure a modern version of python was used in order to leverage many of the added benefits and features.

- **Are plugins from v1 compatiable with v2?**

    Unfortunately, no. However, porting plugins to version 2 is very simple.

- **Is v1 of stoQ still available?**

    Absolutely, though it is no longer maintained (minus major bug fixes or security issues) in favor of v2. You can get the `framework here <https://github.com/PUNCH-Cyber/stoq/tree/v1>`_ and the `plugins here <https://github.com/PUNCH-Cyber/stoq-plugins-public/tree/v1>`_.

- **Why should I use stoQ?**

    Because your time is valuable and there are better things to do with it than run the same tools over and over again. stoQ allows you to automate most of the mundane tasks analysts do on a daily basis. It also allows you to do this scanning at scale, against a few to hundreds of millions of payloads daily.

- **How long has stoQ been around?**

    We started developing stoQ back in 2011 to help automate and streamline many of our day to day tasks. In 2015, after several years of developing and real world use in large enterprise environments, we decided to open source the entire framework, along with many plugins.

- **Why is everything a plugin?**

    Flexibility. When we started building stoQ we didn't want to have to reengineer it if we switched databases, or if we wanted to use a different queuing system, or some other random piece of our workflow changed. By leveraging plugins, it's simple a matter of adding or removing them.

- **Can stoQ be used for more than just file analysis?**

    Absolutely. We've used it for everything from processing threat intel feeds, to scanning e-mails (and their attachments), to slack bots.

- **How does stoQ work at scale?**

    As with anything that "scales", it depends. Infrastructure, location, resources, and many other things come into play. In our experience, it is possible to scan hundreds of millions of payloads per day with the right setup. Overall, we have been very pleased with it's ability to scale to fit all of our needs without issue.

- **Do you plan on maintaining this project long term?**

    Absolutely. We use stoQ in several production grade capabilities, as do many stoQ users. We've been developing it since 2011, and will continue to do so.

- **Can I contribute?**

    Of course! Check out the :ref:`contributing section <contributing>` to find out how.

- **Something seems broken, how can I get help?**

    Feel free to `submit an issue <https://github.com/PUNCH-Cyber/stoq/issues>`_.

- **How can I ask other questions?**

    Feel free to send us an e-mail at stoq @ punchcyber.com or, reach out to us at `@punchcyber <https://twitter.com/punchcyber>`_ or the author `@mlaferrera <https://twitter.com/mlaferrera>`_