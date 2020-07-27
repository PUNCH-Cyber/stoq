.. _faq:

Frequently Asked Questions
==========================


- **What is the difference between stoQ v2 and v3?**

    The basic workflow and concept between the two versions are nearly similar, but under the hood 
    a lot has changed. Version 2 of stoQ was a complete rewrite of v1, filled with lots of lessons learned, 
    optimizations, and best practices. Additionally, we made the decision to ensure a modern version 
    of python was used in order to leverage many of the added benefits and features.

    stoQ v3 built upon v2, but added many additional features such as native AsyncIO support, streamlined
    data flow, and passing the full request stte to each worker plugin. A full list of changes can be 
    found in the `CHANGELOG <https://github.com/PUNCH-Cyber/stoq/blob/master/CHANGELOG.md>`_.

- **Are plugins from v2 compatiable with v3?**

    Unfortunately, no. However, porting plugins to v3 is very simple. You can read more about that
    :ref:`here <upgradingplugins>`.

- **Is v1 or v2 of stoQ still available?**

    Absolutely, though they are no longer maintained (minus major bug fixes or security issues) in favor of v3. 

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

- **stoQ seems slow when decoding json, can this be improved?**

    Possibly. stoQ leverages BeautifulSoup's UnicodeDammit function to serialize bytes into proper json serializable content. In order to limit the python library requirements and maximize compatibility, we purposefully limit core dependencies. BeautifulSoup by default attempts to leverage the python library `cchardet`, which is much more efficient than the default python library that BeautifulSoup falls back to `chardet`. Simply install `cchardet` via pip, and you may see a nice performance boost if you have complex results with bytes.

- **I know stoQ supports async operations, but my plugins don't seem to be completing any faster!**

    While all current stoQ plugins support the latest version of stoQ, not all of them will run asynchronously. There are several reasons for this. Some depend on 3rd party libraries that are not asyncio compatiable. For these, we will keep an eye out for updated 3rd party libraries that support asyncio. For many others, it is simply a matter of competing priorities. We, and very gratefully, several contributors to stoQ have been updating plugins for full asyncio support, it is still a time consuming process. If you would like to help in this effort, please do! We are more than happy to accept all of the help you are willing to volunteer.

- **Do you plan on maintaining this project long term?**

    Absolutely. We use stoQ in several production grade capabilities, as do many stoQ users. We've been developing it since 2011, and will continue to do so.

- **Can I contribute?**

    Of course! Check out the :ref:`contributing section <contributing>` to find out how.

- **Something seems broken, how can I get help?**

    Feel free to `submit an issue <https://github.com/PUNCH-Cyber/stoq/issues>`_.

- **How can I ask other questions?**

    Feel free to join us on `spectrum <https://spectrum.chat/stoq>`_, reach out to us at `@punchcyber <https://twitter.com/punchcyber>`_ or the author `@mlaferrera <https://twitter.com/mlaferrera>`_
