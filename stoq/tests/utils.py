import os


def current_dir():
    return os.path.dirname(os.path.realpath(__file__))


def get_data_dir():
    return os.path.join(current_dir(), 'data')


def get_plugins_dir():
    return os.path.join(get_data_dir(), 'plugins')


def get_plugins2_dir():
    return os.path.join(get_data_dir(), 'plugins2')


def get_invalid_plugins_dir():
    return os.path.join(get_data_dir(), 'invalid_plugins')


def get_complex_dispatcher():
    return os.path.join(get_data_dir(), 'complex_dispatcher.yar')


def get_always_dispatcher():
    return os.path.join(get_data_dir(), 'always_dispatcher.yar')
