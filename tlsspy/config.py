import yaml

CONFIG = dict()

def configure(filename):
    global CONFIG
    CONFIG.update(yaml.load(file(filename).read()))
