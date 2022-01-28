WTF_CSRF_ENABLED = True
SECRET_KEY = 'bqmola'

import yaml

with open("config.yml", "r") as yamlfile:
    settings = yaml.load(yamlfile, Loader=yaml.FullLoader)