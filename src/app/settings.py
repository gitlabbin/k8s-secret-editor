import yaml
import base64

from .user import User

with open("config.yml", "r") as yamlfile:
    settings = yaml.load(yamlfile, Loader=yaml.FullLoader)
    users = []
    admins = settings["admins"]
    viewers = settings["viewers"]
    users_raw = settings["users"]
    for usr in users_raw:
        adminFiltered = list(filter(lambda item: item == usr["name"], admins))

        if len(adminFiltered) == 1:
            users.append(User(email=usr["email"], name=usr["name"],
                              password=base64.b64decode(usr["password"]).decode("utf-8"), role='admin'))
        else:
            users.append(User(email=usr["email"], name=usr["name"],
                              password=base64.b64decode(usr["password"]).decode("utf-8"), role='viewer'))
