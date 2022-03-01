class App:
    """
    Class to store IoT apps

    Attributes:
        name: a string of app name
        desc: a string of app description
        dev_list: a list of mappings from `device type` to `device name`
    """
    def __init__(self, name, desc, dev_map):
        self.name = name
        self.desc = desc
        self.dev_map = dev_map


class Device:
    """
    Class to store IoT devices

    Attributes:
        name: a string of device name
        type: a string of device type
        net_list: a list of network names which a device is on
        outdoor: a boolean value. If it is False, then `indoor` is True
        plug_into: a string representing another device name which the current device is plugged into
    """
    def __init__(self, name, type, net_list, outdoor=False, plug_into=None):
        self.name = name
        self.type = type
        self.net_list = net_list
        self.outdoor = outdoor
        self.plug_into = plug_into


class Net:
    """
    Class to store IoT networks

    Attributes:
        name: a string of network name
        type: a string of network type
    """

    def __init__(self, name, type):
        self.name = name
        self.type = type
