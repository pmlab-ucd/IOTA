import json

from app_logic_extractor import app_logic_extractor
from lib.entity import App, Device, Net
from lib.util import convert_to_prolog_symbol, convert_to_prolog_var
from vul_analyzer import vul_analyzer
from vul_scanner import vul_scanner


def translate_vul_exists(prolog_dev_name, cve_id):
    """
    Given a device full name and the list of CVE-IDs on that device, translate each CVE ID to
        Prolog's `vulExistsV2` predicate

    :param prolog_dev_name: a string of the device full name, in Prolog camel format
    :param cve_id: a CVE-ID on that device
    :return: a converted string of Prolog `vulExistsV2` predicate
    """
    return 'vulExistsV2(' + prolog_dev_name + ', \'' + cve_id + '\').\n'


def translate_vul_property(exploit_model_tuple):
    """
    Translate the app_logic_tuple returned by vul_analyzer() function to Prolog's `vulPropertyV2` predicate

    :param exploit_model_tuple: a tuple of exploit model for a CVE ID: (cve_id, precondition, effect, probability, impact_score)
    :return: a converted string of Prolog `vulPropertyV2` predicate
    """
    (cve_id, precondition, effect, probability, impact_score) = exploit_model_tuple
    return 'vulPropertyV2(\'' + cve_id + '\', ' + precondition + ', ' + effect + ', ' + str(probability) + ', ' + str(impact_score) + ').\n'


def parse_app_config(app_config_file):
    """
    Parse `app_config.json` file and return a list of App objects

    :param app_config_file: path to `app_config.json` file
    :return: a list of App objects
    """
    f_app_config = open(app_config_file)
    app_json = json.load(f_app_config)

    app_list = []
    for app in app_json['apps']:
        app_name = app['App name']
        app_desc = app['description']
        app_dev_map = app['device map']
        app_list.append(App(app_name, app_desc, app_dev_map))

    f_app_config.close()
    return app_list


def parse_sys_config(sys_config_file):
    """
    Parse `sys_config.json` file and return a list of Device objects

    :param sys_config_file: path to `sys_config.json` file
    :return: a tuple of (a list of Device objects, a tuple of Network objects)
    """
    f_dev_config = open(sys_config_file)
    dev_json = json.load(f_dev_config)

    dev_list = []
    for dev in dev_json['devices']:
        dev_name = dev['name']
        dev_type = dev['type']
        dev_net_list = dev['network']

        cur_dev_obj = Device(dev_name, dev_type, dev_net_list)
        dev_list.append(cur_dev_obj)

        if 'outdoor' in dev.keys():
            outdoor = dev['outdoor']
            cur_dev_obj.outdoor = outdoor
        if 'plug into' in dev.keys():
            plug_into = dev['plug into']
            cur_dev_obj.plug_into = plug_into

    net_list = []
    for net in dev_json['networks']:
        net_name = net['name']
        net_type = net['type']
        net_list.append(Net(net_name, net_type))

    f_dev_config.close()
    return dev_list, net_list


def translate_device_predicates(device_list):
    """
    Given the device objects list, generate Prolog facts about device type, device inNetwork, plugInto, outdoor,
    vulExistsV2, and vulPropertyV2
    :param device_list: a list of Device objects
    :return: a string of translated Prolog predicates
    """
    res = ''
    for device in device_list:
        prolog_dev_type = convert_to_prolog_symbol(device.type)
        prolog_dev_name = convert_to_prolog_symbol(device.name)

        # translate facts about device type declaration
        res += prolog_dev_type + '(' + prolog_dev_name + ').\n'

        # translate facts about device outdoor declaration
        if device.outdoor:
            res += 'outdoor(' + prolog_dev_name + ').\n'

        # translate facts about device plug into declaration
        if device.plug_into:
            prolog_outlet = convert_to_prolog_symbol(device.plug_into)
            res += 'plugInto(' + prolog_dev_name + ', ' + prolog_outlet + ').\n'

        # translate facts about device in network
        for net in device.net_list:
            prolog_net_name = convert_to_prolog_symbol(net)
            res += 'inNetwork(' + prolog_dev_name + ', ' + prolog_net_name + ').\n'

        # Translate facts about vulnerability existence and property
        # run vul_scanner to get CVEIDs for the given device
        cve_list = vul_scanner(device.name)

        for cve_id in cve_list:
            res += translate_vul_exists(prolog_dev_name, cve_id)

            # run vul_analyzer to get the exploit model for that CVE-ID
            exploit_model_tuple = vul_analyzer(cve_id, device.type)
            res += translate_vul_property(exploit_model_tuple)

        res += '\n'

    return res


def translate_sys_config(sys_config_file):
    """
    Translate IoT system configuration to Prolog facts

    :param sys_config_file: path to `sys_config.json` file
    :return: a converted string of Prolog rules for the app logic
    """
    # Parse sys config JSON file
    dev_list, net_list = parse_sys_config(sys_config_file)

    # Translate facts about: device type, device inNetwork, plugInto, outdoor, vulExistsV2, and vulPropertyV2
    res = translate_device_predicates(dev_list)

    # Translate facts about: network type declaration, e.g., `wifi(wifi1).` `zigbee(zigbee1).`
    for network in net_list:
        res += convert_to_prolog_symbol(network.type) + '(' + convert_to_prolog_symbol(network.name) + ').\n'

    return res


def translate_app_logic(app_config_file):
    """
    Translate app logic to Prolog rules based on app configuration file and device configuration file
    IMPORTANT: An IoT app in proper form always has one action in the [[main clause]],
        and the [[conditional clause]] should have NONE or multiple conditions connected by AND.

    :param app_config_file: path to `app_config.json` file
    :return: a converted string of Prolog rules for the app logic
    """
    # Parse app config JSON file
    app_list = parse_app_config(app_config_file)

    # Translate app logic to Prolog rules
    res = ''
    for app in app_list:
        # convert app description to Python tuple
        # app_logic_tuple = app_logic_extractor(app.desc)
        app_logic_tuple = ('AND', ['motion sensor', 'door contact sensor'], ['motion', 'open'], 'NONE', ['bulb'], ['on'])
        # app_logic_tuple = ('NONE', ['motion sensor'], ['motion'], 'NONE', ['bulb'], ['on'])

        if app_logic_tuple is None:
            print('error: the input app logic tuple is None\n')
            return ''

        cond_relation, cond_np_list, cond_vp_list, main_relation, main_np_list, main_vp_list = app_logic_tuple

        # Convert the app logic
        return translate_app_logic_AND_cond_clause(app.dev_map, cond_np_list, cond_vp_list, main_np_list, main_vp_list)


def translate_app_logic_AND_cond_clause(app_dev_map, cond_np_list, cond_vp_list, main_np_list, main_vp_list):
    """
    The cond lists can have one or multiple elements. But if they multiple elements, they must be in logical AND relationship
    E.g., app_logic_tuple = ('AND', ['motion sensor', 'door contact sensor'], ['motion', 'open'], 'NONE', ['bulb'], ['on'])

    :return: a string of Prolog rules
    """
    # Convert main clause
    action = main_vp_list[0]
    actuator_type = main_np_list[0]
    res = action + '(' + convert_to_prolog_symbol(app_dev_map[actuator_type]) + ') :-\n'

    # Convert conditional clause
    for trigger_dev, trigger_act in zip(cond_np_list, cond_vp_list):
        if trigger_dev == 'motion sensor':
            if trigger_act == 'motion':
                res += '\treportsMotion(' + convert_to_prolog_symbol(app_dev_map[trigger_dev]) + '),\n'
        if trigger_dev == 'door contact sensor':
            if trigger_act == 'open':
                res += '\treportsOpen(' + convert_to_prolog_symbol(app_dev_map[trigger_dev]) + '),\n'

    return res[:-2] + '.\n'


def test_translate_vul_exists():
    return translate_vul_exists('Nest Cam IQ indoor', 'CVE-2019-5035')
    # should return:
    # vulExistsV2(nestCamIQIndoor, 'CVE-2019-5035').\n


def test_translate_vul_analyzer():
    exploit_tuple = ('CVE-2019-5035', 'network', 'rootPrivilege', 0.55, 10.0)
    return translate_vul_property(exploit_tuple)
    # should return:
    # vulPropertyV2('CVE-2019-5035', network, rootPrivilege, 0.55, 10.0).


def test_translate_app_logic():
    # app_logic_tuple = ('AND', ['motion sensor', 'door contact sensor'], ['motion', 'open'], 'NONE', ['light'], ['on'])
    app_config_file = 'YOUR_IOTA_ROOT/python/test/app_config.json'
    dev_config_file = 'YOUR_IOTA_ROOT/python/test/dev_config.json'

    return translate_app_logic(app_config_file)
