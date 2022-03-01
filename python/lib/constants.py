device_type_list = ['ac', 'air quality sensor', 'alarm', 'base station', 'basestation', 'bulb', 'camera', 'camera hub',
                    'coffee machine', 'contact sensor', 'door contact sensor', 'door controller', 'door lock',
                    'door lock hub', 'doorbell', 'energy monitoring system', 'game console', 'gateway', 'gas valve', 'heater',
                    'hub', 'humidifier', 'humidity sensor', 'light sensor', 'motion sensor', 'outlet',
                    'presence sensor', 'printer', 'router', 'outlet', 'smart shades', 'smoke detector', 'speaker',
                    'switch', 'temperature sensor', 'thermostat', 'toaster', 'tv', 'ventilator', 'water sensor',
                    'water valve', 'window contact sensor', 'window controller', 'zigbee gateway']

brand_name_list = ['Amazon', 'Arlo', 'Belkin', 'Bosch', 'Ecobee', 'Insteon', 'Konke', 'Nest', 'Philips', 'Ring', 'Smartthings',
              'Sonos', 'Wink', 'Xiaomi', 'Yale']

device_action_list = ['high', 'low', 'on', 'off', 'open', 'close', 'motion', 'notify']

phy_env_feature_list = ['humidity', 'illuminance', 'motion', 'smoke', 'temperature', 'voice', 'water']

device_sense_dict = {
    'camera': {'motion', 'voice'},
    'thermostat': {'temperature', 'humidity'},
    'temperature sensor': {'temperature'},
    'motion sensor': {'motion'},
    'speaker': {'voice'},
    'air quality sensor': {'smoke', 'humidity'},
    'smoke detector': {'smoke'},
    'water sensor': {'water'},
    'light sensor': {'illuminance'}
}

device_affect_dict = {
    'camera': {'voice'},
    'speaker': {'voice'},
    'bulb': {'illuminance'},
    'tv': {'illuminance', 'voice'},
    'smart shades': {'illuminance'},
    'water valve': {'water'},
    'humidifier': {'humidity', 'water'},
    'ventilator': {'humidity'},
    'toaster': {'smoke'},
    'coffee machine': {'smoke'},
    'heater': {'temperature'},
    'air conditioner': {'temperature'},
}

cwe_to_exp_type = {
    'CWE-16': 'Password Brute Forcing',
    'CWE-20': 'Database Injection',
    'CWE-22': 'Path Traversal',
    'CWE-74': 'Data Injection',
    'CWE-78': 'OS Command Injection',
    'CWE-79': 'Cross-Site Scripting',
    'CWE-88': 'Parameter Injection',
    'CWE-89': 'SQL Injection',
    'CWE-113': 'HTTP Response Splitting',
    'CWE-119': 'Buffer Overflow',
    'CWE-190': 'Integer Overflow',
    'CWE-191': 'Integer Underflow',
    'CWE-200': 'Retrieve Embedded Sensitive Data',
    'CWE-269': 'Authentication Bypass',
    'CWE-276': 'Privilege Abuse',
    'CWE-287': 'Authentication Bypass',
    'CWE-295': 'Man in the Middle',
    'CWE-310': 'Cryptanalysis',
    'CWE-311': 'Sniffing Attacks',
    'CWE-312': 'Retrieve Embedded Sensitive Data',
    'CWE-326': 'Encryption Brute Forcing',
    'CWE-327': 'Crypto Analysis',
    'CWE-346': 'Origin Validation Bypass',
    'CWE-352': 'Cross-Site Request Forgery',
    'CWE-434': 'Privilege Abuse',
    'CWE-444': 'HTTP Request Smuggling',
    'CWE-522': 'Authentication Bypass',
    'CWE-707': 'Protocol Manipulation',
    'CWE-732': 'Privilege Abuse',
    'CWE-755': 'Improper Handling of Exceptional Conditions',
    'CWE-787': 'Buffer Overflow',
    'CWE-798': 'Authentication Bypass'
}

if __name__ == '__main__':
    print('Number of distinct exploit types:', len(set(cwe_to_exp_type.values())))
