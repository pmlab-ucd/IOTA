#!/usr/bin/python3

import mysql.connector

from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.stem import WordNetLemmatizer

from lib.constants import brand_name_list, device_type_list, cwe_to_exp_type
from vul_scanner import query_iot_cve_from_cvetable
from lib.query_mysql import write_to_vul_analysis_table, query_cve_from_cvetable_given_cveid


def parse_description(desc):
    """
    Convert the string of descriptions to a list of lemmas.

    :param desc: a string of vulnerability description consisting of one or more sentences
    :return: a tuple of (lemma_list, lemma_list_raw, desc_lower)
    """
    # create a lemmatizer for word standardization
    wordnet_lemmatizer = WordNetLemmatizer()

    desc_lower = desc.lower()  # a string of original CVE description in lower case
    sent_list = sent_tokenize(desc_lower)
    sent_list_raw = sent_tokenize(desc)

    lemma_list = []  # a list of lemmatized words for one description, in lower case
    for sent in sent_list:
        sentence_words = word_tokenize(sent)
        for word in sentence_words:
            lemma_list.append(wordnet_lemmatizer.lemmatize(word, pos='v'))

    lemma_list_raw = []  # a list of lemmatized words for one description, in raw form
    for sent in sent_list_raw:
        sentence_words_raw = word_tokenize(sent)
        for word in sentence_words_raw:
            lemma_list_raw.append(wordnet_lemmatizer.lemmatize(word, pos='v'))

    return lemma_list, lemma_list_raw, desc_lower


def get_protocol(lemma_list):
    """
    Get the wireless protocol type based on vulnerability description.

    :param lemma_list: a list of lemmatized words from vulnerability description
    :return: a string of wireless protocol type
    """
    if 'wifi' in lemma_list or 'wi-fi' in lemma_list or 'tcp' in lemma_list or 'udp' in lemma_list or 'http' in lemma_list or 'dns' in lemma_list or 'telnet' in lemma_list or 'mqtt' in lemma_list:
        return 'wifi'

    if 'bluetooth' in lemma_list or 'ble' in lemma_list:
        return 'bluetooth'

    if 'zigbee' in lemma_list:
        return 'zigbee'

    if 'zwave' in lemma_list or 'z-wave' in lemma_list:
        return 'zwave'

    return 'undecided'


def full_fledged(lemma_list, device_type):
    """
    Decide if the device is full-fledged.

    :param lemma_list: a list of lemmatized words from vulnerability description
    :param device_type: a string of device type
    :return: a boolean indicating whether a device is full-fleged or not
    """
    return 'camera' in lemma_list or 'router' in lemma_list or 'hub' in lemma_list or 'tv' in lemma_list or 'printer' in lemma_list or 'basestation' in lemma_list or 'thermostat' in lemma_list or \
            device_type == 'camera' or device_type == 'router' or device_type == 'hub' or device_type == 'tv' or device_type == 'printer' or device_type == 'basestation' or device_type == 'thermostat'


def is_dos(lemma_list, desc_lower, C, I, A):
    """
    Decide if the exploit type is DoS.

    :return: a boolean value
    """
    return 'dos' in lemma_list or 'denial of service' in desc_lower or 'denial-of-service' in desc_lower or 'crash' in lemma_list or C == 0 and I == 0 and A == 2


def is_buffer_overflow(desc_lower):
    """
    Decide if the exploit type is buffer overflow.

    :return: a boolean value
    """
    return 'buffer overflow' in desc_lower or 'buffer overrun' in desc_lower or 'stack overflow' in desc_lower


def is_man_in_the_middle(lemma_list, lemma_list_raw, desc_lower):
    """
    Decide if the exploit type is man in the middle.

    :return: a boolean value
    """
    return 'man-in-the-middle' in lemma_list or 'man in the middle' in desc_lower or 'MITM' in lemma_list_raw


def is_xss(lemma_list_raw, desc_lower):
    """
    Decide if the exploit type is XSS.

    :return: a boolean value
    """
    return 'XSS' in lemma_list_raw or 'cross-site scripting' in desc_lower or 'cross site scripting' in desc_lower


def is_csrf(lemma_list_raw, desc_lower):
    """
    Decide if the exploit type is CSRF.

    :return: a boolean value
    """
    return 'CSRF' in lemma_list_raw or 'XSRF' in lemma_list_raw or 'cross-site request forgery' in desc_lower or 'cross site request forgery' in desc_lower


def decide_exploit_precondition(exploit_range, desc, device_type):
    """
    Decide the precondition of an exploit based on its exploit range and natural language description. NOTICE: Original
    `Network` attack vector can be misleading as CVSS does not have enough information to decide its actual range.
    Original `Adjacent` attack vector is ambiguous about physically adjacent and logically adjacent.

    :param exploit_range: the exploit range field of its CVSS, including Network, Adjacent, Local, Physical
    :param desc: a string of one or multiple sentences for vulnerability description
    :param device_type: a string of device_type
    :return: a string indicating the exploit precondition
    """
    lemma_list, lemma_list_raw, desc_lower = parse_description(desc)

    if exploit_range == 'PHYSICAL':
        return 'physical'

    if exploit_range == 'LOCAL':
        return 'local'

    # Decide the protocol based on vulnerability descriptions
    protocol = get_protocol(lemma_list)

    # If the exploit range is `ADJACENT_NETWORK`, then we identify whether it is physically or logically adjacent
    if exploit_range == 'ADJACENT_NETWORK':
        return decide_precondition_for_original_adjacent(protocol, lemma_list)

    # If the exploit range is `NETWORK`, we should check if it is the correct range
    return decide_precondition_for_original_network(device_type, protocol, lemma_list, lemma_list_raw, desc_lower)


def decide_precondition_for_original_adjacent(protocol, lemma_list):
    # If the exploit is about wifi network, then attacker has to join the wifi network first
    if protocol == 'wifi':
        return 'wifi:adjacent_logically'

    if protocol == 'bluetooth' or protocol == 'zigbee' or protocol == 'zwave':
        return protocol + ':' + decide_precondition_low_power_protocol(lemma_list)

    # for other undecided adjacent types, we set precondition as `wifi:adjacent_logically`
    return 'wifi:adjacent_logically'


def decide_precondition_for_original_network(device_type, protocol, lemma_list, lemma_list_raw, desc_lower):
    if 'remote' in lemma_list:
        return 'network'
    if (is_xss(lemma_list_raw, desc_lower) or is_csrf(lemma_list_raw, desc_lower) or 'dns rebinding' in desc_lower) and full_fledged(lemma_list, device_type):
        return 'network'

    # if a device is not full-fledged, and there is no `remote` keyword, then set precondition as `PROTOCOL:adjacent_XXX`
    if not full_fledged(lemma_list, device_type):
        if protocol == 'bluetooth' or protocol == 'zigbee' or protocol == 'zwave':
            return protocol + ':' + decide_precondition_low_power_protocol(lemma_list)
        return 'wifi:adjacent_logically'

    return 'network'


def decide_precondition_low_power_protocol(lemma_list):
    if 'sniff' in lemma_list or 'decrypt' in lemma_list or 'eavesdrop' in lemma_list or 'intercept' in lemma_list:
        return 'adjacent_physically'
    return 'adjacent_logically'


def decide_exploit_effect(desc, device_type, C, I, A):
    """
    Decide the effect of an exploit based on its natural language description.

    :param desc: a string of one or multiple sentences for vulnerability description
    :param device_type: a string of device_type
    :param C: confidentiality, 2: COMPLETE, 1: PARTIAL, 0: NONE
    :param I: integrity, 2: COMPLETE, 1: PARTIAL, 0: NONE
    :param A: availability, 2: COMPLETE, 1: PARTIAL, 0: NONE
    :return: a string indicating the exploit effect
    """
    lemma_list, lemma_list_raw, desc_lower = parse_description(desc)

    # Here are some rules based on keywords in the descriptions
    if 'root' in lemma_list or 'arbitrary' in lemma_list:
        if full_fledged(lemma_list, device_type):
            return 'rootPrivilege'
        else:
            return 'commandInjection'

    if 'control' in lemma_list or 'take over' in desc_lower:
        return 'deviceControl'

    if (('inject' in lemma_list or 'insert' in lemma_list or 'execute' in lemma_list) and 'command' in lemma_list) or (
            'hijack' in lemma_list and 'request' in lemma_list):
        return 'commandInjection'

    if ('inject' in lemma_list or 'insert' in lemma_list or 'obtain') and (
            'data' in lemma_list or 'event' in lemma_list):
        return 'eventAccess'

    if ('steal' in lemma_list or 'obtain' in lemma_list or 'retrieve' in lemma_list) and (
            'wifi' in lemma_list or 'wi-fi' in lemma_list):
        return 'wifiAccess'

    if is_dos(lemma_list, desc_lower, C, I, A):
        return 'DoS'

    # Here are some customized rules based on CIA triad
    # if the device has CIA all high, and it is a full-fledged device, then it is root, otherwise, we return deviceControl
    if C == 2 and I == 2 and A == 2:
        if full_fledged(lemma_list, device_type):
            return 'rootPrivilege'
        return 'deviceControl'

    # Now we need to construct more complicated rules
    # rule for door lock
    if 'unlock' in lemma_list and 'lock' in lemma_list:
        return 'commandInjection'

    # rule for light bulb
    if 'turn on' in desc_lower and ('light' in lemma_list or 'bulb' in lemma_list):
        return 'commandInjection'

    # rule for buffer overflow
    if is_buffer_overflow(desc_lower):
        if 'inject' in lemma_list or 'hijack' in lemma_list or 'hijacking' in lemma_list:
            if full_fledged(lemma_list, device_type):
                return 'rootPrivilege'
            else:
                return 'commandInjection'
        else:
            return 'DoS'

    return 'unknown_exploit_effect'


def decide_exploit_type(cwe, cwe_to_exp_type, desc, C, I, A):
    """
    Decide the type of an exploit based on its CWE and natural language description.

    :param cwe: a string of the CWE-ID of the NVD-CVE entry
    :param cwe_to_exp_type: a dictionary mapping CWE-ID to exploit types
    :param desc: a string of one or multiple sentences for vulnerability description
    :param C: confidentiality, 2: COMPLETE, 1: PARTIAL, 0: NONE
    :param I: integrity, 2: COMPLETE, 1: PARTIAL, 0: NONE
    :param A: availability, 2: COMPLETE, 1: PARTIAL, 0: NONE
    :return: a string of exploit types
    """
    lemma_list, lemma_list_raw, desc_lower = parse_description(desc)

    if is_dos(lemma_list, desc_lower, C, I, A):
        return 'Denial of Service'

    if is_buffer_overflow(desc_lower):
        return 'Buffer Overflow'

    if is_man_in_the_middle(lemma_list, lemma_list_raw, desc_lower):
        return 'Man in the Middle'

    if cwe in cwe_to_exp_type:
        return cwe_to_exp_type[cwe]

    return 'unknown_exploit_type'


def vul_analyzer(cve_id, device_type):
    """
    Analyze the given CVE ID and turn the exploit model.

    :param cve_id: a string of CVE ID
    :param device_type: device type can help to decide exploit precondition and effect
    :return: a tuple of exploit model (in Prolog terminology)
    """
    # Create a MySQL connect object and cursor object.
    db = mysql.connector.connect(host='localhost', user='YOUR_USERNAME_HERE', password='YOUR_PASSWORD_HERE', database='cve')
    cursor = db.cursor()

    # Query MySQL database to get the cve_tuple
    cve_id, cwe, probability, impact_score, exploit_range, desc, C, I, A = query_cve_from_cvetable_given_cveid(cursor, cve_id)
    precondition = decide_exploit_precondition(exploit_range, desc, device_type)
    effect = decide_exploit_effect(desc, device_type, C, I, A)
    # exploit_type = decide_exploit_type(cwe, cwe_to_exp_type, desc, C, I, A)

    return cve_id, precondition, effect, probability, impact_score


def main():
    # Create a MySQL connect object and cursor object.
    db = mysql.connector.connect(host='localhost', user='YOUR_USERNAME_HERE', password='YOUR_PASSWORD_HERE', database='cve')
    cursor = db.cursor()

    # Create the dictionary to store queried CVEs for IoT devices
    iot_cve_dict = query_iot_cve_from_cvetable(cursor, brand_name_list, device_type_list)

    # Parse CVE descriptions to decide the effect type of each exploit
    for (brand_name, device_type) in iot_cve_dict:
        # print(brand_name, device_type)
        cve_tuple_list = iot_cve_dict[(brand_name, device_type)]
        for (cveid, cwe, probability, impact_score, exploit_range, desc, C, I, A) in cve_tuple_list:
            precondition = decide_exploit_precondition(exploit_range, desc, device_type)
            effect = decide_exploit_effect(desc, device_type, C, I, A)
            exploit_type = decide_exploit_type(cwe, cwe_to_exp_type, desc, C, I, A)

            cve_exploit_model = (cveid, exploit_type, precondition, effect, probability, impact_score, desc)
            write_to_vul_analysis_table(db, cursor, cve_exploit_model)

    cursor.close()
    db.close()


def test_vul_analyzer():
    return vul_analyzer('CVE-2019-3949', 'base station')
# should return: ('CVE-2019-3949', 'network', 'rootPrivilege', 0.98)


if __name__ == '__main__':
    print(test_vul_analyzer())
