#!/usr/bin/python3

import mysql.connector
from lib.constants import brand_name_list, device_type_list
from lib.query_mysql import query_device_boolean_from_cvetable


def query_iot_cve_from_cvetable(cursor, brand_name_list, device_type_list):
    """
    Query `cvetable` using specified brand_name_list and device_type_list.

    :param cursor: a cursor object for the connected MySQL DB
    :param brand_name_list: a list of device brand names as stings
    :param device_type_list: a list of device types as stings
    :return: a dictionary with keys being tuples of (brand_name, device_type) and values being sets of CVE records as tuples
    """
    res = {}  # result dictionary

    for brand_name in brand_name_list:
        for device_type in device_type_list:
            temp_list = query_device_boolean_from_cvetable(cursor, brand_name + ' ' + device_type)
            if len(temp_list) > 0:
                res[(brand_name, device_type)] = temp_list
                # print(str((brand_name, device_type)) + ': ')
                # print(temp_list)

    # Compute result
    total_cve = set()
    for val in res.values():
        for cveid, cwe, probability, impact_score, exploit_range, description, C, I, A in val:
            total_cve.add(cveid)

    print('Total CVE number for IoT devices: ', len(total_cve))

    return res


def vul_scanner(device_name):
    """
    Query `cvetable` using the given the given `device_information` which is a string of brand_name and device_type.

    :param device_name: a string of device info, e.g., "Ring doorbell"
    :return: a list of CVEIDs for the given device
    """
    # Create a MySQL connect object and cursor object.
    db = mysql.connector.connect(host='localhost', user='iota', password='QiGuai8@!', database='cve')
    cursor = db.cursor()

    cve_tuples_list = query_device_boolean_from_cvetable(cursor, device_name)

    res = []
    for cve_tuple in cve_tuples_list:
        res.append(cve_tuple[0])

    return res


def count_total_iot_cves():
    # Create a MySQL connect object and cursor object.
    db = mysql.connector.connect(host='localhost', user='iota', password='QiGuai8@!', database='cve')
    cursor = db.cursor()

    query_iot_cve_from_cvetable(cursor, brand_name_list, device_type_list)


def test_vul_scanner():
    return vul_scanner('ring doorbell')
# should return: ['CVE-2019-9483']


if __name__ == '__main__':
    print(test_vul_scanner())
