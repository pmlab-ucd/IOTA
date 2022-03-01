import mysql.connector


def write_to_vul_analysis_table(db, cursor, cve_exploit_model):
    """
    Write a record to `vul_analysis` table.

    :param cursor: a cursor object for the connected MySQL DB
    :param cve_exploit_model: a tuple of values of a record
    :return: None
    """
    (cveid, exploit_type, precondition, effect, probability, impact_score, description) = cve_exploit_model

    add_template = ("REPLACE INTO vul_analysis "
                    "(cveid, exploit_type, precondition, effect, probability, impact_score, description) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)")
    add_value = (cveid, exploit_type, precondition, effect, probability, impact_score, description)
    cursor.execute(add_template, add_value)
    db.commit()


def query_cve_from_cvetable_given_cveid(cursor, cveid):
    """
    Query `cvetable` based on a given CVE-ID.

    :param cursor: a cursor object for the connected MySQL DB
    :param cveid: a string of a CVE-ID
    :return: a tuple of query result for the specified CVE-ID
    """
    query_str = "select cveid, cwe, probability, impact_score, exploit_range, description, C, I, A from cvetable where cveid='{}';".format(cveid)
    cursor.execute(query_str)
    res = cursor.fetchall()

    assert len(res) == 1, 'error: incorrect number of record(s) found for the given CVEID: ' + cveid

    # a record is a tuple of (exploit, impact, expRange, description)
    return res[0]


def query_device_natural_from_cvetable(cursor, device_name):
    """
    Query `cvetable` based on a device name, using `natural language` mode.

    :param cursor: a cursor object for the connected MySQL DB
    :param device_name: a string of device name
    :return: a list of tuples of query results from `cvetable`

    >>> query_device_natural_from_cvetable(cursor, 'arlo basestation')
    """
    query_str = "select cveid, cwe, probability, impact_score, exploit_range, description from cvetable where match (description) against ('{}' in natural language mode);".format(
        device_name)
    cursor.execute(query_str)
    res = cursor.fetchall()

    if len(res) == 0:
        print('warning: no CVE found for the given device: {}'.format(device_name))

    cve_list = []
    for record in res:
        cve_list.append(record)

    # a record is a tuple of (cveid, cwe, probability, impact_score, exploit_range, description)
    return cve_list


def query_device_boolean_from_cvetable(cursor, device_name):
    """
    Query `cvetable` based on a device name, using `boolean` mode.

    :param cursor: a cursor object for the connected MySQL DB
    :param device_name: a string of device name, including the brand name
    :return: a list of tuples of query results from `cvetable`

    >>> query_device_boolean_from_cvetable(cursor, 'arlo basestation')
    """
    # Concatenate the device name words using `+` to generate the boolean search pattern
    words = device_name.split()
    device_seq = ''.join(['+' + word + ' ' for word in words])
    device_seq = device_seq[:-1]

    query_str = "select cveid, cwe, probability, impact_score, exploit_range, description, C, I, A from cvetable where match (description) against ('{}' in boolean mode);".format(device_seq)
    cursor.execute(query_str)
    res = cursor.fetchall()

    cve_list = []
    for record in res:
        cve_list.append(record)

    # a record is a tuple of (cveid, cwe, probability, impact_score, exploit_range, description)
    return cve_list


if __name__ == '__main__':
    # Create a MySQL connect object and cursor object.
    db = mysql.connector.connect(host='localhost', user='YOUR_USERNAME_HERE', password='YOUR_PASSWORD_HERE', database='cve')
    cursor = db.cursor()

    # Test query CVE-ID
    result = query_cve_from_cvetable_given_cveid(cursor, 'CVE-2019-9483')
    for item in result:
        print(item)

    # Test query device in natural language mode
    cve_list = query_device_natural_from_cvetable(cursor, 'arlo basestation')
    print(cve_list)

    # Test query device in boolean mode
    cve_list = query_device_boolean_from_cvetable(cursor, 'arlo basestation')
    print(cve_list)

    cursor.close()
    db.close()
