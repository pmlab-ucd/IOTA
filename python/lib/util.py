def convert_to_prolog_symbol(name_str):
    """
    Convert name string to Prolog symbol atom.
    Rule for Prolog symbols: They can include digits (after the initial lower-case letter) and the underscore character

    :param name_str: a string of device name or device type
    :return: a string of converted Prolog symbol atom
    """
    # strip leading and trailing spaces, and remove hyphens which are not legal character in Prolog symbols
    l = name_str.strip().replace('-', '').split()

    # make the first letter of the first word lowercase
    res = l[0][0].lower() + l[0][1:]

    # concatenate the words
    for word in l[1:]:
        res += word[0].upper() + word[1:]

    return res


def convert_to_prolog_var(name_str):
    """
    Convert name string to Prolog variable.
    Rule for Prolog variables: They starts with a capital letter. They can include digits (after the initial lower-case letter) and the underscore character

    :param name_str: a string of device name or device type
    :return: a string of converted Prolog variable
    """
    # strip leading and trailing spaces, and remove hyphens which are not legal character in Prolog symbols
    l = name_str.strip().replace('-', '').split()

    # make the first letter of the first word uppercase
    res = l[0][0].upper() + l[0][1:]

    # concatenate the words
    for word in l[1:]:
        res += word[0].upper() + word[1:]

    return res
