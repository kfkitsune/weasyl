"""
Support for securing code.
"""

import random
import string


secure_random = random.SystemRandom()
key_characters = string.ascii_letters + string.digits


def generate_key(size):
    """
    Generate a cryptographically-secure random key.

    Parameters:
        size (int): The number of characters in the key.

    Returns:
        An ASCII printable :term:`native string` of length *size*.
    """
    return "".join(secure_random.choice(key_characters) for i in range(size))


def input_validation_integer(int_to_test):
    """
    Validate a purported integer (Python `int`) before using it, returning integer
    zero (0) if `int_to_test` cannot be made into an int.

    Parameters:
        int_to_test - A claimed integer.

    Returns:
        If `int_to_test` can be made into a Python Integer object, int(int_to_test);
        otherwise, if the creation of the int() object fails with a ValueError, integer zero (0).
    """
    try:
        return int(int_to_test)
    except ValueError:
        return 0
