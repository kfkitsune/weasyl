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
