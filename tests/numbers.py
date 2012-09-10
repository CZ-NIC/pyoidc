#!/usr/bin/env python
# Borrowed from http://gorakhargosh.github.com/pyoauth/_modules/pyoauth/

from array import array
import struct
import math

def long_to_bytes(num, blocksize=0):
    """
    Convert a long integer to a byte string::

        long_to_bytes(n:long, blocksize:int) : string

    :param num:
        Long value
    :param blocksize:
        If optional blocksize is given and greater than zero, pad the front of
        the byte string with binary zeros so that the length is a multiple of
        blocksize.
    :returns:
        Byte string.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = ''
    num = long(num)
    pack = struct.pack
    while num > 0:
        s = pack('>I', num & 0xffffffffL) + s
        num >>= 32
        # strip off leading zeros
    for i in range(len(s)):
        if s[i] != '\000':
            break
    else:
        # only happens when n == 0
        s = '\000'
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * '\000' + s
    return s


def bytes_to_long(byte_string):
    """
    Convert a byte string to a long integer::

        bytes_to_long(byte_string) : long

    This is (essentially) the inverse of long_to_bytes().

    :param byte_string:
        A byte string.
    :returns:
        Long.
    """
    acc = 0L
    unpack = struct.unpack
    length = len(byte_string)
    if length % 4:
        extra = (4 - length % 4)
        byte_string = '\000' * extra + byte_string
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', byte_string[i:i+4])[0]
    return acc

def mpi_to_long(mpi_byte_string):
    """
    Converts an OpenSSL-format MPI Bignum byte string into a long.

    :param mpi_byte_string:
        OpenSSL-format MPI Bignum byte string.
    :returns:
        Long value.
    """
    #Make sure this is a positive number
    assert (ord(mpi_byte_string[4]) & 0x80) == 0

    byte_array = bytes_to_bytearray(mpi_byte_string[4:])
    return bytearray_to_long(byte_array)


def long_to_mpi(num):
    """
    Converts a long value into an OpenSSL-format MPI Bignum byte string.

    :param num:
        Long value.
    :returns:
        OpenSSL-format MPI Bignum byte string.
    """
    byte_array = long_to_bytearray(num)
    ext = 0
    #If the high-order bit is going to be set,
    #add an extra byte of zeros
    if not (bit_count(num) & 0x7):
        ext = 1
    length = byte_count(num) + ext
    byte_array = bytearray_concat(bytearray_create_zeros(4+ext), byte_array)
    byte_array[0] = (length >> 24) & 0xFF
    byte_array[1] = (length >> 16) & 0xFF
    byte_array[2] = (length >> 8) & 0xFF
    byte_array[3] = length & 0xFF
    return bytearray_to_bytes(byte_array)

def bytearray_create(sequence):
    """
    Creates a byte array from a given sequence.

    :param sequence:
        The sequence from which a byte array will be created.
    :returns:
        A byte array.
    """
    return array('B', sequence)


def bytearray_create_zeros(count):
    """
    Creates a zero-filled byte array of with ``count`` bytes.

    :param count:
        The number of zero bytes.
    :returns:
        Zero-filled byte array.
    """
    return array('B', [0] * count)


def bytearray_concat(byte_array1, byte_array2):
    """
    Concatenates two byte arrays.

    :param byte_array1:
        Byte array 1
    :param byte_array2:
        Byte array 2
    :returns:
        Concatenated byte array.
    """
    return byte_array1 + byte_array2


def bytearray_to_bytes(byte_array):
    """
    Converts a byte array into a string.

    :param byte_array:
        The byte array.
    :returns:
        String.
    """
    return byte_array.tostring()


def bytes_to_bytearray(byte_string):
    """
    Converts a string into a byte array.

    :param byte_string:
        String value.
    :returns:
        Byte array.
    """
    byte_array = bytearray_create_zeros(0)
    byte_array.fromstring(byte_string)
    return byte_array


def bytearray_to_long(byte_array):
    """
    Converts a byte array to long.

    :param byte_array:
        The byte array.
    :returns:
        Long.
    """
    total = 0L
    multiplier = 1L
    for count in range(len(byte_array)-1, -1, -1):
        byte_val = byte_array[count]
        total += multiplier * byte_val
        multiplier *= 256
    return total


def long_to_bytearray(num):
    """
    Converts a long into a byte array.

    :param num:
        Long value
    :returns:
        Long.
    """
    bytes_count = byte_count(num)
    byte_array = bytearray_create_zeros(bytes_count)
    for count in range(bytes_count - 1, -1, -1):
        byte_array[count] = int(num % 256)
        num >>= 8
    return byte_array

def byte_count(num):
    """
    Determines the number of bytes in a long.

    :param num:
        Long value.
    :returns:
        The number of bytes in the long integer.
    """
    #if num == 0:
    #    return 0
    if not num:
        return 0
    bits = bit_count(num)
    return int(math.ceil(bits / 8.0))


def bit_count(num):
    """
    Determines the number of bits in a long value.

    :param num:
        Long value.
    :returns:
        Returns the number of bits in the long value.
    """
    #if num == 0:
    #    return 0
    if not num:
        return 0
    s = "%x" % num
    return ((len(s)-1)*4) +\
           {'0':0, '1':1, '2':2, '3':2,
            '4':3, '5':3, '6':3, '7':3,
            '8':4, '9':4, 'a':4, 'b':4,
            'c':4, 'd':4, 'e':4, 'f':4,
            }[s[0]]