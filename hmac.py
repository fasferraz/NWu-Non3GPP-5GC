from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
import binascii

if __name__ == "__main__":
    '''
    ref. https://en.wikipedia.org/wiki/HMAC

        HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog")
        = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
    '''
    key = b'key'
    message = b'The quick brown fox jumps over the lazy dog'
    result = HMAC.new(key, msg=message, digestmod=SHA256)
    h_res = binascii.hexlify(result.digest())
    assert(h_res == b'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8')

