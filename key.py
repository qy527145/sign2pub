import base64
import json
import time
from functools import wraps
from multiprocessing import Pool

import gmpy2
from Crypto import Hash
from Crypto.Signature.pkcs1_15 import _EMSA_PKCS1_V1_5_ENCODE  # noqa
from Crypto.Signature.pss import _EMSA_PSS_ENCODE  # noqa
from crypto_plus import CryptoPlus

alg_map = {
    'RS256': ('SHA256', _EMSA_PKCS1_V1_5_ENCODE),
    'RS384': ('SHA384', _EMSA_PKCS1_V1_5_ENCODE),
    'RS512': ('SHA512', _EMSA_PKCS1_V1_5_ENCODE),
    'PS256': ('SHA256', _EMSA_PSS_ENCODE),
    'PS384': ('SHA384', _EMSA_PSS_ENCODE),
    'PS512': ('SHA512', _EMSA_PSS_ENCODE),
}


def timer(loop=1000000):
    def outer(func):
        @wraps(func)
        def inner(*args, **kwargs):
            res = None
            start = time.perf_counter()
            print(f"[{inner.__name__}] start run")
            # Call the actual function
            for _ in range(loop):
                res = func(*args, **kwargs)

            duration = time.perf_counter() - start
            print(f"[{inner.__name__}] took {duration * 1000} ms")
            return res

        return inner

    return outer


def cal_rsa_n(token: str):
    message, signature = token.rsplit('.', 1)
    header, payload = message.split('.')
    header = header + '=' * - (len(header) % - 4)
    alg = json.loads(base64.urlsafe_b64decode(header).decode())['alg']

    assert alg in alg_map
    hash_alg, encode = alg_map[alg]
    hash_alg = getattr(Hash, hash_alg)

    # payload = payload + '=' * - (len(payload) % - 4)
    signature = signature + '=' * - (len(signature) % - 4)
    message = message.encode()
    signature = base64.urlsafe_b64decode(signature)
    return gmpy2.mpz(int.from_bytes(signature)) ** gmpy2.mpz(65537) - int.from_bytes(
        encode(hash_alg.new(message), len(signature)))


def primes(limit=100):
    for i in range(2, limit):
        if gmpy2.is_prime(i):
            yield i


@timer(1)
def batch_cal(tokens):
    with Pool(min(len(tokens), 8)) as p:
        nums = p.map(cal_rsa_n, tokens)
        if len(nums) == 1:
            res = nums[0]
        else:
            res = gmpy2.gcd(*nums)
    for prime in primes(100):
        while res % prime == 0:
            res = res // prime

    return res


@timer(1)
def check(tokens, key):
    rsa = CryptoPlus.loads(key)
    for token in tokens:
        message, signature = token.rsplit('.', 1)
        header, payload = message.split('.')
        header = header + '=' * - (len(header) % - 4)
        alg = json.loads(base64.urlsafe_b64decode(header).decode())['alg']
        assert alg in alg_map
        signature = signature + '=' * - (len(signature) % - 4)
        message = message.encode()
        signature = base64.urlsafe_b64decode(signature)
        assert rsa.verify(message, signature, hash_algorithm=alg_map[alg][0])


def input_tokens(limit=2):
    tokens = []
    while True:
        token = input('Enter a JWT Token: ')
        if token:
            tokens.append(token)
        elif len(tokens) >= limit:
            return tokens


def get_n(key: str):
    return CryptoPlus.loads(key).public_key.n


def main():
    rsa_n = None
    tokens = input_tokens(2)
    while True:
        if not tokens:
            continue
        n = batch_cal(tokens)
        if rsa_n:
            n = gmpy2.gcd(rsa_n, n)
        rsa_n = n
        key = CryptoPlus.construct_rsa(n=int(n)).dumps()[1].decode()
        try:
            check(tokens, key)
            print("n: ")
            print(n)
            print('公钥: ')
            print(key)
            break
        except:
            print('ERROR: need more tokens')
            tokens = input_tokens(1)
            continue


if __name__ == '__main__':
    main()
