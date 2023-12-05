import requests
import hashlib
import sys


def request_api_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"there are some problem {res.status_code}")
    return res


def leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def password_check(password):
    sh1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5, tail = sh1password[:5], sh1password[5:]
    response = request_api_data(first_5)
    return leaks_count(response, tail)


def main(args):
    for password in args:
        count = password_check(password)
        if count:
            print(f"{password} found {count} times, pls change")
        else:
            print(f"{password} not fount, carry on!")


main(sys.argv[1:])
