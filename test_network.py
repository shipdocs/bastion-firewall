#!/usr/bin/env python3
import urllib.request

print("Attempting to connect to httpbin.org...")
try:
    response = urllib.request.urlopen('http://httpbin.org/ip', timeout=10)
    print(f"Success! Response: {response.read().decode()}")
except Exception as e:
    print(f"Failed: {e}")

