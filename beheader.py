#!/usr/bin/env python3

import requests
from tabulate import tabulate
import argparse

parser = argparse.ArgumentParser()

parser.add_argument('-u', '--url', dest='url', required=True, help="URI to be scanned")

args = parser.parse_args()
url = args.url

logo = r"""

@@@@@@@   @@@@@@@@  @@@  @@@  @@@@@@@@   @@@@@@   @@@@@@@   @@@@@@@@  @@@@@@@
@@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@
@@!  @@@  @@!       @@!  @@@  @@!       @@!  @@@  @@!  @@@  @@!       @@!  @@@
!@   @!@  !@!       !@!  @!@  !@!       !@!  @!@  !@!  @!@  !@!       !@!  @!@
@!@!@!@   @!!!:!    @!@!@!@!  @!!!:!    @!@!@!@!  @!@  !@!  @!!!:!    @!@!!@!
!!!@!!!!  !!!!!:    !!!@!!!!  !!!!!:    !!!@!!!!  !@!  !!!  !!!!!:    !!@!@!
!!:  !!!  !!:       !!:  !!!  !!:       !!:  !!!  !!:  !!!  !!:       !!: :!!
:!:  !:!  :!:       :!:  !:!  :!:       :!:  !:!  :!:  !:!  :!:       :!:  !:!
 :: ::::   :: ::::  ::   :::   :: ::::  ::   :::   :::: ::   :: ::::  ::   :::
:: : ::   : :: ::    :   : :  : :: ::    :   : :  :: :  :   : :: ::    :   : :
"""
print(logo)
HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
)


STS = ["max-age", "includesubdomains", "preload"]
XFS = ["deny", "sameorigin"]
RP = ["no-referrer", "same-origin", "strict-origin-when-cross-origin", "origin-when-cross-origin", "no-referrer-when-downgrade", "origin", "strict-origin", "unsafe-url"]
XCTO = ["nosniff"]
present = []
data_STS = {}
data_XFS = {}
data_XCTO = {}
data_RP = {}


response = requests.get(url)
headers = response.headers

def data(flag, head, value):
        if head == "Strict-Transport-Security":
                data_STS[flag] = value
        if head == "X-Frame-Options":
                data_XFS[flag] = value
        if head == "X-Content-Type-Options":
                data_XCTO[flag] = value
        if head == "Referrer-Policy":
                data_RP[flag] = value

def header_check():
    for header in HEADERS:
        if header in headers:
            present.append(header)

def flag_check():
        for header in HEADERS:
                if header == "Content-Security-Policy":
                        continue
                if header not in present:
                        data(header, header, "Header Absent")
                        continue
                for flag in STS if header == "Strict-Transport-Security" else XFS if header == "X-Frame-Options" else RP if header == "Referrer-Policy" else XCTO:
                        if flag == "max-age":
                                        if "max-age" in headers[header]:
                                                flags = headers[header].split(";")
                                                lifetime = flags[0].split('=')[1]
                                                data("max-age", header, lifetime)
                                        elif "max-age" not in headers[header] and header == "Strict-Transport-Security":
                                                data("max-age", header, "absent")
                                        continue
                        if flag.lower() in headers[header].lower() and flag != "max-age":
                                        data(flag, header, "present")
                        else:
                                        data(flag, header, "absent")

def Table():
        print("Strict-Transport-Security")
        table_STS = list(data_STS.items())
        print(tabulate(table_STS, headers=["Flag", "Status"], tablefmt="fancy_grid"))
        print("\nX-Frame-Options")
        table_XFS = list(data_XFS.items())
        print(tabulate(table_XFS, headers=["Flag", "Status"], tablefmt="fancy_grid"))
        print("\nX-Content-Type-Options")
        table_XCTO = list(data_XCTO.items())
        print(tabulate(table_XCTO, headers=["Flag", "Status"], tablefmt="fancy_grid"))
        print("\nReferrer-Policy")
        table_RP = list(data_RP.items())
        print(tabulate(table_RP, headers=["Flag", "Status"], tablefmt="fancy_grid"))

header_check()
flag_check()
Table()
