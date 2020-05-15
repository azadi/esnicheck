#!/usr/bin/env python3

from esnicheck.check import ESNICheck


def main():
    urls = []
    with open("mostvisited.txt", "r") as f:
        for each in f:
            if not each.startswith("#"):
                urls.append(each.strip())

    with open("esni.txt", "w") as w:
        for each in urls:
            has_esni = ESNICheck(each).has_esni()
            if has_esni:
                w.write(f"{each}\n")


if __name__ == "__main__":
    main()
