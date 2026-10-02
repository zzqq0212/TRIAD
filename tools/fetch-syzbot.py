#!/usr/bin/env python3
"""Fetch a public syzbot report page and print its title and URL.

This downloads only the public HTML report metadata; it does not execute or
mutate anything. Use it on the Ubuntu host to collect provenance evidence.
"""
import argparse
import html
import re
import sys
import urllib.error
import urllib.request

_TITLE = re.compile(r"<title>(.*?)</title>", re.S | re.I)


def main(argv=None):
    p = argparse.ArgumentParser(description="Fetch a public syzbot report title")
    p.add_argument("bug_id")
    args = p.parse_args(argv)
    url = "https://syzkaller.appspot.com/bug?id=" + args.bug_id
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            text = resp.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        print("fetch failed: %s" % exc, file=sys.stderr)
        return 2
    m = _TITLE.search(text)
    title = html.unescape(m.group(1)).strip() if m else "(title not found)"
    print("title=%s\nurl=%s" % (title, url))
    return 0


if __name__ == "__main__":
    sys.exit(main())
