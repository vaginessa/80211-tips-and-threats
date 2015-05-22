#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# OS X wireless frameworks load example
#
# based on:
# http://newosxbook.com/articles/11208ellpA.html

__author__ = '090h'
__license__ = 'GPL'

from pprint import pprint
from os import path, listdir
import objc


def get_framework_names(frameworks_path):
    folders = filter(lambda x: '.framework' in x, listdir(frameworks_path))
    return [d.split('.')[0] for d in folders]


def load_framework(framework_path):
    try:
        framework_name = path.basename(framework_path).split('.')[0]
        print('Loading %s from %s' % (framework_name, framework_path))
        return objc.loadBundle(framework_name, globals(), framework_path)
    except Exception as ex:
        print('Loading failed with exception: %s' % ex)
        return None


def get_frameworks(private=False):
    framework_dirs = ['/System/Library/Frameworks']
    if private:
        framework_dirs.append('/System/Library/PrivateFrameworks')

    return ['%s/%s.framework' % (fd, f)
            for fd in framework_dirs
            for f in get_framework_names(fd)]


def load_all_frameworks():
    failed = []
    print('Parsing/loading found frameworks..')
    for f in get_frameworks(True):
        print(f)
        l = load_framework(f)
        print(l)
        if l is None:
            failed.append(f)

    print('Failed to load:')
    pprint(failed)


def get_wireless_frameworks():
    wireless_frameworks = []
    for f in get_frameworks(True):
        for w in ['wifi', 'wireless', 'air', 'wlan', '80211']:
            if w in f.lower():
                wireless_frameworks.append(f)
    return wireless_frameworks


def main():
    wireless_frameworks = get_wireless_frameworks()
    print('Wireless frameworks found:')
    pprint(wireless_frameworks)
    for wf in wireless_frameworks:
        bundle = load_framework(wf)
        print(bundle)
        pprint(dir(bundle))

if __name__ == '__main__':
    main()
