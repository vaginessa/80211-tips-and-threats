#!/usr/bin/env python
# -*- coding: utf-8 -*-
# CoreWLAN dummy example

__author__ = '090h'
__license__ = 'GPL'

from pprint import pprint
import objc


def dump(obj):
    for attr in dir(obj):
        print "(%s) obj.%s = %s" % (type(attr), attr, getattr(obj, attr))


COREWLAN_FRAMEWORK = '/System/Library/Frameworks/CoreWLAN.framework'


class CoreWLAN(object):

    def __init__(self):
        # load private framework
        self.bundle = objc.loadBundle('CoreWLAN', globals(), COREWLAN_FRAMEWORK)

    def get_interface_names(self):
        return CWInterface.interfaceNames()


class WlanInterface(object):

    def __init__(self):
        self.cw = CoreWLAN()
        self.iface = CWInterface.interface()

    def get_channel(self):
        return self.iface.channel()

    def scan(self):
        return self.iface.scanForNetworksWithSSID_error_(None, None)

    def scan_ssid_list(self, ssid_list):
        return self.iface.scanForNetworksWithChannels_ssidList_legacyScanSSID_includeHiddenNetworks_mergedScanResults_maxAge_maxMissCount_maxWakeCount_maxAutoJoinCount_waitForWiFi_waitForBluetooth_priority_error()

    def power(self, state):
        return self.iface.setPower_error_(state, None)

    def zone(self):
        return self.iface.zone()


def main():
    cw = CoreWLAN()
    print('Wireless interfaces')
    pprint(cw.get_interface_names())
    # print(type(CWInterface.interfaceNames()))
    pprint([i for i in CWInterface.interfaceNames()])

    wl = WlanInterface()
    # dump(cw.iface)
    print('Properties:')
    pprint(objc.propertiesForClass(CWInterface))
    print('Current channel is: %s' % wl.get_channel())


if __name__ == '__main__':
    main()


