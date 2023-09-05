#!/usr/bin/python3
#
# Author: TheNeoBurn
#
# Scrapes the current extern IPv4 and IPv6 addresses from an AVM Fritz!Box router 
# and updates a dynamic DNS  entry at SPDyn (spdyn.de).
# 
import hashlib
import re
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from urllib.error import HTTPError
import xml.etree.ElementTree as ET


# Your Fritz!Box URL (without tailing slash!)
FRITZBOX_URL = 'http://fritz.box'
# Your Fritz!Box username (or None to detect automatically)
FRITZBOX_USER = None
# Your Fritz!Box password
FRITZBOX_PASS = 'password'

# Your SPDyn domain 
SPDYN_DOMAIN = 'your_sub_domain.spdns.de'
# Your SPDyn token for the domain
SPDYN_TOKEN = 'aaaa-aaaa-aaaa'


class FritzBox:
    def __init__(self, url, username = '', password = ''):
        self.URL_LOGIN = '/login_sid.lua?version=2'
        self.URL_DATA = '/data.lua'
        self.BoxUrl = url
        self.SID = '0000000000000000'
        self.Challenge = ''
        self.Blocktime = 0
        self.Password = password
        self.Username = username

    def login(self):
        # Read required login data
        url = self.BoxUrl + self.URL_LOGIN + '&sid=' + self.SID
        http_response = urlopen(url)
        xml = ET.fromstring(http_response.read())
        self.Challenge = xml.find("Challenge").text
        self.Blocktime = int(xml.find("BlockTime").text)

        # Search for default fritz#### username if none is set
        if self.Username is None or self.Username == '':
            for user in xml.find("Users").findall("User"):
                if re.match('^fritz[0-9]{4}$', user.text):
                    self.Username = user.text
                    break
        
        # Check if we are banned
        if (self.Blocktime > 0):
            print('Login blocked for the next %s seconds!'%(self.Blocktime))
            return self
        
        # Execute login if SID is 0
        if not self.isRegistered():
            if self.Challenge.startswith('2$'): # Calculate PBKDF2 response
                challenge_parts = self.Challenge.split("$")
                iter1 = int(challenge_parts[1])
                salt1 = bytes.fromhex(challenge_parts[2])
                iter2 = int(challenge_parts[3])
                salt2 = bytes.fromhex(challenge_parts[4])
                hash1 = hashlib.pbkdf2_hmac("sha256", self.Password.encode(), salt1, iter1)
                hash2 = hashlib.pbkdf2_hmac("sha256", hash1, salt2, iter2)
                response = f"{challenge_parts[4]}${hash2.hex()}"
            else: # Calculate fallback MD5 response
                response = self.Challenge + "-" + self.Password
                response = response.encode("utf_16_le")
                md5_sum = hashlib.md5()
                md5_sum.update(response)
                response = self.Challenge + "-" + md5_sum.hexdigest()
            post_data = urlencode({ "username": self.Username, "response": response }).encode()
            url = self.BoxUrl + self.URL_LOGIN
            http_request = Request(url, post_data, { "Content-Type": "application/x-www-form-urlencoded" })
            http_response = urlopen(http_request)
            xml = ET.fromstring(http_response.read())
            self.SID = xml.find("SID").text
        return self

    def isRegistered(self):
        return not self.SID == '0000000000000000'

    def getDataPage(self, page: str):
        if not self.isRegistered(): self.login()
        # e.g.: dslOv, dslStat, netMoni, overview, ...
        url = self.BoxUrl + self.URL_DATA
        post_data = urlencode({ "xhr": "1", "sid": self.SID, "lang": "de", "page": page, "xhrld": "all", "useajax": "1", "no_sidrenew": "" }).encode()
        http_request = Request(url, post_data, { "Content-Type": "application/x-www-form-urlencoded" })
        http_response = urlopen(http_request)
        return http_response.read()

    def readExternalIPs(self):
        ipv4 = ''
        ipv6 = ''
        page = bytes.decode(self.getDataPage('netMoni'))
        if page[0] == '{':
            # New data format as JSON
            jdata = json.loads(page)
            ipv4 = jdata['data']['connections'][0]['ipv4']['ip']
            ipv6 = jdata['data']['connections'][0]['ipv6']['ip']
        else:
            # Read the netMoni HTML page to scrape external IP addresses
            addrs = page.split('Adresse: ')
            for addr in addrs:
                match = re.match('^(([0-9]{1,3}\\.){3}[0-9]{1,3})', addr[0:100])
                if match is not None:
                    ipv4 = match.group(1)
                else:
                    match = re.match('^((([0-9a-fA-F]{1,4}|:):)+[0-9a-fA-F]{1,4})', addr)
                    if match is not None:
                        ipv6 = match.group(1)
        return (ipv4, ipv6)


class SPDynUpdater:
    def __init__(self, domain, token) -> None:
        self.URL_UPDATE = 'https://update.spdyn.de/nic/update'
        self.Domain = domain
        self.Token = token

    def updateIPs(self, ipv4, ipv6 = None):
        ips = ipv4
        if (ipv6 is not None): ips = ips + ',' + ipv6
        url = self.URL_UPDATE + '?hostname=' + self.Domain + '&myip=' + ips + '&user=' + self.Domain + '&pass=' + self.Token
        try:
            urlopen(url)
        except HTTPError as e:
            return False
        return True


# Create an instance for Fritz!Box access
Box = FritzBox(FRITZBOX_URL, FRITZBOX_USER, FRITZBOX_PASS)
(ipv4, ipv6) = Box.readExternalIPs()

# Create an instance to update the dynamic DNS entry
Updater = SPDynUpdater(SPDYN_DOMAIN, SPDYN_TOKEN)
if Updater.updateIPs(ipv4, ipv6):
    print('SPDyn addresses updated: ' + ipv4 + ', ' + ipv6)
else:
    print('SPDyn update failed!')
