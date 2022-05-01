import sys
import re
import os
from scapy.utils import rdpcap
from scapy.all import sniff
from scapy.all import Raw

print('''\033[1;31mPcap plaintext reader for CTF flags\u001b[0m\n''')

capture_file = rdpcap(sys.argv[1])

print('\033[1;32m[+] Pcap imported: : \u001b[0m'+ str(capture_file))

raws = sniff(offline=capture_file, filter = 'tcp port 80 or tcp port 443', lfilter = lambda p: p.haslayer(Raw))

if raws != 0:
    print('\n\033[1;32m[+] ' + str(len(raws)) + ' plain text packets found: \u001b[0m' + str(raws))
else:
    print('[-] No plain text found.')
payloads = 0
for payload in raws:
    payloads += 1
    if payloads != 0:
        print('\n\033[1;32m[+] Plain text found: \u001b[0m ' + str(raws[payloads -1].payload.load))
    else:
        print('[-] Plain text empty.')
 
    if re.findall('({.*})', str(payload)):
        print('\n\033[1;32m[+] Plain text found ( \033[1;31mcontaining a Flag \u001b[0m\033[1;32m)\u001b[0m \033\n: \u001b[0m ', str(payload))
        print('\n\033[1;31m[+] Flag found: \u001b[0m ', re.findall('({.*})', str(payload[0])))
    else: 
        pass

