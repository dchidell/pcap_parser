# pcap_parser
Generates traffic summary statistucs & an excel file from a pcap

# Description:
This script will take a captured pcap file and parse it. Metadata will be exported per-packet to an excel file. Summary information will be output to console on script completion.

# Important Notes:
Takes a long time for large pcap files ~30 seconds per GB on my mac + file save time - larger CPU will assist this.

# Usage:
```
dchidell@dchidell-mac:pcap_parse$ python3 pcap_parse.py -h
usage: pcap_parse.py [-h] capture.pcap capture.xlsx

Processes a PCAP file and converts packets to excel rows for further analysis.

positional arguments:
  capture.pcap  This is the pcap file containing the capture we wish to parse
  capture.xlsx  This is the excel file we wish to export.

optional arguments:
  -h, --help    show this help message and exit

Written by David Chidell (dchidell@cisco.com)
```
