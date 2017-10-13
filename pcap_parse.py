#!/usr/bin/python3
# Author: David Chidell (dchidell)

#################################
# This script reads a pcap file,  generates summary stats & an excel file to assist in the creation of traffic profiles.
#################################
# The following is performed as a result of this script:
# * PCAP File opened and read
# * Summary statistics output to stdout
# * An excel file created containing one row per IP packet in the pcap file
##################################
# Requirements:
# * 'xlsxwriter', 'argparse', 'dpkt', 'binascii' python packages. ALl of these can be installed using pip
# * File read & write access to the current directory
# * A rather large amount of memory for large pcap files!
##################################
# Notes:
# Takes a long time for large pcap files ~30 seconds per GB on my mac + file save time - larger CPU will assist this.
##################################

import xlsxwriter
import argparse
import dpkt
import binascii
import sys

def parse_args():
    parser = argparse.ArgumentParser(
        description='Processes a PCAP file and converts packets to excel rows for further analysis.',
        epilog='Written by David Chidell (dchidell@cisco.com)')
    parser.add_argument('pcap', metavar='capture.pcap',
                        help='This is the pcap file containing the capture we wish to parse')
    parser.add_argument('outfile', metavar='capture.xlsx',
                        help='This is the excel file we wish to export.')
    return parser.parse_args()


def raw_mac_to_string(mac_addr):
    mac_hex = binascii.hexlify(mac_addr)
    str_list = list()
    for i in range(6):
        str_list.append(mac_hex[i*2:i*2+2].decode('utf-8'))
    human_mac = ":".join(str_list)
    return human_mac

def raw_ip_to_string(ip_addr):
    ip_hex = binascii.hexlify(ip_addr)
    str_list = list()
    for i in range(4):
        hex_octet_string = ip_hex[i*2:i*2+2].decode('utf-8')
        dec_octet_int = int(hex_octet_string,16)
        str_list.append(str(dec_octet_int))
    human_ip = ".".join(str_list)
    return human_ip

def write_excel_row(sheet,row,data):
    for col,entry in enumerate(data):
        sheet.write(row,col,entry)

def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * (filled_len-1) + '>' + '-' * (bar_len - filled_len)

    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush()

def main():
    args = parse_args()
    filename = args.outfile if '.xlsx' in args.outfile else args.outfile+'.xlsx'

    workbook = xlsxwriter.Workbook(filename)
    sheet = workbook.add_worksheet()
    write_excel_row(sheet,0,['TIMESTAMP','SRC IP','DST IP','VLAN','SIZE','PROTOCOL','SRC PORT','DST PORT'])

    first_ts = -1
    last_ts = -1
    packet_count = 0
    ip_count = 0
    vlan_dict = {}
    packet_sizes = []
    
    print('*** Processing packets and writing excel! This can take a while if you have a large pcap!')
    print('Counting packets...')
    for ts, packet in dpkt.pcap.Reader(open(args.pcap,'rb')):
        packet_count += 1

    print('Found {} packets!'.format(packet_count))

    current_packet = 0
    current_percent = 0

    for ts, packet in dpkt.pcap.Reader(open(args.pcap,'rb')):
        current_packet += 1
        percent_done = round((current_packet / packet_count)*100)
        if percent_done != current_percent:
            current_percent = percent_done
            progress(current_packet, packet_count, status=' Processing PCAP')

        eth = dpkt.ethernet.Ethernet(packet)
        if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip_count += 1
        if first_ts == -1:
            first_ts = ts

        excel_entry = []
        ip = eth.data
        excel_entry.append(ts)
        excel_entry.append(raw_ip_to_string(ip.src))
        excel_entry.append(raw_ip_to_string(ip.dst))

        if hasattr(eth,'tag'):
            excel_entry.append(eth.tag)
            if eth.tag in vlan_dict:
                vlan_dict[eth.tag] += 1
            else: vlan_dict[eth.tag] = 1
        else:
            excel_entry.append('None')

        packet_sizes.append(ip.len)
        excel_entry.append(ip.len)

        allowed_frame_types = {
            dpkt.ip.IP_PROTO_TCP:'TCP',
            dpkt.ip.IP_PROTO_UDP:'UDP',
            dpkt.ip.IP_PROTO_ICMP:'ICMP',
        }

        if ip.p in list(allowed_frame_types.keys()):
            excel_entry.append(allowed_frame_types[ip.p])
            l4_proto = ip.data
            if ip.p in (dpkt.ip.IP_PROTO_TCP,dpkt.ip.IP_PROTO_UDP):
                excel_entry.append(l4_proto.sport)
                excel_entry.append(l4_proto.dport)
            else:
                excel_entry.append('N/A')
                excel_entry.append('N/A')
        else:
            excel_entry.append('Other')
            excel_entry.append('N/A')
            excel_entry.append('N/A')
        write_excel_row(sheet,ip_count,excel_entry)
        last_ts = ts

    print('=')
    print('Saving Excel file...')
    workbook.close()
    print('Excel packet flow saved as: {}'.format(filename))

    print('*** Flow Information ***')
    print('* Total Packets: {} IP Packets: {} Non-IP Packets: {}'.format(packet_count,ip_count,packet_count-ip_count))
    print('* Capture Time: {:0.2f} seconds'.format(last_ts-first_ts))
    print('* Max Packet Size: {} bytes'.format(max(packet_sizes)))
    print('* Min Packet Size: {} bytes'.format(min(packet_sizes)))
    print('* Average Capture Data rate: {:0.2f} pps'.format(packet_count/(last_ts-first_ts)))
    print('* VLAN Count: {}'.format(len(vlan_dict)))

    throughput_bytes = (sum(packet_sizes)/(last_ts-first_ts))
    throughput_value = -1

    byte_strings = ['','k','m','g','t']
    current_ordinal_index = -1

    for scale, ordinal in enumerate(byte_strings,1):
        if throughput_bytes*8 < (1000**scale):
            current_ordinal_index = scale-1
            throughput_value = throughput_bytes*8 / (1000**(scale-1))
            break

    print('* Average throughput: {bytes:0.2f} {ordinal}bytes/s or {bits:0.2f} {ordinal}bit/s (ONLY INCLUDES IP PACKETS!)'.format(bits=throughput_value,bytes=throughput_value/8,ordinal=byte_strings[current_ordinal_index]))

    print('** Packet Size Distribution:')
    packet_size_distribution = [0,64,128,256,512,1024,1280,1518,2112,9000]

    for idx,size in enumerate(packet_size_distribution):
        if size == 0: continue
        count = sum(map(lambda x: x<=size and x>packet_size_distribution[idx-1],packet_sizes))
        print(' <={} bytes: {}'.format(size,count))
    print('Warning: Very large packet sizes indicate IP fragmentation.')

if __name__ == "__main__":
    main()