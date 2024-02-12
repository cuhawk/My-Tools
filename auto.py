#!/usr/bin/env python

import os
import re
import sys
import argparse
import subprocess
import logging

protocol_ports = {
    'SMB': ['139', '445'],
    'FTP': ['21'],
    'HTTP': ['80', '443', '5000', '8000', '8080'],
    'WINRM': ['5985', '5986'],
    'RDP': ['3389'],
    'SSH': ['22', '2222'],
    'MYSQL': ['3306'],
    'MSSQL': ['1433'],
    'AD': ['53', '88', '389'],
    'NFS_RPC': ['111', '135', '635', '2049'],
    'EMAIL': ['25', '110', '995', '26', '143', '993', '587'],
    'WEBHOST': ['2082', '2083', '2086', '2087', '2095', '2096', '2097', '2098']
}

all_ports = ','.join({port for ports in protocol_ports.values() for port in ports})

def setup_logging():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename='../../Documents/scanning_automator.log',
                        filemode='a')
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logging.getLogger('').addHandler(console_handler)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Scanning Automator')
    parser.add_argument('input_file', help='Path to the input IP file')
    return parser.parse_args()

def live_nmap_output(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        while True:
            output = process.stdout.readline()
            if output == b'' and process.poll() is not None:
                break
            if output:
                logging.info(output.strip().decode('UTF-8'))
        rc = process.poll()
        return rc
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e}")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

def nmap_scans(file_path, new_directory):
    if not os.path.exists(new_directory + "/scan.txt"):
        nmap_cmd = f"nmap --max-rate 300 -open -iL {file_path} -oN {new_directory}/scan.txt -vvv"
        live_nmap_output(nmap_cmd)

    try:
        ip_protocol_ports = {}
        with open(new_directory + '/scan.txt', 'r') as file:
            lines = file.readlines()

            ip = ''
            ports = []
            for line in lines:
                if 'Nmap scan report for' in line:
                    ip = re.search(r'Nmap scan report for (.*)', line).group(1)
                    ports = []
                elif re.match(r'^([0-9]+)/tcp', line):
                    ports.append(re.search(r'^([0-9]+)/tcp', line).group(1))
                elif line.strip() == '' and ports:
                    ports_str = ','.join(ports)
                    ip_file_path = new_directory + "/" + ip + ".txt"
                    if not os.path.exists(ip_file_path):
                        nmap_cmd_two = f"nmap --max-rate 300 -sCV -p{ports_str} {ip} -oN {new_directory}/{ip}.txt"
                        live_nmap_output(nmap_cmd_two)
                    ports = []

        current_ip = ''
        for line in lines:
            if "Nmap scan report for" in line:
                current_ip = line.split()[-1]
                ip_protocol_ports[current_ip] = {protocol: [] for protocol in protocol_ports}
            port_line_match = re.match(r"(\d+)/tcp\s+open", line)
            if port_line_match:
                port = port_line_match.group(1)
                for protocol, ports in protocol_ports.items():
                    if port in ports:
                        ip_protocol_ports[current_ip][protocol].append(port)

        for protocol in protocol_ports:
            with open(f"{new_directory}/{protocol}_ports_open.txt", 'w') as outfile:
                for ip, protocols in ip_protocol_ports.items():
                    ports = protocols[protocol]
                    if ports:
                        outfile.write(f"{ip}: {', '.join(ports)}\n")

    except FileNotFoundError:
        logging.error(f"File not found: {new_directory}/scan.txt")
    except Exception as e:
        logging.error(f"An error occurred while processing the scan results: {e}")

def main():
    setup_logging()
    try:
        args = parse_arguments()
        file_path = args.input_file

        if not os.path.isfile(file_path):
            logging.error(f"The specified input file does not exist: {file_path}")
            sys.exit(1)

        logging.info(f"Starting scan for file: {file_path}")

        filename = os.path.basename(file_path)
        directory = os.path.dirname(file_path)
        new_filename = f"{filename.rsplit('.', 1)[0]}_scan"
        new_directory = os.path.join(directory, new_filename, "nmap")

        os.makedirs(new_directory, exist_ok=True)

        nmap_scans(file_path, new_directory)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
