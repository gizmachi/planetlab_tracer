#!/usr/bin/python2.7

# Authon: Josef Gustafsson
# Support: josgu898@student.liu.se

# OS tools needed:
# openssl, whois, scamper
# scamper needs to run as root. (uses raw sockets)

import os
# import argparse
import cPickle as pickle
import numpy as np
import multiprocessing
import time
import math
import socket
import string
# from M2Crypto import SSL, RSA

# Some filenames and directories
targets_dir = "targets/"
output_dir = "output/"
certs_dir = output_dir + "cert/"
topsites_filename = "topsites.txt"
geoasn_filename = "geoasn.pickles"
topips_filename = "topips.txt"
output_filename = "traces2.txt"


# GLOBAL
on_pl = True
as_map = {}


# All relevant info for a single target domain
class Website:
    def __init__(self, url, rank):
        self.url = url
        self.rank = rank
        self.source = str(socket.gethostbyname(socket.gethostname()))
        self.ssl = None

        self.cert_keylength = None
        self.cert_ca = None
        self.cert_subject = None
        self.cert_san = None
        self.cert_fingerprint = None
        self.cert_valid = None
        self.cert_sign_algo = None
        self.cert_pubkey_algo = None
        self.cert_version = None
        self.cert_not_before = None
        self.cert_not_after = None

        self.cipher_suites = None

        self.http_ip = None
        self.http_path_ip = None
        self.http_path_as = None
        self.http_path_country = None

        self.https_ip = None
        self.https_path_ip = None
        self.https_path_as = None
        self.https_path_country = None


    def __str__(self):
        delim = '|'
        return str(self.rank) \
               + delim + str(self.url) \
               + delim + str(self.http_ip) \
               + delim + str(self.http_path_ip) \
               + delim + str(self.http_path_as) \
               + delim + str(self.http_path_country) \
               + delim + str(self.ssl) \
               + delim + str(self.cert_valid) \
               + delim + str(self.cert_version) \
               + delim + str(self.cert_not_before) \
               + delim + str(self.cert_not_after) \
               + delim + str(self.cert_sign_algo) \
               + delim + str(self.cert_pubkey_algo) \
               + delim + str(self.cert_keylength) \
               + delim + str(self.cert_ca) \
               + delim + str(self.cert_subject) \
               + delim + str(self.cert_san) \
               + delim + str(self.cert_fingerprint) \
               + delim + str(self.cipher_suites)


# Create the necessary folder structure
def setupFolders(clean):
    # Create certs folder if not exists
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)

    # Create targets folder if not exists
    if not os.path.exists(targets_dir):
        os.makedirs(targets_dir)

    # Create output folder if not exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Remove aux files, will be recreated later if needed
    if clean:
        if os.path.exists(targets_dir + '/' + topsites_filename):
            os.remove(targets_dir + '/' + topsites_filename)

        if os.path.exists(targets_dir + '/' + nossl_filename):
            os.remove(targets_dir + '/' + nossl_filename)

        if os.path.exists(targets_dir + '/' + topip_filename):
            os.remove(targets_dir + '/' + topip_filename)

def set_country_path(targets):
    # if os.path.exists(targets_dir + geoasn_filename):
    #     geoasn = pickle.load(open(targets_dir + geoasn_filename, "rb"))
    # else:
    geoasn = {}

    for t in targets:
        if t.http_ip is not None:
            cp = []
            if t.http_path_as is not None:
                for asn in t.http_path_as:
                    try:
                        country = geoasn[asn]
                    except:
                        stream = os.popen('whois -h whois.cymru.com AS' + asn)
                        for i in range(3):
                            tmp = stream.readline() # Ignore lines of header output.
                            # print tmp
                        try:        
                            tmp = stream.readline()
                            # print tmp 
                            geoasn[asn] = tmp.split(',')[-1][:-1]
                        except:
                            geoasn[asn] = "XX"          
                        country = geoasn[asn]

                    if len(cp) == 0 or country != cp[-1]:
                        cp.append(country)
                t.http_path_country = cp

        # # Redo for https
        # if t.https_ip is not None:
        #     cp = []
        #     if t.https_path_as is not None:
        #         for asn in t.https_path_as:
        #             try:
        #                 country = geoasn[asn]
        #             except:
        #                 stream = os.popen('whois -h whois.cymru.com AS' + asn)
        #                 for i in range(2):
        #                     stream.readline() # Ignore lines of header output.
        #                 try:        
        #                     cc = stream.readline().split()[0]
        #                     geoasn[asn] = cc          
        #                 except:
        #                     geoasn[asn] = "XX"          
        #                 country = geoasn[asn]

        #             #TODO != cp[-1]
        #             if len(cp) == 0 or country != cp[-1]:
        #                 cp.append(country)
        #         t.https_path_country = cp

    pickle.dump(geoasn, open(targets_dir + geoasn_filename, "wb"))

def getASpath(IPpath):
    # Translate IP path to AS path
    ASpath = []
    for line in IPpath:
        address = line[0]
        # Ignore private IPs
        # TODO ignore 172.16 - 172.31
        if address[:7] != "192.168" \
            and address[:3] != "10." \
            and address[:4] != "127." \
            and address != '*':
            # Count looked up IPs
            AS = lookupAS(address)
            for item in AS:
                if item is not None and item != 'NA':
                    if len(ASpath) == 0 or item != ASpath[-1]:
                        ASpath.append(item)
    return ASpath

def lookupAS(address):
    # Map an IP address to an AS
    global as_map
    AS = []
    # statistics["stat_aslookup"] += 1

    if address in as_map:
        AS.append(as_map[address])
        # statistics["stat_aslookup_failed"] += 1
    else:
        # cymru gives better replies than regular whois
        stream = os.popen('whois -h whois.cymru.com ' + address)
        if on_pl:
            headerlines = 3
        else:
            headerlines = 1

        for i in range(headerlines):
            stream.readline() # Ignore lines of header output.
        while True:
            try:        
                # Read AS from whois info
                tmp = stream.readline().split()[0]
                if tmp != "NA":
                    # print "Mapped " + str(address) + " to AS" + str(tmp)
                    AS.append(tmp)
                    as_map[address] = tmp
            except:
                break        
    return AS

def set_traces(targets):
    # Scamper needs an input file. Create tmp files of IP addresses for http/https
    print "Running traces..."
    ips = []
    mapping = {}

    if os.path.exists(targets_dir + topips_filename):
            os.remove(targets_dir + topips_filename)
            
    # Trace for HTTP
    for t in targets:
        if t.http_ip is not None:
            ips.append(t.http_ip)
            mapping[t.http_ip] = t

    writefile(targets_dir + topips_filename, ips)

    scamperTrace(mapping)
    os.remove(targets_dir + '/' + topips_filename)

    set_country_path(targets)
    
    # # Redo for HTTPS
    # for t in targets:
    #     if t.https_ip is not None:
    #         ips.append(t.https_ip)
    #         mapping[t.https_ip] = t

    # writefile(targets_dir + topips_filename, ips)

    # scamperTrace(mapping)
    # os.remove(targets_dir + '/' + topips_filename)

def set_ssl(targets):
    for t in targets:
        if t.https_ip is not None:
            if downloadCert(t):
                t.ssl = True
                set_ssl_properties(t)
            else:
                t.ssl = False

def set_ssl_properties(target):
    filename = certs_dir + target.url + '.pem'

    stream = os.popen('openssl x509 -fingerprint -in ' + filename + ' -text -noout')

    prev = ""
    line = ""

    while True:
        prev = line
        line = stream.readline()[:-1]
        if line == "" and prev == "":
            break
        # print line


        if "Version" in line:
            try:
                # print line.split(": ")[1]
                target.cert_version = line.split(": ")[1]
            except:
                pass

        if "Not Before" in line:
            try:
                # print line.split(": ")[1]
                target.cert_not_before = line.split(": ")[1]
            except:
                pass

        if "Not After" in line:
            try:
                target.cert_not_after = line.split(": ")[1]
                # print line.split(": ")[1]
            except:
                pass

        if "Subject:" in line:
            # print line.split("CN=")[1]
            try:
                target.cert_subject = line.split("CN=")[1]
            except:
                pass

        if "Issuer:" in line:
            # print line.split("CN=")[1]
            try:
                target.cert_ca = line.split("CN=")[1]
            except:
                pass

        if "Subject Alternative Name" in prev:
            # print line.lstrip()
            try:
                target.cert_san = line.lstrip()
            except:
                pass

        if "SHA1 Fingerprint" in line:
            # print line.split('=')[1].translate(None, ':')
            try:
                target.cert_fingerprint = line.split('=')[1].translate(string.maketrans('', ''), '!@#$')
            except:
                pass

        if "Signature Algorithm" in line:
            # print line.split(':')[1][1:]
            try:
                target.cert_sign_algo = line.split(':')[1][1:]
            except:
                pass

        if "Public Key Algorithm" in line:
            # print line.split(':')[1][1:]
            try:
                target.cert_pubkey_algo = line.split(':')[1][1:]
            except:
                pass

        if "Public-Key" in line:
            # print line.split(':')[1][2:-5]
            try:
                target.cert_keylength = line.split(':')[1][2:-5]   
            except:
                pass

        # Check validation code from file
        for l in open(filename,'r+').readlines():
            if "Verify return code:" in l:
                try:
                    target.cert_valid = l.split(':')[-1][:-1]
                except:
                    pass
                    # print line.split()[-1]
 
def set_ciphers(targets):
    for t in targets:
        if t.http_ip is not None:
            print "Testing supported cipher suites for " + t.http_ip
        else:
            print "No IP set for " + t.url
            return
        try:
            stream = os.popen('nmap --script ssl-enum-ciphers -p 443 ' + t.http_ip)

            for i in range(7):
                line = stream.readline()

            prev_line = None
            current_suit_list = []
            current_suit = None
            suites = {}
            while True:
                prev_line = line
                line = stream.readline()

                # Done
                if len(line) > 10 and line[:10] == "Nmap done:":
                #     print "Done."
                    break

                line = line[:-1].split()
                if len(line) > 1:

                    if line[1] == "NULL":
                        pass
                    elif line[1] == "ciphers:":
                        current_suit = prev_line[1]
                        current_suit_list = []

                        line = stream.readline().split()
                        while line[1] != "compressors:":
                            current_suit_list.append(line[1])
                            line = stream.readline().split()
                        suites[current_suit] = current_suit_list

            # print suites
            t.cipher_suites = suites
            # Do something
        except:
            print "Ooops..."

def scamperTrace(mapping):
    # Run all traces using scamper

    # flag -O planetlab is required for using planerlab raw sockets
    # -c specifies command for each target
    #     -g 15 increases the acceptable number of dropped probes
    #     -P ICMP uses ICMP style tracing. No paris.
    #     -f read targets from file 
    #     -p 1000 limit the number of packets per second
    if on_pl:
        stream = os.popen('./scamper/scamper -O planetlab -c "trace -g 15 -P icmp " -f -p 1000 ' + targets_dir + '/' + topips_filename)
    else:
        stream = os.popen('scamper -O planetlab -c "trace -g 15 -P icmp " -f -p 1000 ' + targets_dir + '/' + topips_filename)
    # traces = {}             # Completed traces
    current = []            # Current trace
    current_target = "" 
    counter = 0

    # This is the IP of the PL node
    host_ip = str(socket.gethostbyname(socket.gethostname()))

    # PARSER
    # Loop over output
    while True:
        line = stream.readline().split()

        # Empty line, that means last trace complete.
        # Translate IP path to AS path and add to traces
        if line == []:
            if current_target != "":
                aspath = getASpath(current)
                mapping[current_target].http_path_as = aspath
                mapping[current_target].http_path_ip = current

                counter += 1
                print str(counter) + "/" + str(len(targets)) + ": Traced " + current_target + ": " + str(aspath)
            else:
                print "No trace output!"

            break

        # Start of a new trace. (that means prev. complete)
        # Translate IP path to AS path and add to traces
        if line[0] == 'traceroute':
            if current != []:
                aspath = getASpath(current)

                mapping[current_target].http_path_as = aspath
                mapping[current_target].http_path_ip = current

                counter += 1
                print str(counter) + "/" + str(len(targets)) + ": Traced " + current_target + ": " + str(aspath)                
                
                # Reset current path.
                current = []
            # Set new target
            current_target = line[4]

        # The line is a hop in some trace. Add it to current path (if not *)
        elif line[1] != '*':
            # print line
            current.append((line[1], line[2] + line[3]))

def set_url2ip(targets):
    # Lookup all ips
    print "resolving IP addresses of all targets"
    target_ips = []
    for t in targets:
        try:
            ip = socket.gethostbyname(t.url)
            print ip
            t.http_ip = ip
            # TODO include https
            t.https_ip = ip
        except:
            pass

def writefile(filename, content):
    if os.path.exists(filename):
        os.remove(filename)

    f = open(filename,'a+')
    for line in content:
        f.write(str(line) + '\n')
    f.close()

def readfile(filename, maxLen = 1000000):
    lines = []
    count = 0

    if os.path.exists(filename):
        for line in open(filename,'r+').readlines():
        # with open(filename, 'r+') as f:
        #     for line in f:
                # Optional max length
                if count >= maxLen:
                    break
                else:
                    count += 1
                # add to list, remove newline at end of line.
                lines.append(line[:-1])
    return lines

def downloadCert(target):
    # Use threading to implement timeout
    # TODO include client identifier in filename
    # Download cert using openssl
    site = target.url
    print "Downloading cert for ",site
    force = False
    p = multiprocessing.Process(target=runOpenssl, args=(site, force))
    p.start()
    p.join(6)

    if p.is_alive():
        p.terminate()
        p.join()

    # If no cert downloaded, remove empy file and add to no-ssl list
    if os.stat(certs_dir + site + '.pem').st_size == 0:
        print "No SSL cert found for " + site
        os.remove(certs_dir + '/' + site + '.pem')
        return False # Download failed
    return True # Download successful

def runOpenssl(site, force):
    # Separate funktion to be used with threading        
    # Saves 0 byte cert if not ssl enabled, removed by calling function
    cert_path = certs_dir + site + '.pem'
    os.popen('openssl s_client -CApath /etc/ssl/certs/ -showcerts -connect ' + site + \
    # os.popen('openssl s_client -CApath /etc/ssl/certs/ -showcerts -x509_strict -connect ' + site + \
        ':443 </dev/null 2>/dev/null > ' + cert_path)

def gen_log_space(limit, n):
    # Create a vector of n logarithmmically spaced indices from 0 to limit.
    result = [1]
    if n>1:  # just a check to avoid ZeroDivisionError
        ratio = (float(limit)/result[-1]) ** (1.0/(n-len(result)))
    while len(result)<n:
        next_value = result[-1]*ratio
        if next_value - result[-1] >= 1:
            # safe zone. next_value will be a different integer
            result.append(next_value)
        else:
            # problem! same integer. we need to find next_value by artificially incrementing previous value
            result.append(result[-1]+1)
            # recalculate the ratio so that the remaining values will scale correctly
            ratio = (float(limit)/result[-1]) ** (1.0/(n-len(result)))
    # round, re-adjust to 0 indexing (i.e. minus 1) and return np.uint64 array
    return np.array(map(lambda x: round(x)-1, result), dtype=np.uint64)
    


### MAIN
if __name__ == "__main__":
    # Set starttime
    nr_of_targets = 10000

    start_time = time.time()

    # read targets from file
    tmp_targets = readfile(targets_dir + topsites_filename)
    
    # Create logarithmically spaced vector of sample indices
    logspace = gen_log_space(len(tmp_targets), nr_of_targets)
    
    targets = []
    for i in range(len(tmp_targets)):
        if i in logspace:
            targets.append(Website(tmp_targets[i], i + 1))

    tmp_targets = []

    set_url2ip(targets)

    # Download certs:
    set_ssl(targets)
    
    # Check supported cipher suites
    # set_ciphers(targets)

    # perform traces
    set_traces(targets)

    # Set runtime in statistics
    runtime = time.time() - start_time
    print "Completed run in " + str(int(math.floor(runtime/60))) \
        + "m " + str(int(runtime % 60)) + "s."

    writefile(output_dir + output_filename, targets)
    






