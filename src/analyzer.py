#!/usr/bin/python

# This program reads all data gathered from PlanetLab and analyses the results
# The program is intended to run on the infosec server.

###########################################
### DATA FORMAT CHANGED, MAY NOT WORK!! ###
###########################################


import os
import cPickle as pickle
import urllib

# Directory containing data folders for each PL node
data_dir = "/home/josgu898/tddd17_project/data"
output_dir = "/home/josgu898/tddd17_project/plots/data"

def load(nodename):
    # Read pickles files from one PL node
    stats = pickle.load(open(data_dir + "/" + nodename + "/stats.pickles", "rb"))
    traces = pickle.load(open(data_dir + "/" + nodename + "/traces.pickles", "rb"))
    return traces, stats

def geoip(address):
    # Lookup geolocation of IP address
    # Parse responce and return country code
    response = urllib.urlopen('http://api.hostip.info/get_html.php?ip=' + address + '&position=true').read()
    return response.split('\n')[0].split()[-1][1:-1]
    # return response

def geoas(asn):
    # cymru gives better replies than regular whois

    stream = os.popen('whois -ch whois.cymru.com AS' + asn)
    for i in range(2):
        stream.readline() # Ignore lines of header output.
    try:        
        cc = stream.readline().split()[0]
        return cc           
    except:
        return "XX"

def printdict(dic, lines=0, t=0):
    # Destructive method, make temp copy
    d = dic

    # Total can be provided if sum is not correct total
    # i.e. trace dicts have overlaps, many ases from same trace -> sum not correct
    if t != 0:
        total = t
    else:
        total = 0
        for item in d:
            total += d[item]

    # Nummber of lines to print, 0 = unlimited
    if lines == 0:
        lc = len(dic)
    else:
        lc = lines

    for i in range(lc):
        mc = most_common(d)
        print str(mc) + ": " + str(d[mc]) \
                + ", " + str(int(100*float(d[mc])/float(total))) + "%"
        del d[mc]


def most_common(dic):
    res = "failed"
    count = 0	
    for line in dic:
        if dic[line] > count:
            res = line
            count = dic[line]
    return res

def sum_dict(dic):
    s = 0
    for item in dic:
        s += dic[item]
    return s

def mean_list(l):
    total = 0
    count = 0
    for i in range(len(l)):
        count += l[i]
        total += i*l[i]
    return float(total)/float(count)


def country_path(aspath, geoasn):
    cp = []
    for asn in aspath:
        try:
            country = geoasn[asn]
        except:
            print "Failed to resolve country for " + asn
        if country not in cp:
            cp.append(country)
    return cp

def write_aspath(with_incomplete, without_incomplete):
    filename =  output_dir + "/asPathlengthData.txt"
    print "writing " + filename
    if os.path.exists(filename):
        os.remove(filename)
    f = open(filename,'w')

    f.write("Serial All Complete\n")
    for i in range(len(with_incomplete)):
        f.write(str(i) + " " + str(with_incomplete[i]) + " " + str(without_incomplete[i]) + '\n')
    f.close()

def write_countrypath(with_incomplete, without_incomplete):
    filename =  output_dir + "/countryPathlengthData.txt"
    print "writing " + filename
    if os.path.exists(filename):
        os.remove(filename)
    f = open(filename,'w')

    f.write("Serial All Complete\n")
    for i in range(len(with_incomplete)):
        f.write(str(i) + " " + str(with_incomplete[i]) + " " + str(without_incomplete[i]) + '\n')
    f.close()

def write_ascount(asdict):
    filename =  output_dir + "/ascountData.txt"
    print "writing " + filename
    if os.path.exists(filename):
        os.remove(filename)
    f = open(filename,'w')

    # convert from dict to list
    ascount = []
    for item in asdict:
        ascount.append(asdict[item])
    ascount.sort(reverse=True)

    f.write("Serial ASN Count\n")
    for i in range(len(ascount)):
        f.write(str(i) + " " + str(ascount[i]) + '\n')
    f.close()

def write_countrycount(asdict):
    filename =  output_dir + "/countrycountData.txt"
    print "writing " + filename
    if os.path.exists(filename):
        os.remove(filename)
    f = open(filename,'w')

    # convert from dict to list
    ascount = []
    for item in asdict:
        ascount.append(asdict[item])
    ascount.sort(reverse=True)

    f.write("Serial Country Count\n")
    for i in range(len(ascount)):
        f.write(str(i) + " " + str(ascount[i]) + '\n')
    f.close()



if __name__ == "__main__":
    nodes = []
    nodes = os.listdir(data_dir)
    all_traces = []
    all_stats = []
    count = 0
    geoasn = pickle.load(open(data_dir + "/geoasn.pickles", "rb"))

    check_traces = True         # Aggregated PATH data
    lookup_nodes = False        # Geographical location of PL nodes
    aggregate_stats = True      # Path lengths etc...
    write_data_files = False    # Write files for drawing diagrams

    # Read all data into memory 
    for n in nodes:
        try:
            t, s = load(n)
            count += 1
            all_traces.append(t)
            all_stats.append(s)
        except:
            pass

    print "Total " + str(len(nodes)) + " nodes. Loaded data from " + str(count) + " nodes."
    print "Analyzing data..."

    # PlanetLab nodes by country
    countries = {}
    if lookup_nodes:
        for t in all_traces:
            try:
                country = geoip(t[t.keys()[0]][0])
                if country not in countries:
                    countries[country] = 1
                else:
                    countries[country] += 1
            except:
                pass

        print "\nPlanetLab Nodes by country:"
        printdict(countries)


    # Total number of traces
    total_traces = 0
    total_traces_correct = 0
    total_addr = 0
    total_ssl = 0

    if aggregate_stats:
        # Count traces that terminate correctly
        for t in all_traces:
            total_traces += len(t)
            for line in t:
                if line == t[line][-1]:
                    total_traces_correct += 1

        print "\n" + str(total_traces_correct) + " of " + str(total_traces) \
              + " traces terminated correctly. ("\
              +  str(int(100*float(total_traces_correct)/float(total_traces))) + '%)'

        # Count SSL enabled sites
        for s in all_stats:
            total_addr += s["stat_ip_targets"]
            total_ssl += s["stat_ssl_targets"]

        print str(total_ssl) + " of " + str(total_addr) \
              + " sites accessible via HTTPS. ("\
              +  str(int(100*float(total_ssl)/float(total_addr))) + '%)'
        
        as_path_len = []
        as_path_len_all = []
        country_path_len = []
        country_path_len_all = []

        # Count AS/country path length
        for t in all_traces:
            for line in t:
                aspath = t[line][1]
                cpath = country_path(aspath, geoasn)
                #if "RU" in cpath and "RU" != cpath[-1]:
                #    print cpath, t[line][0], t[line][2]

                # AS path length
                while len(as_path_len_all) <= len(aspath):
                    as_path_len_all.append(0)
                as_path_len_all[len(aspath)] += 1

                # Country path length
                while len(country_path_len_all) <= len(cpath):
                    country_path_len_all.append(0)
                country_path_len_all[len(cpath)] += 1

                if line == t[line][-1]:
                    # AS path length (correct)
                    while len(as_path_len) <= len(aspath):
                        as_path_len.append(0)
                    as_path_len[len(aspath)] += 1

                    # Country path length (correct)
                    while len(country_path_len) <= len(cpath):
                        country_path_len.append(0)
                    country_path_len[len(cpath)] += 1
                   

        print "AS Path lengths: " + str(as_path_len) \
                + ", average: " + str(mean_list(as_path_len))
        print "AS Path lengths (all): " + str(as_path_len_all) \
                + ", average: " + str(mean_list(as_path_len_all))
        print "Country Path lengths: " + str(country_path_len) \
                + ", average: " + str(mean_list(country_path_len))
        print "Country Path lengths (all): " + str(country_path_len_all) \
                + ", average: " + str(mean_list(country_path_len_all))

        if write_data_files:
            write_aspath(country_path_len_all, as_path_len)
            write_countrypath(country_path_len_all, as_path_len)


    # AS counting
    total_as = {}
    total_as_noduplicate = {}
    total_transit = {}
    total_transit_noduplicate = {}
    total_country = {}
    total_transit_country = {}
    total_country_noduplicate = {}
    total_transit_country_noduplicate = {}
    include_failed = False

    if check_traces:
        for t in all_traces:
            as_from_node = []
            transit_from_node = []
            country_from_node = []
            transit_country_from_node = []
            for line in t:
                if line == t[line][-1] or include_failed:
                    
                    cp = country_path(t[line][1], geoasn)
                    for country in cp:
                        # Count Countries
                        if country not in total_country:
                            total_country[country] = 1
                        else:
                            total_country[country] += 1

                        if country not in country_from_node:
                            country_from_node.append(country)

                        # Count Transits countries
                        if not country == cp[0] and not country == cp[-1]:
                            if country not in total_transit_country:
                                total_transit_country[country] = 1
                            else:
                                total_transit_country[country] += 1
        
                            if country not in transit_country_from_node:
                                transit_country_from_node.append(country)



                    for asn in t[line][1]:

                        # Count all ASes
                        if asn not in total_as:
                            total_as[asn] = 1
                        else:
                            total_as[asn] += 1

                        if asn not in as_from_node:
                            as_from_node.append(asn)


                        # Count Transits
                        if not asn == t[line][1][0] and not asn == t[line][1][-1]:
                            if asn not in total_transit:
                                total_transit[asn] = 1
                            else:
                                total_transit[asn] += 1
        
                            if asn not in transit_from_node:
                                transit_from_node.append(asn)



            for asn in as_from_node:
                # All ASes
                if asn not in total_as_noduplicate:
                    total_as_noduplicate[asn] = 1
                else:
                    total_as_noduplicate[asn] += 1

            for asn in transit_from_node:
                # Transits
                if asn not in total_transit_noduplicate:
                    total_transit_noduplicate[asn] = 1
                else:
                    total_transit_noduplicate[asn] += 1

            for country in country_from_node:
                # Transits
                if country not in total_country_noduplicate:
                    total_country_noduplicate[country] = 1
                else:
                    total_country_noduplicate[country] += 1

            for country in transit_country_from_node:
                # Transits
                if country not in total_transit_country_noduplicate:
                    total_transit_country_noduplicate[country] = 1
                else:
                    total_transit_country_noduplicate[country] += 1

        
        if write_data_files:
            write_ascount(total_as)
            write_countrycount(total_country)

        if include_failed:
            total = total_traces
        else:
            total = total_traces_correct


        print "Total ASes: " + str(len(total_as))
        print "Total Transit ASes: " + str(len(total_transit))
        print "Total Countries: " + str(len(total_country))
        print "Total Transit Countries: " + str(len(total_transit_country))

        print "Total AS occurances: " + str(sum_dict(total_as))
        print "Total AS transit occurances: " + str(sum_dict(total_transit))
        print "Total Countries occurances: " + str(sum_dict(total_country))
        print "Total Transit Countries occurances: " + str(sum_dict(total_transit_country))

        print "Total AS count (no duplicate): " + str(sum_dict(total_as_noduplicate))
        print "Total AS transit count (no duplicate): " + str(sum_dict(total_transit_noduplicate))
        print "Total Countries (no duplicate): " + str(sum_dict(total_country_noduplicate))
        print "Total Transit Countries (no duplicate): " + str(sum_dict(total_transit_country_noduplicate))


        lines_to_print = 10
        print "\nNumber of occurances for most common ASes:"
        printdict(total_as, lines_to_print, total)

        print "\nNumber of occurances for most common ASes (each node counted once):"
        printdict(total_as_noduplicate, lines_to_print, 24)

        print "\nNumber of occurances for Transit ASes:"
        printdict(total_transit, lines_to_print, total)

        print "\nNumber of occurances for Transit ASes (each node counted once):"
        printdict(total_transit_noduplicate, lines_to_print, 24)

        print "\nNumber of occurances for Countries:"
        printdict(total_country, lines_to_print, total)

        print "\nNumber of occurances for Countries (each node counted once):"
        printdict(total_country_noduplicate, lines_to_print, 24)

        print "\nNumber of occurances for Transit Countries:"
        printdict(total_transit_country, lines_to_print, total)

        print "\nNumber of occurances for Transit Countries (each node counted once):"
        printdict(total_transit_country_noduplicate, lines_to_print, 24)

#        for t in all_traces:
#            for line in t:
#                print line, t[line]

    print "\nDone!"



