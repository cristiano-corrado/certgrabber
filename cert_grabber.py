# -*- encoding: utf-8 -*-
# requires a recent enough python with idna support in socket
# pyopenssl, cryptography and idna
from utils.nmap import PortScanner,PortScannerAsync
import os
import sys
import ipaddress 
from utils.threads import ThreadPool, Lock
from utils.db import Datastore
from utils.logger import logging
from utils.tls_scanner_wrap import tls_scan
from datetime import datetime
from utils.which import which


counter = ''
db = Datastore() 
date = datetime.now()
if db.exists() == 0:
    db.create_table()

pool = ThreadPool(30)

def callback_results(host,scan_results):
    '''
    Where all the magic happens, checks results from nmap_scan and stores information in db when port open
    '''
    nmap=scan_results['nmap']
    port = nmap['scaninfo']['tcp']['services']
    scan = scan_results['scan']
    state=scan[host]['tcp'][int(port)]['state']

    if state == 'open' :
        logging.info('[NMAP-{}] Host {} open!'.format(port,host))
        
        tls_scanner_output = tls_scan(host,port)
        
        if tls_scanner_output :
            
            tls_version=tls_scanner_output['tlsVersion']
            secure_renegotiation=tls_scanner_output['secureRenego']
            tls_supported=tls_scanner_output['tlsVersions']
            for certchain in range(len(tls_scanner_output['certificateChain'])):
                if certchain == 0:
                    try:
                        subjectCN = tls_scanner_output['certificateChain'][0]['subjectCN']
                    except   KeyError as e :  
                        if 'subjectCN' in str(e):
                            subjectCN = "None"
                    try:
                        subjectAltName = tls_scanner_output['certificateChain'][0]['subjectAltName']
                    except KeyError as e :
                        if 'subjectAltName' in str(e):
                            subjectAltName = "None"
                    try:
                        pubkeysize=tls_scanner_output['certificateChain'][0]['publicKeySize']
                    except KeyError as e :    
                        if 'pubkeysize' in str(e):
                            pubkeysize = "None"
                    try:
                        expired = tls_scanner_output['certificateChain'][0]['expired']
                    except KeyError as e :
                        if 'expired' in str(e):
                            expired = "None"

                    try:    
                        cert_valid =  tls_scanner_output['verifyCertResult']
                    except KeyError as e:
                        if 'cert_valid' in str(e):
                            cert_valid = "None"

                    try:
                        subject = tls_scanner_output['certificateChain'][0]['subject']
                    except KeyError as e :
                        if 'subject' in str(e):
                            subject = "None"
                    try:
                        issuer =  tls_scanner_output['certificateChain'][0]['issuer']
                    except KeyError as e :
                        if 'issuer' in str(e):
                            issuer = "None"
                    try:
                        notAfter = tls_scanner_output['certificateChain'][0]['notAfter']
                    except KeyError as e :
                        if 'notAfter' in str(e):
                            notAfter = "None"
                    try:
                        signatureAlg = tls_scanner_output['certificateChain'][0]['signatureAlg']
                    except KeyError as e :
                        if 'signatureAlg' in str(e):
                            signatureAlg = "None"

                id = len(db.getdata().fetchall())
                id += 1
                logging.info("[COUNTER] There are other {} hosts to complete".format(counter))
                db.insert(id,host,port,tls_version,secure_renegotiation,tls_supported,issuer,subject,subjectCN,subjectAltName,pubkeysize,expired,notAfter,cert_valid,signatureAlg)
                db.commit()
        else:
            with open('failed-hosts.txt','a') as failed:
                logging.critical("[TLSSCANNER] check the host {} results of report was empty. Logged host to file failed-hosts.txt".format(host))
                failed.write("{}\n".format(host))                    
            
def nmap_scan(ip,port):
    '''
    Nmap Portscan passflags assume port 443 open can be changed in future
    '''
    nmap_flags = "-sS -n -Pn -T4 --max-retries 1"
    nm = PortScannerAsync()
    try:
        nm.scan(ip,port,nmap_flags,sudo=True,callback=callback_results)
        while nm.still_scanning():
            nm.wait(1)
    except KeyboardInterrupt:
        nm.stop()
    
def map_hosts(filename) :
    '''
    reads ip from file created on ip.urand0m.com and stores in memory, then cleans and rewrites it with ip per line 
    '''

    MAP_HOSTS = []

    with open(filename,'r') as scanfile:
        split=scanfile.readlines()   
        if ',' in split[0]:    
            with open(filename,'w') as scanfile:
                for ip in split[0].split(','):
                    MAP_HOSTS.append((str(ip),'443'))
                    scanfile.write("{}\n".format(ip))
            logging.info("[SYSTEM] file {} has been cleaned and organised by line".format(filename)) 
        else:            
            for ip in split:
                MAP_HOSTS.append((ip.rstrip(),'443'))
            logging.info("[SYSTEM] file {} is already organised by line".format(filename)) 
                    
    return MAP_HOSTS
    
def auto_resume(ip):
    Lock().acquire
     # thread blocks at this line until it can obtain lock

    # in this section, only one thread can be present at a time.
    with open(sys.argv[1], "r") as f:
        lines = f.readlines()
    with open(sys.argv[1],'w') as hostlist:
        for line in lines:
            if line.strip("\n") != ip:
                f.write(line)

    Lock().release
    
if __name__ == '__main__':
    if os.getuid() != 0:
        logging.critical("You need to run as root user!")
        sys.exit()
    
    if not which('nmap'):
        logging.critical("no nmap binary found in path. (Examples - MacOS: brew install nmap, Linux: apt-get install nmap")
        sys.exit()

    MAP = map_hosts(sys.argv[1])
    if os.path.exists('failed-hosts.txt'):
        os.remove('failed-hosts.txt')
        logging.info("File failed-hosts.txt from previous scan has been removed")

    counter = len(MAP)
    logging.info("[SCANNER] Total Number of IP in list: {}".format(counter))
  
    try:
        for ip,port in MAP:
            counter -= 1
            pool.add_task(nmap_scan, ip,port)
            
    except KeyboardInterrupt:
        print("[SYSTEM] Pressed CTRL+C gracefully exiting from the application...")
        pool.wait_completion()
    
