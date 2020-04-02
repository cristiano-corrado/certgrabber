import os
import shlex
import subprocess
from utils.logger import logging
import json

def tls_scan(host,port):
    
    logging.info("[TLSSCANNER] starting tls-scan for Host: {}".format(host))
    tls_scanner = "tools/tls-scan/tls-scan -b 1 --no-parallel-enum -V --cacert=tools/tls-scan/ca-bundle.crt -c {}:{} ".format(host,port)
    args = shlex.split(tls_scanner)
    proc = subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    ( output, err ) = proc.communicate()

    if err:
            logging.critical("[TLSSCANNER] Unable to scan {} error: {}".format(host,err))
    ret_code = proc.wait()
    if ret_code == 0 and len(output) > 5 :
        try :
            output = json.loads(output.decode('utf-8').strip())
            return output
            
        except json.decoder.JSONDecodeError as e:
            return False
    else:
        return False
        


