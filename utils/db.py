import os
import sqlite3
from utils.logger import logging

class Datastore(object):
    """sqlite3 database class that holds testers jobs"""
    if not os.path.exists("db/"):
        os.mkdir("db")
    __DB_LOCATION = "db/certs.sqlite3"

    def __enter__(self):
        return self

    def __exit__(self, ext_type, exc_value, traceback):

        self.cur.close()
        if isinstance(exc_value, Exception):
            self.connection.rollback()
        else:
            self.connection.commit()
        self.connection.close()

    def __init__(self):
        """Initialize db class variables"""

        if not os.path.isfile(Datastore.__DB_LOCATION):
            with open(Datastore.__DB_LOCATION,"w+") as datastore:
                logging.info("[DB] created new database file: {}".format(Datastore.__DB_LOCATION))
                datastore.close()

        self.connection = sqlite3.connect(Datastore.__DB_LOCATION,check_same_thread=False)
        self.cur = self.connection.cursor()

    def close(self):
        self.connection.close()

    def execute(self, new_data):
        return self.cur.execute(new_data)

    def getdata(self):
        selectAll = "SELECT * from certgrabbers"
        return self.cur.execute(selectAll)

    def insert(self,id,host,port,tls_version,secure_renegotiation,tls_supported,issuer,subject,subjectCN,subjectAltName,pubkeysize,expired,notAfter,cert_valid,signatureAlg):
        
        insertdb = 'INSERT INTO certgrabbers VALUES ("{}","{}","{}","{}","{}","{}","{}","{}","{}","{}","{}","{}","{}","{}","{}")'.format(id,host,port,tls_version,secure_renegotiation,tls_supported,issuer,subject,subjectCN,subjectAltName,pubkeysize,expired,notAfter,cert_valid,signatureAlg)
        logging.info("[DB] Inserted to DB: {}".format(host))
        self.cur.execute(insertdb)


    def create_table(self):
        """create a database table if it does not exist already"""
        self.cur.execute('''CREATE TABLE IF NOT EXISTS certgrabbers(id integer,host,port,tls_version,secure_renegotiation,tls_supported,issuer,subject,subjectCN,subjectAltName,pubkeysize,expired,notAfter,cert_valid,signatureAlg)''')
        logging.info("[DB] Created: certgrabbers")

    def commit(self):
        """commit changes to database"""
        self.connection.commit()

    def exists(self):
        check = self.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='gggitrepos';")
        logging.info("[DB] {} already exists.".format(self.__DB_LOCATION))
        return check.fetchone()[0]

    def removedb(self):
        logging.info("[DB] {} successfully removed".format(self.__DB_LOCATION))
        os.remove(Datastore.__DB_LOCATION)

