# cert_grabber

cert_grabber is a wrapper around the great [tls-scan]( https://github.com/prbinu/tls-scan ) .

Default port for scan TLS/SSL certs is **443** at the moment you cannot change that.

In order to make it running :

```
pip3 install -r requirements.txt
```

It usage is fairly simple :

```
python3 cert_grabber [hostlist-file]
```

## Hostlist file

the hostlist file must be a comma separated list of single IPs or one per line IPs list. 

## Host not scanned

the hosts which returned a bad or empty output will be saved in **failed-hosts.txt** which require a further manual analysis.

## Results 

The results are stored in a sqlite3 database for easy and nice select and sorting of data.

the db is saved in **db/cert.sqlite**

Below a description of the field of the database and the data that the headers represent :
| DB Header | Description | Example |
|-------------|-------------|-----------|
| *id* | numeric integer that represent the identifier in DB| 3043 |
|*host* |easy to guess| 3.3.3.3 | 
|*port* |easy to guess| 443 |
|*tls_version*| The tls/ssl version used to estabilish connection with the host. | TLSv1 |
| *secure_renegotiation*| checks if the server enforces secure renegotiation | True/False
|*tls supported* | reports the tls/ssl version supported | ['SSLv3', 'TLSv1', 'TLSv1_1', 'TLSv1_2'] 
| *issuer* | Certificate Issuer | CN=COMODO SHA-256 Organization Validation Secure Server CA; O=COMODO CA Limited; L=Salford; ST=Greater Manchester; C=GB| 
| *subject* | subject name in certificate | CN=Vigor Router; OU=DrayTek Support; O=DrayTek Corp.; L=HuKou; ST=HsinChu; C=TW|
| *subjectDN* | subject Common Name | DPNAS15.myqnapcloud.com | 
| *subjectAltNames* | subject Alternative Common Name | DNS:DPNAS15.myqnapcloud.com |
| *pubkeysize* | is the number of bits in a key used by a cryptographic algorithm | 2048 |
| *expired* | if certificate is expired | True/False|
| *notAfter* | Evidence of certificate expired | Nov  2 00:00:40 2015 GMT |
| *cert_calid* | if the certificate is valid or not | True/False|
| *signatureAlg* | The signature algorithm specified when creating the CSR corresponds to the message digest used to sign the request itself|sha1WithRSAEncryption|

## Tools to make the data more human readable 

I use [DB Browser for SQLite](https://sqlitebrowser.org/dl/)


## TODO

* Resume scan on abort
* Pass programmatically different port / list of ports.
* Handling KeyBoardInterrupt better.