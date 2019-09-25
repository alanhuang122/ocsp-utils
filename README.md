# ocsp-utils
Tool to check OCSP status of certificates

This tool allows for the checking of a host's certificate's OCSP status. It automatically retrieves the X.509 certificate presented by the host, extracts the OCSP responder URL from the AIA extension, queries the OCSP responder, and extracts the data from the response.

## Usage
```
pip install -r requirements.txt # ensure you've installed the dependencies
./ocsp.py <hostname>
```
