from OpenSSL import SSL, crypto
import socket, binascii, subprocess, requests, idna
from oscrypto import asymmetric
from ocspbuilder import OCSPRequestBuilder
from asn1crypto import core, ocsp, x509

sslv3 = SSL.Context(SSL.SSLv3_METHOD)
sslv23 = SSL.Context(SSL.SSLv23_METHOD)
tlsv1 = SSL.Context(SSL.TLSv1_METHOD)
tlsv11 = SSL.Context(SSL.TLSv1_1_METHOD)
tlsv12 = SSL.Context(SSL.TLSv1_2_METHOD)

contexts = [tlsv12, tlsv11, tlsv1, sslv3, sslv23]

from flask import Flask, render_template, redirect, flash
from forms import Form

app = Flask(__name__)
app.config.from_object('config')

if __name__ == '__main__':
    app.run()

@app.route('/', methods=('GET', 'POST'))
def application():
    form = Form()
    if form.validate_on_submit():
        name = form.name.data
        print(name)
        encoded_name = idna.encode(name)
        response = get_response(encoded_name)
        print(response)
        flash('response status: {}'.format(response['status']))
        for r in response['data']['responses']:
            flash('cert ID:')
            ID = r['cert_id']
            flash('\thash algorithm: {}'.format(ID['hash_algorithm']['algorithm']))
            flash('\tissuer name hash: {}'.format(ID['issuer_name_hash']))
            flash('\tissuer key hash: {}'.format(ID['issuer_key_hash']))
            flash('\tserial number: {}'.format(ID['serial_number']))
            flash('status: {}'.format(r['cert_status']))
        flash('produced at: {}'.format(response['data']['produced_at']))
        flash('responder: {}'.format(response['data']['responder_id']))
        return render_template('results.html')
    return render_template('ocsp.html', form=form)

def get_certs(hostname):
    '''Get certs in OpenSSL.crypto.x509 format.'''
    for context in contexts:
        try:
            s = socket.socket()
            conn = SSL.Connection(context, s)
            conn.set_connect_state()
            conn.set_tlsext_host_name(hostname) #SNI
            conn.connect((hostname, 443))
            conn.do_handshake()
            chain = conn.get_peer_cert_chain()
            return chain
        except:
            continue

def convert_to_oscrypto(chain):
    '''Converts a list of certs from OpenSSL.crypto.x509 to oscrypto._openssl.asymmetric.Certificate'''
    l = []
    for c in chain:
        l.append(asymmetric.load_certificate(crypto.dump_certificate(crypto.FILETYPE_PEM, c).encode('latin-1')))
    return l

def create_ocsp_request(cert, issuer):
    '''Takes a certificate and the issuing certificate in oscrypto._openssl.asymmetric.Certificate format and creates an OCSP request body.'''
    builder = OCSPRequestBuilder(cert, issuer)
    return builder.build().dump()

def get_ocsp_uri(hostname):
    '''Gets the OCSP responder URL for a website.'''
    chain = get_certs(hostname)
    return extract_ocsp_uri(chain[0])

def extract_ocsp_uri(cert):
    '''Gets the OCSP responder URL for a OpenSSL.crypto.x509 certificate object.'''
    return subprocess.Popen(["openssl", "x509", "-noout", "-ocsp_uri"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)\
            .communicate(input=crypto.dump_certificate(crypto.FILETYPE_PEM, cert))[0].strip()

def parse_ocsp(response):
    '''Converts from asn1crypto.ocsp.OCSPResponse to a dict'''
    OCSP = {}
    OCSP['status'] = response['response_status'].native
    if OCSP['status'] != 'successful':
        print('error')#.format(OCSP['status']))
        return OCSP
    OCSP['data'] = {} #ResponseData
    OCSP['data']['version'] = response.response_data['version'].native
    if isinstance(response.response_data['responder_id'].chosen, core.OctetString):
        OCSP['data']['responder_id'] = binascii.hexlify(response.response_data['responder_id'].chosen.native).upper()
    elif isinstance(response.response_data['responder_id'].chosen, x509.Name):
        OCSP['data']['responder_id'] = {'country_name' : response.response_data['responder_id'].chosen.native['country_name'],
                                        'organization_name' : response.response_data['responder_id'].chosen.native['organization_name'],
                                        'common_name' : response.response_data['responder_id'].chosen.native['common_name']}
    OCSP['data']['produced_at'] = response.response_data['produced_at'].native
    OCSP['data']['responses'] = []
    for x in response.response_data['responses'].native:
        respdata = {}
        respdata['cert_id'] = {}
        respdata['cert_id']['hash_algorithm'] = {'algorithm' : x['cert_id']['hash_algorithm']['algorithm'], 'parameters' : x['cert_id']['hash_algorithm']['parameters']}
        respdata['cert_id']['issuer_name_hash'] = binascii.hexlify(response.response_data['responses'].native[0]['cert_id']['issuer_name_hash']).upper()
        respdata['cert_id']['issuer_key_hash'] = binascii.hexlify(response.response_data['responses'].native[0]['cert_id']['issuer_key_hash']).upper()
        respdata['cert_id']['serial_number'] = hex(response.response_data['responses'].native[0]['cert_id']['serial_number']).upper().replace('X', '')[:-1]
        respdata['cert_status'] = response.response_data['responses'].native[0]['cert_status']
        if not respdata['cert_status']:
            respdata['cert_status'] = 'good'
        #check for revoked
        respdata['this_update'] = response.response_data['responses'].native[0]['this_update']
        respdata['next_update'] = response.response_data['responses'].native[0]['next_update']
        respdata['single_extensions'] = response.response_data['responses'].native[0]['single_extensions']
        OCSP['data']['responses'].append(respdata)
    OCSP['data']['response_extensions'] = response.response_data['response_extensions'].native
    return OCSP

def contact_ocsp_server(certs):
    '''Sends an OCSP request to the responding server for a certificate chain'''
    chain = convert_to_oscrypto(certs)
    req = create_ocsp_request(chain[0], chain[1])
    URI = extract_ocsp_uri(certs[0])
    data = requests.post(URI, data=req, stream=True, headers={'Content-Type' : 'application/ocsp-request'})
    response = ocsp.OCSPResponse.load(data.raw.data)
    parsed = parse_ocsp(response)
    return parsed

def get_response(hostname):
    '''Gets and parses an OCSP response for a hostname'''
    certs = get_certs(hostname)
    parsed = contact_ocsp_server(certs)
    return parsed
