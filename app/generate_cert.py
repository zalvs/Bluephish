# Generates the self-signed certificate used to serve the interface over HTTPS.
#
# TLS is not optional here: the session cookie is issued with the Secure flag,
# so a browser would never send it back over plain HTTP and nobody could stay
# signed in. A self-signed pair is enough for a local/internal deployment (the
# browser shows a warning that the operator accepts once); in front of a real
# deployment, put a reverse proxy with a CA-issued certificate and point
# THEPHISH_TLS_CERT / THEPHISH_TLS_KEY at it.
import os
import subprocess


def ensure_self_signed(cert_file, key_file, common_name = 'localhost'):
	if os.path.isfile(cert_file) and os.path.isfile(key_file):
		return cert_file, key_file
	cert_dir = os.path.dirname(cert_file)
	if cert_dir and not os.path.isdir(cert_dir):
		os.makedirs(cert_dir, exist_ok = True)
	# openssl ships with the base image; the SAN entries keep modern browsers
	# from rejecting the certificate outright
	subprocess.check_call([
		'openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048',
		'-keyout', key_file, '-out', cert_file,
		'-days', '825', '-subj', '/CN={0}'.format(common_name),
		'-addext', 'subjectAltName=DNS:localhost,DNS:thephish,IP:127.0.0.1'
	])
	# The private key must not be world readable
	try:
		os.chmod(key_file, 0o600)
	except OSError:
		pass
	print('[INFO]_[generate_cert]: self-signed certificate generated at {0}'.format(cert_file))
	return cert_file, key_file


if __name__ == '__main__':
	base = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
	ensure_self_signed(os.path.join(base, 'thephish-cert.pem'), os.path.join(base, 'thephish-key.pem'))
