
import sys
import os
import hmac
import getpass

from pbkdf2 import PBKDF2
from hashlib import sha256
from os import urandom
from Crypto.Cipher import AES
from struct import pack, unpack

FILE_BLOCK_SIZE = 16 * 1024 * 1024 # 16MB

def Encrypt( filename, passphrase ) :
	salt = urandom( 32 )
	iv = urandom( 16 )
	kdf = PBKDF2( passphrase, salt )
	key_enc = kdf.read( 32 )
	key_mac = kdf.read( 32 )
	mac = hmac.new( key_mac )
	mac.update( iv )
	aes = AES.new( key_enc, AES.MODE_CBC, iv )
	with open( filename, 'rb' ) as fp :
		with open( filename + '.aes256', 'wb' ) as fpw :
			fp.seek( 0, os.SEEK_END )
			file_len = fp.tell()
			fp.seek( 0, os.SEEK_SET )

			fpw.write( salt )
			fpw.write( iv )
			fpw.write( pack( '<q', file_len ) )

			file_block_num = ( file_len - 1 ) // FILE_BLOCK_SIZE + 1
			remaining_len = file_len
			for i in range( file_block_num ) :
				data = fp.read( min( remaining_len, FILE_BLOCK_SIZE ) )
				data_len = len( data )
				remaining_len -= FILE_BLOCK_SIZE
				if data_len % 16 != 0 :
					data += b'\0' * ( 16 - ( data_len % 16 ) )
				data_encrypted = aes.encrypt( data )
				mac.update( data_encrypted )
				fpw.write( data_encrypted )
				progress = '%.2f%%' % ( ( i + 1 ) / file_block_num * 100.0 )
				print( progress + ( '\b' * len( progress ) ), end = '' )
				sys.stdout.flush()
			print( ( ' ' * 10 ) + ( '\b' * 10 ), end = '' )
			sys.stdout.flush()
			fpw.write( mac.digest() )


def Decrypt( filename, passphrase ) :
	outfilename = filename[ : -7 ]
	succeed = False
	with open( filename, 'rb' ) as infile :
		with open( outfilename, 'wb' ) as outfile :
			salt = infile.read( 32 )
			iv = infile.read( 16 )
			kdf = PBKDF2( passphrase, salt )
			key_enc = kdf.read( 32 )
			key_mac = kdf.read( 32 )
			mac = hmac.new( key_mac )
			mac.update( iv )
			aes = AES.new( key_enc, AES.MODE_CBC, iv )
			file_len, = unpack( '<q', infile.read( 8 ) )
			file_block_num = ( file_len - 1 ) // FILE_BLOCK_SIZE + 1
			remaining_len = file_len
			for i in range( file_block_num ) :
				data_encrypted = infile.read( min( remaining_len, FILE_BLOCK_SIZE ) )
				data_len = len( data_encrypted )
				remaining_len -= FILE_BLOCK_SIZE
				if data_len % 16 != 0 :
					data_encrypted += infile.read( 16 - ( data_len % 16 ) )

				mac.update( data_encrypted )
				data = aes.decrypt( data_encrypted )
				if data_len % 16 != 0 :
					data = data[ : -( 16 - ( data_len % 16 ) ) ]
				outfile.write( data )
				progress = '%.2f%%' % ( ( i + 1 ) / file_block_num * 100.0 )
				print( progress + ( '\b' * len( progress ) ), end = '' )
				sys.stdout.flush()
			print( ( ' ' * 10 ) + ( '\b' * 10 ), end = '' )
			sys.stdout.flush()
			succeed = infile.read( 16 ) == mac.digest()
	if not succeed :
		os.remove( outfilename )
	return succeed

def Usage() :
	print( 'aes256 filename ... [-p "passphrase"] [--silent] [--help]' )

def HandleCommandLine( argv ) :
	passphrase_status = False
	passphrase_on = False
	passphrase = ''
	silent_on = False
	help_on = False
	error_msg = []
	sanitized_argv = []
	for arg in argv[ 1 : ] :
		if arg == '-p' :
			if passphrase_on :
				error_msg.append( 'Too many passphrases' )
			else :
				passphrase_status = True
		elif arg == '--silent' :
			silent_on = True
		elif arg == '--help' or arg == '-h' :
			help_on = True
		elif passphrase_status :
			passphrase = arg
			passphrase_on = True
			passphrase_status = False
		else :
			sanitized_argv.append( arg )
	return { 'error' : list( set( error_msg ) ), 'help' : help_on, 'silent' : silent_on, 'passphrase' : ( passphrase if passphrase_on else '' ) }, sanitized_argv

def RequirePassphrase() :
	p1 = 'a'
	p2 = 'b'
	while p1 != p2 :
		p1 = getpass.getpass( 'Enter passphrase:' )
		p2 = getpass.getpass( 'Enter passphrase again:' )
	return p1
	

def main( argv ) :
	assert FILE_BLOCK_SIZE % 16 == 0

	if len( argv ) <= 1 :
		Usage()
		return

	val_dict, files = HandleCommandLine( argv )

	if val_dict['silent'] :
		sys.stdout = open( os.devnull, 'w' )
		if not val_dict['passphrase'] :
			return

	if val_dict['help'] :
		Usage()
		return

	if val_dict['error'] :
		for er in val_dict['error'] :
			print( er )
		return

	passphrase = val_dict['passphrase'] if val_dict['passphrase'] else RequirePassphrase()

	for filename in files :
		if not os.path.exists( filename ) :
			print( 'File %s does not exist, skipped.' % filename )
			continue
		#helper = AES256Helper( filename )
		if filename.endswith( '.aes256' ) :
			print( 'Decrypting %s ' % filename, end = '' )
			sys.stdout.flush()
			if Decrypt( filename, passphrase ) :
				print( 'done' )
			else :
				print( 'FAILED' )
		else :
			print( 'Encrypting %s ' % filename, end = '' )
			sys.stdout.flush()
			Encrypt( filename, passphrase )
			print( 'done' )

if __name__ == '__main__' :
	main( sys.argv )

