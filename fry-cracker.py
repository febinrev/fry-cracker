#!/usr/bin/env python3
import hashlib
import os
import time
import readline
import datetime
import crypt
import re
import passlib.hash
import argparse

print("""
╔═╗╦═╗╦ ╦   ╔═╗╦═╗╔═╗╔═╗╦╔═╔═╗╦═╗
╠╣ ╠╦╝╚╦╝───║  ╠╦╝╠═╣║  ╠╩╗║╣ ╠╦╝
╚  ╩╚═ ╩    ╚═╝╩╚═╩ ╩╚═╝╩ ╩╚═╝╩╚═
This is a Handy , Swiss Army knife tool for common HASH cracking (CPU based)

                                                        ---> Coded by FEBIN (https://github.com/febinrev)
 """)
def fr_cracker(hashtype,hashed,wordlist):
	if os.path.isfile(wordlist) and int(hashtype) <= 58:
		starttime=datetime.datetime.now()
		print(f"\033[1;33m FRY-CRACKER started start-time:=> {starttime.hour}:{starttime.minute}:{starttime.second}:{starttime.microsecond} Date:=> day:{starttime.day}/month:{starttime.month}/year:{starttime.year} ..............\033[1;32m")
		wfile=open(wordlist,"r", encoding='UTF-8', errors='ignore')
		#words=wfile.readlines()
		words=wfile.read().split("\n")
		wfile.close()
		if hashtype=='1':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.md5(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed} ")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
			print(m)
		elif hashtype=='2':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.sha1(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='3':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.sha224(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='4':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.sha256(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		if hashtype=='5':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.sha384(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='6':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.sha512(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='7':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.sha3_224(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='8':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.sha3_256(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='9':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.sha3_384(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='10':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.sha3_512(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='11':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.blake2b(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36 PASSWORD :=> {passwd}")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='12':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.blake2s(word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='13':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.new("md4",word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='14':
			for passwd in words:
				word=passwd
				if hashed.isupper():
					if passlib.hash.nthash.verify(word,hashed):
						print(f"HASH CRACKED : {hashed}")
						print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
						print("<=========================================================================================================================>")
						print('FRY-CRACKER exited, bye bye')
						exit()
					else:
						pass
				elif hashed.islower():
					chash=hashlib.new("md4",word.encode('utf-16le'))
					duphash=chash.hexdigest()					
					if duphash==hashed:
						print(f"HASH CRACKED : {hashed}")
						print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
						print("<=========================================================================================================================>")
						print('FRY-CRACKER exited, bye bye')
						exit()
					else:
						pass
		elif hashtype=='15':
			for passwd in words:
				word=passwd
				if hashed.isupper():
					hashed=hashed
					if passlib.hash.lmhash.verify(word,hashed):
						print(f"HASH CRACKED : {hashed}")
						print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
						print("<=========================================================================================================================>")
						print('FRY-CRACKER exited, bye bye')
						exit()
					else:
						pass
				else:
					hashed=hashed.upper()
					if passlib.hash.lmhash.verify(word,hashed):
						print(f"HASH CRACKED : {hashed}")
						print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
						print("<=========================================================================================================================>")
						print('FRY-CRACKER exited, bye bye')
						exit()
					else:
						pass
				
		elif hashtype=='16':
			shadow_valid=re.compile(":")
			shadowcolon=shadow_valid.findall(hashed)
			if shadowcolon.count(":") > 0 and not hashed.startswith("$"):
				shadowhash=hashed.split(":")[1]
				print(f"FOUND USER FROM GIVEN HASH > Username : {hashed.split(':')[0]}")
				if shadowhash.startswith("$1$"):
					print("Found Algorithm MD5crypt....!")
				elif shadowhash.startswith("$2a$"):
					print("Found Algorithm BLOWFISH....!")
				elif shadowhash.startswith("$2y$"):
					print("Found Algorithm BLOWFISH....!")
				elif shadowhash.startswith("$5$"):
					print("Found Algorithm SHA256crypt....!")
				elif shadowhash.startswith("$6$"):
					print("Found Algorithm SHA512crypt....!")
			elif shadowcolon.count(":") > 0 and hashed.startswith("$"):
				shadowhash=hashed.split(":")[0]
				if shadowhash.startswith("$1$"):
					print("Found Algorithm MD5crypt....!")
				elif shadowhash.startswith("$2a$"):
					print("Found Algorithm BLOWFISH....!")
				elif shadowhash.startswith("$2y$"):
					print("Found Algorithm BLOWFISH....!")
				elif shadowhash.startswith("$5$"):
					print("Found Algorithm SHA256crypt....!")
				elif shadowhash.startswith("$6$"):
					print("Found Algorithm SHA512crypt....!")

			else:
				shadowhash=hashed
				if shadowhash.startswith("$1$"):
					print("Found Algorithm MD5crypt....!")
				elif shadowhash.startswith("$2a$"):
					print("Found Algorithm BLOWFISH....!")
				elif shadowhash.startswith("$2y$"):
					print("Found Algorithm BLOWFISH....!")
				elif shadowhash.startswith("$5$"):
					print("Found Algorithm SHA256crypt....!")
				elif shadowhash.startswith("$6$"):
					print("Found Algorithm SHA512crypt....!")
				else:
					print("Error: Unknown Shadow hash!!!")
					print("Exit, Bye!")
					exit()
			for passwd in words:
				word=passwd
				if crypt.crypt(word,shadowhash)==shadowhash:
					print(f"HASH CRACKED : {shadowhash}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='17':
			for passwd in words:
				word=passwd
				if passlib.hash.grub_pbkdf2_sha512.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='18':
			for passwd in words:
				word=passwd
				chash=hashlib.new("ripemd160",word.encode())
				duphash=chash.hexdigest()					
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='19':
			for passwd in words:
				word=passwd
				if passlib.hash.argon2.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='20':
			for passwd in words:
				word=passwd
				if passlib.hash.atlassian_pbkdf2_sha1.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='21':
			for passwd in words:
				word=passwd
				if passlib.hash.bcrypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='22':
			for passwd in words:
				word=passwd
				if passlib.hash.bcrypt_sha256.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='23':
			for passwd in words:
				word=passwd
				if passlib.hash.bigcrypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='24':
			for passwd in words:
				word=passwd
				if passlib.hash.bsd_nthash.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='25':
			for passwd in words:
				word=passwd
				if passlib.hash.bsdi_crypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='26':
			for passwd in words:
				word=passwd
				if passlib.hash.cisco_asa.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='27':
			for passwd in words:
				word=passwd
				if passlib.hash.cisco_pix.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='28':
			for passwd in words:
				word=passwd
				if passlib.hash.cisco_type7.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='29':
			for passwd in words:
				word=passwd
				if passlib.hash.crypt16.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='30':
			for passwd in words:
				word=passwd
				if passlib.hash.des_crypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='31':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_bcrypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='32':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_bsdi_crypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='33':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_des_crypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='34':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_md5.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='35':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_md5_crypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='36':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_pbkdf2_sha1.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='37':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_pbkdf2_sha256.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='38':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_pbkdf2_sha512.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='39':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_sha1.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='40':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_sha1_crypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='41':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_sha256_crypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='42':
			for passwd in words:
				word=passwd
				if passlib.hash.ldap_sha512_crypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='43':
			for passwd in words:
				word=passwd
				if passlib.hash.msdcc.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='44':
			for passwd in words:
				word=passwd
				if passlib.hash.msdcc2.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='45':
			for passwd in words:
				word=passwd
				if passlib.hash.mssql2000.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='46':
			for passwd in words:
				word=passwd
				if passlib.hash.mssql2005.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='47':
			for passwd in words:
				word=passwd
				if passlib.hash.mysql323.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

		elif hashtype=='48':
			for passwd in words:
				word=passwd
				if passlib.hash.mysql41.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='49':
			for passwd in words:
				word=passwd
				if passlib.hash.oracle10.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='50':
			for passwd in words:
				word=passwd
				if passlib.hash.oracle11.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='51':
			for passwd in words:
				word=passwd
				if passlib.hash.pbkdf2_sha1.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='52':
			for passwd in words:
				word=passwd
				if passlib.hash.pbkdf2_sha256.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='53':
			for passwd in words:
				word=passwd
				if passlib.hash.pbkdf2_sha512.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='54':
			for passwd in words:
				word=passwd
				if passlib.hash.phpass.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='55':
			for passwd in words:
				word=passwd
				if passlib.hash.postgres_md5.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='56':
			for passwd in words:
				word=passwd
				if passlib.hash.scram.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='57':
			for passwd in words:
				word=passwd
				if passlib.hash.scrypt.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='58':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.new("whirlpool",word)
				duphash=chash.hexdigest()
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='59':
			for passwd in words:
				word=passwd.encode()
				chash=hashlib.new("shake_128",word)
				duphash=chash.hexdigest(len(hashed))
				if duphash==hashed:
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass
		elif hashtype=='60':
			for passwd in words:
				word=passwd
				if passlib.hash.htdigest.verify(word,hashed):
					print(f"HASH CRACKED : {hashed}")
					print(f"\033[1;36m PASSWORD :=> {passwd} \033[1;37m")
					print("<=========================================================================================================================>")
					print('FRY-CRACKER exited, bye bye')
					exit()
				else:
					pass

	else:
		print("\033[1;31m May be the choice you made is wrong or Wordlist may be not found!")
	print(" \nNo Passwords Cracked! Try some other wordlists. FRY-CRACKER Execution Finished!.......")

try:

	parser = argparse.ArgumentParser(description='Parse the input hash,wordlists etc.')
	parser.add_argument('-m', "--hash_alg",dest='hashtype', action='store',default=1,help='The Type of hash to be cracked (refer the available hashes --hashtypes)')
	parser.add_argument('-H', "--hash",dest='hash', action='store',help='The actual hash to be cracked (paste the hash)')
	parser.add_argument('-w', "--wordlist",dest='wordlist', action='store', default="passwords.txt",help='The actual path of the wordlist used to crack.')
	parser.add_argument('-i',"--interactive", dest='interactive', action='store_true',help='Interactive mode')
	parser.add_argument('-o','--hashtypes',dest='hashtypes', action='store_true',help='To View the type of hashes and its unique id ')
	args=parser.parse_args()

	if args.interactive:
		os.system('clear')
		print("""\033[1;34m
╔═╗╦═╗╦ ╦   ╔═╗╦═╗╔═╗╔═╗╦╔═╔═╗╦═╗
╠╣ ╠╦╝╚╦╝───║  ╠╦╝╠═╣║  ╠╩╗║╣ ╠╦╝
╚  ╩╚═ ╩    ╚═╝╩╚═╩ ╩╚═╝╩ ╩╚═╝╩╚═
This is a Handy , Swiss Army knife tool for common HASH cracking (CPU based)

                                                        ---> Coded by FEBIN (https://github.com/febinrev)

AVAILABE HASHES COULD BE CRACKED:
\033[1;33mBasic:\033[1;34m
[1] MD5
[2] SHA1
[3] SHA224
[4] SHA256
[5] SHA384
[6] SHA512
[7] SHA3_224
[8] SHA3_256
[9] SHA3_384
[10] SHA3_512
[11] blake2b
[12] blake2s
[13] MD4

\033[1;33mOS Based:\033[1;34m
[14] NTLM raw | NT Hash
[15] LM Hash
[16] Unix SHADOW Hash
[17] Unix/Linux GRUB-PBKDF2

\033[1;33mServices Based:\033[1;34m
[18] RipeMD-160
[19] ARGON2
[20] ATLASSIAN_PBKDF2_SHA1
[21] BCRYPT
[22] BCRYPT_SHA256
[23] BIGCRYPT
[24] BSD NT_HASH
[25] BSDI_CRYPT
[26] CISCO ASA
[27] CISCO PIX
[28] CISCO TYPE7
[29] CRYPT16
[30] DES_CRYPT
[31] LDAP_bcrypt
[32] LDAP_bsdi_crypt
[33] LDAP_des_crypt 
[34] LDAP_md5
[35] LDAP_md5_crypt
[36] LDAP_pbkdf2_sha1
[37] LDAP_pbkdf2_sha256
[38] LDAP_pbkdf2_sha512
[39] LDAP_sha1
[40] LDAP_sha1_crypt
[41] LDAP_sha256_crypt
[42] LDAP_sha512_crypt
[43] MSDCC
[44] MSDCC2
[45] MS-SQL2000
[46] MS-SQL2005
[47] MySQL323
[48] MySQL41
[49] ORACLE-10
[50] ORACLE-11
[51] PBKDF2_SHA1
[52] PBKDF2_SHA256
[53] PBKDF2_SHA512
[54] PHP-PASS
[55] POSTGRESQL_MD5
[56] SCRAM
[57] SCRYPT
[58] WHIRLPOOL
[59] SHAKE_128
[60] HT_digest

		 """)
		hashtype=str(input("\033[1;39m CHOOSE THE TYPE OF HASH YOU WANNA CRACK : ")).strip()
		print("")
		hashe=input("\033[1;39m Enter/Paste The Hash : ").strip()
		hashed=str(hashe)
		print("")
		wordlist=input("\033[1;39m Enter the Path/Wordlist : ").strip()
		fr_cracker(hashtype,hashed,wordlist)
	elif args.hashtypes:
		print("""\033[1;34m
AVAILABE HASHES COULD BE CRACKED:
\033[1;33mBasic:\033[1;34m
[1] MD5
[2] SHA1
[3] SHA224
[4] SHA256
[5] SHA384
[6] SHA512
[7] SHA3_224
[8] SHA3_256
[9] SHA3_384
[10] SHA3_512
[11] blake2b
[12] blake2s
[13] MD4

\033[1;33mOS Based:\033[1;34m
[14] NTLM raw | NT Hash
[15] LM Hash
[16] Unix SHADOW Hash
[17] Unix/Linux GRUB-PBKDF2

\033[1;33mServices Based:\033[1;34m
[18] RipeMD-160
[19] ARGON2
[20] ATLASSIAN_PBKDF2_SHA1
[21] BCRYPT
[22] BCRYPT_SHA256
[23] BIGCRYPT
[24] BSD NT_HASH
[25] BSDI_CRYPT
[26] CISCO ASA
[27] CISCO PIX
[28] CISCO TYPE7
[29] CRYPT16
[30] DES_CRYPT
[31] LDAP_bcrypt
[32] LDAP_bsdi_crypt
[33] LDAP_des_crypt 
[34] LDAP_md5
[35] LDAP_md5_crypt
[36] LDAP_pbkdf2_sha1
[37] LDAP_pbkdf2_sha256
[38] LDAP_pbkdf2_sha512
[39] LDAP_sha1
[40] LDAP_sha1_crypt
[41] LDAP_sha256_crypt
[42] LDAP_sha512_crypt
[43] MSDCC
[44] MSDCC2
[45] MS-SQL2000
[46] MS-SQL2005
[47] MySQL323
[48] MySQL41
[49] ORACLE-10
[50] ORACLE-11
[51] PBKDF2_SHA1
[52] PBKDF2_SHA256
[53] PBKDF2_SHA512
[54] PHP-PASS
[55] POSTGRESQL_MD5
[56] SCRAM
[57] SCRYPT
[58] WHIRLPOOL
[59] SHAKE_128
[60] HT_digest

		 """)
	elif int(args.hashtype) <= 58 and args.hash and args.wordlist:
		if os.path.isfile(args.wordlist):
			fr_cracker(args.hashtype,args.hash,args.wordlist)
		else:
			print("The wordlist you entered not found! Using Default list...")
			fr_cracker(args.hashtype,args.hash,"passwords.txt")
	else:
		print("Usage Error: Please give proper input. Check -h for help!!")
		print("Example : fry-cracker.py -m 1 -H 482c811da5d5b4bc6d497ffa98491e38 -w /usr/share/wordlists/rockyou.txt")
		print("Example: Interactive mode : fry-cracker -i or/ fry-cracker --interactive")
		print("Example: View available hashtypes to crack : fry-cracker -o or/ fry-cracker --hashtypes")

except KeyboardInterrupt:
	print("")
	print("\033[1;31mUSER INTERRUPT DETECTED ,, Bye Bye")
	print("\033[1;38mHappy Hacking! ")
	exit()
except ModuleNotFoundError:
	print("hashlib or readline library not found.....It is essential for this tool")
	print("Try installing it using the command ==> 'python3 -m pip install hashlib readline'")
	exit()
except ValueError:
	print("")
	print("\033[1;31m HASH Error or Invalid hashtype Choice : May be the hash you entered mismatched with your choice!")
	print("\033[1;38mHappy Hacking! ")
	exit()

