#!/usr/bin/python3
import hashlib
import os
import time
import readline
import datetime
os.system('clear')
print("""\033[1;34m
╔═╗╦═╗╦ ╦   ╔═╗╦═╗╔═╗╔═╗╦╔═╔═╗╦═╗
╠╣ ╠╦╝╚╦╝───║  ╠╦╝╠═╣║  ╠╩╗║╣ ╠╦╝
╚  ╩╚═ ╩    ╚═╝╩╚═╩ ╩╚═╝╩ ╩╚═╝╩╚═
This is just a Simple, Handy , Swiss Army knife tool for common HASH cracking

                                                        ---> Coded by FEBIN (https://github.com/febinrev)

AVAILABE HASHES COULD BE CRACKED:

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

 """)
def fr_cracker():
	hashtype=str(input("\033[1;39m CHOOSE THE TYPE OF HASH YOU WANNA CRACK : "))
	print("")
	hashe=input("\033[1;39m Enter/Paste The Hash : ")
	hashed=str(hashe)
	print("")
	wordlist=input("\033[1;39m Enter the Path/Wordlist : ")
	if os.path.isfile(wordlist):
		starttime=datetime.datetime.now()
		print(f"\033[1;33m FRY-CRACKER started start-time:=> {starttime.hour}:{starttime.minute}:{starttime.second}:{starttime.microsecond} Date:=> day:{starttime.day}/month:{starttime.month}/year:{starttime.year} ..............\033[1;32m")
		wfile=open(wordlist,"r", encoding='UTF-8')
		words=wfile.read().split()
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
		else:
			print("\033[1;31mNo Words in this list matched the HASH   or   May be the choice you made is wrong")
			print("\033[1;37 FRY-CRACKER Execution Finished.......")

try:
	fr_cracker()
except UnicodeDecodeError:
	print("\033[1;31mSorry UnicodeDecode error: Couldn't Read that wordlist at the moment....")
	print("Tool Restarting in 5 seconds.....Please give another wordlist.....")
	time.sleep(5)
	print("")
	try:
	 fr_cracker()
	except KeyboardInterrupt:
		print("")
		print("\033[1;31mUSER INTERRUPT DETECTED ,, Bye Bye")
		("\033[1;38mHappy Hacking! ")
		exit()
except KeyboardInterrupt:
	print("")
	print("\033[1;31mUSER INTERRUPT DETECTED ,, Bye Bye")
	print("\033[1;38mHappy Hacking! ")
	exit()
except ModuleNotFoundError:
	print("hashlib library not found.....It is essential for this tool")
	print("Try installing it using the command ==> 'python3 -m pip install hashlib'")
	exit()
