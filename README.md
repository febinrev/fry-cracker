# FRY-CRACKER

### RAW HASH CRACKER....A handy tool for password/hash bruteforcing and cracking (CPU BASED)

## Cracks common Hashes almost very quickly....

### Usage:
----------------------------------------------------------------------------------------
       
       $ python3 -m pip install -r requirements.txt
       $ chmod +x fry-cracker
       $ ./fry-cracker.py -i #for interactive mode
       $ ./fry-cracker.py -h #for help
       $ ./fry-cracker.py --hashtypes # to view the types of hashes can be cracked
       
     
     usage: fry-cracker.py [-h] [-m HASHTYPE] [-H HASH] [-w WORDLIST] [-i] [-o]

    Parse the input hash,wordlists etc.

    optional arguments:
      -h, --help            show this help message and exit
      -m HASHTYPE, --hash_alg HASHTYPE
                        The ID of Type of hash to be cracked (refer the available hashes --hashtypes)
      -H HASH, --hash HASH  The actual hash to be cracked (paste the hash)
      -w WORDLIST, --wordlist WORDLIST
                        The actual path of the wordlist used to crack.
      -i, --interactive     Interactive mode
      -o, --hashtypes       To View the type of hashes and its unique id

 
    [ SELECT THE APPROPRIATE TYPE OF HASH AND A GOOD WORDLIST TO CRACK!]
---------------------------------------------------------------------------------------------
 
## AVAILABE HASHES COULD BE CRACKED:

  ### Basic:
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

### OS Based:
    [14] NTLM raw | NT Hash
    [15] LM Hash
    [16] Unix SHADOW Hash
    [17] Unix/Linux GRUB-PBKDF2

### Services Based:
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
