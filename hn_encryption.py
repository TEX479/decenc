from __future__ import print_function,division
import sys
if sys.version_info < (3, 0):
    range = xrange

WINDOWS_IDENTIFIERS = ['windows','Windows','win32', 'cygwin']

# General helper
def debug(*args,**kwargs): print(*args,file=sys.stderr,**kwargs) # type: ignore

def intify(x:int) -> int:
    y = x&0xffffffff
    if y > 0x7fffffff: y -= 2**32
    return y

def hn_hash_linux(text:str) -> int:
    """
        Hash matching the version used in Hacknet on Linux
        (and other systems using mono)
    """
    num = 0
    for c in text:
        num = intify((num << 5) - num + ord(c))
    return num

def hn_hash_win(text:str) -> int:
    """
        Hash matching the version used in Hacknet on Windows
    """
    num = num2 = 0x15051505

    A = [ord(x) for x in text]
    if len(A)%2 == 1:
        A.append(0)

    Z = [a + (b<<16) for a,b in zip(A[0::2], A[1::2])]


    for i in range(0,len(Z)-1,2):
        num  = intify( ((num <<5) + num  + (num  >> 27))^Z[i]   )
        num2 = intify( ((num2<<5) + num2 + (num2 >> 27))^Z[i+1] )
    if len(Z)%2 == 1:
        num  = intify( ((num <<5) + num  + (num  >> 27))^Z[-1]  )

    return intify(num + num2*0x5d588b65)

def hn_hash(text:str, hashOS:str) -> int:
    # Only Windows actually differs
    if hashOS in WINDOWS_IDENTIFIERS:
        h = hn_hash_win(text)
    else:
        h = hn_hash_linux(text)
    return h % (2**16)

# Actual decryption/encryption code
def decrypt(data:str, passcode:int) -> str:
    strArray = data.split()

    R: list[str] = []
    for s in strArray:
        num2 = int(s)
        num4 = (num2 - 0x7fff) - passcode
        num4 //= 1822
        R.append(chr(num4))
    return ''.join(R)

def encrypt(data:str, passcode:int) -> str:
    R: list[int] = []
    for c in map(ord, data):
        R.append(c*1822 + passcode + 0x7fff)
    return ' '.join(map(str,R))


class DEC_ENC:
    """
        Class representing a DEC_ENC file.

        Parses DEC_ENC file contents and decrypt header.
    """
    def __init__(self, content:str, hashOS:str=sys.platform) -> None:
        header = content.strip().split('\n')[0]
        self.cipher = content.strip().split('\n')[1]

        header = header.split('::')
        if len(header) > 4:
            _,comment,signature,check,extension = header
        else:
            extension = ''
            _,comment,signature,check = header

        if comment:
            comment = decrypt(comment, hn_hash('', hashOS))
        if signature:
            signature = decrypt(signature, hn_hash('', hashOS))
        if extension:
            extension = decrypt(extension, hn_hash('', hashOS))

        self.comment = comment
        self.signature = signature
        self.check = check
        self.extension = extension

        self.need_pass = decrypt(self.check, hn_hash('', hashOS)) != 'ENCODED'

    def header(self) -> str:
        H: list[str] = []
        def add(s:str, x:str):
            if x: H.append(s+': {}'.format(x))
        add('Comment', self.comment)
        add('Signature', self.signature)
        add('Extension', self.extension)
        return '\n'.join(H)

# Decoding ways
def dec_msg_brute(dec:DEC_ENC) -> tuple[int, str]:
    """
        Brute force decoding
    """
    # Brute force decryption
    for pw in range(0,2**16):
        r = decrypt(dec.check, pw)
        if r == 'ENCODED':
            plain = decrypt(dec.cipher, pw)
            break
    return pw, plain # type: ignore # <- this is fine, since we know that the loop in this function always sets "pw" and "plain"

def dec_msg_pass(dec:DEC_ENC, password:str, hashOS:str) -> str:
    """
        Decode with given pass
    """
    i = hn_hash(password, hashOS)
    r = decrypt(dec.check,i)
    if r == 'ENCODED':
        plain = decrypt(dec.cipher,i)
    else:
        if password == '':
            raise Exception("A password is needed")
        else:
            raise Exception("Wrong password")
    return plain

# User level stuff
def decrypt_header_only(s:str, hashOS:str) -> None:
    """
        Decrypt only the header
    """
    dec = DEC_ENC(s, hashOS)
    print(dec.header())
    if dec.need_pass:
        print('Content is password protected')
    else:
        print('Content is not password protected')

def decrypt_with_pass(s:str, password:str, nlayers:int=1, verbose:bool=False, hashOS:str=sys.platform) -> tuple[DEC_ENC, str]:
    """
        Decrypt given password
    """
    if nlayers <= 0: raise ValueError("0 decryptions means this function does nothing.")
    for i in range(nlayers):
        dec = DEC_ENC(s, hashOS)
        s = dec_msg_pass(dec, password, hashOS)

        if verbose:
            debug('=== Pass {} ==='.format(i+1))
            debug(dec.header())
        #plain = dec_msg_pass(check, msg, 'Obi-Wan')
    return dec,s # type: ignore # <- this is fine, because dec will be set in the loop

def decrypt_brute(s:str, nlayers:int=1, verbose:bool=False, hashOS:str=sys.platform):
    """
        Brute force decrypter
    """
    if nlayers <= 0: raise ValueError("0 decryptions means this function does nothing.")
    for i in range(nlayers):
        dec = DEC_ENC(s, hashOS)
        pw,s = dec_msg_brute(dec)

        if verbose:
            debug('=== Pass {} ==='.format(i+1))
            debug(dec.header())
            #debug(s)
            if hashOS in WINDOWS_IDENTIFIERS:
                import rainbow_win as rainbow
            else:
                import rainbow_linux as rainbow
            debug('One possible pass is', rainbow.table[pw])
    return dec,s # type: ignore # <- this is fine, because dec will be set in the loop

def encrypt_with_pass(comment:str, signature:str, hashOS:str, extension:str, plain:str, password:str) -> str:
    """
        Encrypt given password
    """
    passnum = hn_hash(password, hashOS)

    comment = encrypt(comment, hn_hash('', hashOS))
    signature = encrypt(signature, hn_hash('', hashOS))
    check = encrypt('ENCODED', passnum)
    extension = encrypt(extension, hn_hash('', hashOS))
    cipher = encrypt(plain, passnum)

    if extension:
        header = ['#DEC_ENC', comment, signature, check, extension]
    else:
        header = ['#DEC_ENC', comment, signature, check]
    return '::'.join(header) + '\n' + cipher
