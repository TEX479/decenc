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

def hn_hash_linux(text:bytes) -> int:
    """
        Hash matching the version used in Hacknet on Linux
        (and other systems using mono)
    """
    num = 0
    for c in text:
        num = intify((num << 5) - num + int(c))
    return num

def hn_hash_win(text:bytes) -> int:
    """
        Hash matching the version used in Hacknet on Windows
    """
    num = num2 = 0x15051505

    A = [int(x) for x in text]
    if len(A)%2 == 1:
        A.append(0)

    Z = [a + (b<<16) for a,b in zip(A[0::2], A[1::2])]


    for i in range(0,len(Z)-1,2):
        num  = intify( ((num <<5) + num  + (num  >> 27))^Z[i]   )
        num2 = intify( ((num2<<5) + num2 + (num2 >> 27))^Z[i+1] )
    if len(Z)%2 == 1:
        num  = intify( ((num <<5) + num  + (num  >> 27))^Z[-1]  )

    return intify(num + num2*0x5d588b65)

def hn_hash(text:bytes, hashOS:str) -> int:
    # Only Windows actually differs
    if hashOS in WINDOWS_IDENTIFIERS:
        h = hn_hash_win(text)
    else:
        h = hn_hash_linux(text)
    return h % (2**16)

# Actual decryption/encryption code
def decrypt(data:str, passcode:int) -> bytes:
    strArray = data.split()

    R: list[int] = []
    for s in strArray:
        num2 = int(s)
        num4 = (num2 - 0x7fff) - passcode
        num4 //= 1822
        R.append(num4)
    return bytes(R)

def encrypt(data:bytes, passcode:int) -> str:
    R: list[int] = []
    for c in data:
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
        elif len(header) == 4:
            extension = ''
            _,comment,signature,check = header
        else:
            raise ValueError("Invalid DEC_ENC file. Header is missing or malformed.")

        if comment:
            comment = decrypt(comment, hn_hash(b'', hashOS)).decode(encoding="utf-8", errors="replace")
        if signature:
            signature = decrypt(signature, hn_hash(b'', hashOS)).decode(encoding="utf-8", errors="replace")
        if extension:
            extension = decrypt(extension, hn_hash(b'', hashOS)).decode(encoding="utf-8", errors="replace")

        self.comment = comment
        self.signature = signature
        self.check = check
        self.extension = extension

        self.need_pass = decrypt(self.check, hn_hash(b'', hashOS)) != b'ENCODED'

    def header(self) -> str:
        h: str = f'Comment:   {self.comment}'
        h   += f'\nSignature: {self.signature}'
        h   += f'\nExtension: {self.extension}'
        return h

# Decoding ways
def dec_msg_brute(dec:DEC_ENC) -> tuple[int, bytes]:
    """
        Brute force decoding
    """
    # Brute force decryption
    for pw in range(0,2**16):
        r = decrypt(dec.check, pw)
        if r == b'ENCODED':
            plain = decrypt(dec.cipher, pw)
            return pw, plain
    raise Exception("Unable to decrypt. This shouldn't happen.")

def dec_msg_pass(dec:DEC_ENC, password:bytes, hashOS:str) -> bytes:
    """
        Decode with given pass
    """
    i = hn_hash(password, hashOS)
    r = decrypt(dec.check,i)
    if r == b'ENCODED':
        plain = decrypt(dec.cipher,i)
    else:
        if password == b'':
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
    print(f'Content is {"" if dec.extension else "not "}password protected')

def decrypt_with_pass(s:str, password:bytes, nlayers:int=1, verbose:bool=False, hashOS:str=sys.platform) -> tuple[DEC_ENC, bytes]:
    """
        Decrypt given password
    """
    if nlayers <= 0: raise ValueError("0 decryptions means this function does nothing.")
    for i in range(nlayers):
        dec = DEC_ENC(s, hashOS)
        s_bytes = dec_msg_pass(dec, password, hashOS)

        if i+1 < nlayers:
            try:    s = s_bytes.decode(encoding='utf-8', errors='strict')
            except: raise ValueError(f"Unable to decrypt past layer {i}. Is 'nlayers' set too high for this file?")

        if verbose:
            debug('=== Pass {} ==='.format(i+1))
            debug(dec.header())
        #plain = dec_msg_pass(check, msg, 'Obi-Wan')
    return dec,s_bytes # type: ignore # <- this is fine, because dec will be set in the loop

def decrypt_brute(s:str, nlayers:int=1, verbose:bool=False, hashOS:str=sys.platform) -> tuple[DEC_ENC, bytes]:
    """
        Brute force decrypter
    """
    if nlayers <= 0: raise ValueError("0 decryptions means this function does nothing.")
    for i in range(nlayers):
        dec = DEC_ENC(s, hashOS)
        pw,s_bytes = dec_msg_brute(dec)

        if i+1 < nlayers:
            try:    s = s_bytes.decode(encoding='utf-8', errors='strict')
            except: raise ValueError(f"Unable to decrypt past layer {i}. Is 'nlayers' set too high for this file?")

        if verbose:
            debug('=== Pass {} ==='.format(i+1))
            debug(dec.header())
            #debug(s)
            if hashOS in WINDOWS_IDENTIFIERS:
                import rainbow_win as rainbow
            else:
                import rainbow_linux as rainbow
            debug('One possible pass is', rainbow.table[pw])
    return dec,s_bytes # type: ignore # <- this is fine, because dec will be set in the loop

def encrypt_with_pass(comment:str, signature:str, hashOS:str, extension:str|None, plain:bytes, password:bytes) -> str:
    """
        Encrypt given password
    """
    passnum = hn_hash(password, hashOS)

    comment = encrypt(comment.encode("utf-8"), hn_hash(b'', hashOS))
    signature = encrypt(signature.encode("utf-8"), hn_hash(b'', hashOS))
    check = encrypt('ENCODED'.encode("utf-8"), passnum)
    if extension != None: extension = encrypt(extension.encode("utf-8"), hn_hash(b'', hashOS))
    cipher = encrypt(plain, passnum)

    if extension != None:
        header = ['#DEC_ENC', comment, signature, check, extension]
    else:
        header = ['#DEC_ENC', comment, signature, check]
    return '::'.join(header) + '\n' + cipher

if __name__ == "__main__":
    with open("message_linux.dec", "r") as f:
        s = f.read()
    dec_enc, output_bytes = decrypt_brute(s=s, nlayers=1, verbose=True, hashOS="linux")
    #print(dec_enc.header())
    print(output_bytes.decode(encoding="utf-8", errors="replace"))

    with open("message_win.dec", "r") as f:
        s = f.read()
    dec_enc, output_bytes = decrypt_brute(s=s, nlayers=1, verbose=True, hashOS="windows")
    #print(dec_enc.header())
    print(output_bytes.decode(encoding="utf-8", errors="replace"))
