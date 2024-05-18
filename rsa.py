import func
from collections import namedtuple
from sm3 import sm3

Pubkey = namedtuple('Pubkey', 'e n')
Privkey = namedtuple('Privkey', 'd n')


class rsa:

    def __init__(self, module='keygen', *, param) -> None:  #默认生成空的示例
        self.module = module
        if self.module == 'keygen' and type(param) is int:  #密钥生成
            self.pubkey, self.privkey = self._keygen(param)
        elif self.module == 'receiver' and type(param) is Pubkey:
            self.pubkey = param

    def _keygen(self, keylen):
        p, q = func.randomPrime(keylen), func.randomPrime(keylen)
        n, r = p * q, (p - 1) * (q - 1)  # r为偶数
        e = 0x10001
        d = func.inv(e, r)
        return Pubkey(e, n), Privkey(d, n)

    def encrypt(self, msg: bytes):  #传入bytes数据，下同
        if 'pubkey' not in self.__dict__.keys():
            return "Do not have public key"
        c = func.power(int(msg, 16), self.pubkey.e, self.pubkey.n)
        return bytes(f"{c:x}", encoding='UTF-8')

    def decrypt(self, cip: bytes):  #传入bytes数据，下同
        if 'privkey' not in self.__dict__.keys():
            return "Do not have private key"
        m = func.power(int(cip, 16), self.privkey.d, self.privkey.n)
        return bytes(f"{m:x}", encoding='UTF-8')

    def signature(self, msg: bytes):
        if 'privkey' not in self.__dict__.keys():
            return "Do not have private key"
        m = func.power(int(sm3.sm3_hash(msg, typing='hex'), 16), self.privkey.d, self.privkey.n)
        return bytes(f"{m:x}", encoding='UTF-8')

    def verify(self, hash, sig) -> bool:
        if 'pubkey' not in self.__dict__.keys():
            return "Do not have public key"
        msg_hash = func.power(int(sig, 16), self.pubkey.e, self.pubkey.n)
        sss = bytes(f"{msg_hash:0256x}"[-len(hash):], encoding='UTF-8')
        return sss == hash
