import math
import os

_IV = []

TEST1 = "abc"  #测试案例
TEST2 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"

_T = lambda j: 0x79CC4519 if j < 16 else 0x7A879D8A
_FF = lambda j, x, y, z: x ^ y ^ z if j < 16 else (x & y) | (x & z) | (y & z)
_GG = lambda j, x, y, z: x ^ y ^ z if j < 16 else (x & y) | (~x & z)
_rotl = lambda x, k: ((x << k % 32) & 0xffffffff) | ((x >> (32 - k % 32)) & 0xffffffff)
_p0 = lambda x: x ^ (_rotl(x, 9)) ^ (_rotl(x, 17))
_p1 = lambda x: x ^ (_rotl(x, 15)) ^ (_rotl(x, 23))


def _init(m, typing='text'):  #转换+迭代+分组
    global _IV  #初始化
    _IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    s = ""
    if typing == 'text':
        for ch in m:
            s = s + format(ord(ch), '08b')  #8位ascii码
    elif typing == 'hex':
        for i in m:
            s += f'{int(i,16):04b}'
    l = len(s)
    k = 512 - (l + 1 + 64) % 512
    s = s + '1' + k * '0' + format(l, '064b')
    li = []
    for i in range(0, len(s), 32):
        li.append(format(int('0b' + s[i:i + 32], 2), '08x'))
    return li


def _messageEx(B: list):  #消息扩展
    w = [int(B[j], 16) for j in range(16)]  #w[0-15]=B[0-15]
    for j in range(16, 68):
        w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)) ^ _rotl(w[j - 13], 7) ^ w[j - 6])
    w1 = [w[j] ^ w[j + 4] for j in range(64)]
    return (w, w1)


def _cf(trp):
    global _IV  #显式声明变量，当成全局变量处理
    R = _IV[:]  #ABCDEFGH<-IV
    for j in range(64):
        SS1 = (_rotl((_rotl(R[0], 12) + R[4] + _rotl(_T(j), j)) % 0x100000000, 7)) % 0x100000000
        SS2 = (SS1 ^ _rotl(R[0], 12)) % 0x100000000  #模拟32位寄存器的截断效果
        TT1 = (_FF(j, R[0], R[1], R[2]) + R[3] + SS2 + trp[1][j]) % 0x100000000
        TT2 = (_GG(j, R[4], R[5], R[6]) + R[7] + SS1 + trp[0][j]) % 0x100000000
        R[3] = R[2]
        R[2] = _rotl(R[1], 9)
        R[1] = R[0]
        R[0] = TT1
        R[7] = R[6]
        R[6] = _rotl(R[5], 19)
        R[5] = R[4]
        R[4] = _p0(TT2)
    _IV = [_IV[i] ^ R[i] for i in range(8)]  #异或操作


class sm3:

    @staticmethod
    def _convert_encode(msg, typing):  #调整编码规则
        ''' 模式:输入text,输入hex(输入bytes)
            默认:hash计算中为test,kdf中为hex'''
        if typing == 'text':
            if type(msg) is bytes:
                msg = msg.decode()
        elif typing == 'hex':
            msg = msg[2:] if msg[0:2] == b'0x' else msg
            if type(msg) is bytes:
                msg = msg.decode()
        return msg

    @classmethod
    def sm3_hash(cls, msg, *, typing='text') -> bytes:
        msg = cls._convert_encode(msg, typing)
        assert len(msg) < 2**64
        B = _init(msg, typing)
        for i in range(0, len(B), 16):  #每16个字为一组进行消息扩展
            _cf(_messageEx([B[i + j] for j in range(16)]))
        return bytes("".join([f"{i:08x}" for i in _IV]), encoding='UTF-8')

    @classmethod
    def sm3_kdf(cls, z, klen, *, typing='hex'):
        ''' Z:KDF所需的数据。
            klen:导出密钥的字节长度。'''
        z = cls._convert_encode(z, typing)
        ct = 0x00000001
        n = math.ceil(klen / 32)
        assert n < 2**32 - 1
        hash = b''
        for i in range(n):
            msg = z + f"{ct:08x}"
            hash += sm3.sm3_hash(msg, typing=typing)
            ct += 1
        return hash[:klen * 2]