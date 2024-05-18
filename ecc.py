import func

unit = (0, 0)  #无穷远点


class curve(object):  #y^2=x^3+ax+b
    '''ec curve'''

    def __init__(self, name) -> None:
        self.name = name
        if name == 'secp256k1':
            self.p, self.a, self.b, self.G, self.n, self.h = (
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0, 7,
                (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141, 1)
        elif name == 'test':
            self.p, self.a, self.b, self.G, self.n, self.h = (11, 1, 6, (2, 7), 8, 1)

    def _add(self, p1, p2) -> tuple:
        if p1 == unit or p2 == unit:
            return p1 if p2 == unit else p2
        elif p1[0] == p2[0] and (p1[1] + p2[1]) % self.p == 0:
            return unit
        assert self.is_on_curve(p1) and self.is_on_curve(p2)

        (x1, y1), (x2, y2) = p1, p2
        if p1 == p2:
            m = ((3 * x1**2 + self.a) * func.inv(2 * y1, self.p)) % self.p
        else:
            m = ((y2 - y1) * func.inv(x2 - x1, self.p)) % self.p
        x3 = (m**2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def _double(self, p) -> tuple:
        return self._add(p, p)

    def nPoint(self, n, p: tuple) -> tuple:
        r0, r1 = unit, p
        s = f"{n:b}"
        for i in s:
            if i == '0':
                r1 = self._add(r0, r1)
                r0 = self._double(r0)
            else:
                r0 = self._add(r0, r1)
                r1 = self._double(r1)
        return r0

    def is_on_curve(self, p) -> bool:  #判断点是否在曲线上，无穷远点也在曲线上
        x, y = p
        return (x**3 + self.a * x + self.b - y**2) % self.p == 0 or p == unit
