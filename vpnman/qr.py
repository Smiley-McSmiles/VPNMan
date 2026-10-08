"""A small QR code encoder (byte mode, versions 1-40), so share links can be shown as QR codes without extra packages.

Follows ISO/IEC 18004 (and Project Nayuki's reference implementation).  ``encode(text)`` returns the matrix as a list of
rows of booleans (True = dark), without the quiet zone.
"""

# error correction codewords per block and number of blocks, by level and version (index 0 unused)
_ECC_PER_BLOCK = {
    "L": (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30,
          30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    "M": (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28,
          28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
}
_BLOCKS = {
    "L": (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17,
          18, 19, 19, 20, 21, 22, 24, 25),
    "M": (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29,
          31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
}
_FORMAT = {"L": 1, "M": 0}


class TooLong(ValueError):
    pass


def _raw_modules(ver):
    n = (16 * ver + 128) * ver + 64
    if ver >= 2:
        k = ver // 7 + 2
        n -= (25 * k - 10) * k - 55
        if ver >= 7:
            n -= 36
    return n


def _data_codewords(ver, ecl):
    return _raw_modules(ver) // 8 - _ECC_PER_BLOCK[ecl][ver] * _BLOCKS[ecl][ver]


def _gf_mul(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree):
    res = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            res[j] = _gf_mul(res[j], root)
            if j + 1 < degree:
                res[j] ^= res[j + 1]
        root = _gf_mul(root, 0x02)
    return res


def _rs_remainder(data, divisor):
    res = [0] * len(divisor)
    for b in data:
        factor = b ^ res.pop(0)
        res.append(0)
        for i, coef in enumerate(divisor):
            res[i] ^= _gf_mul(coef, factor)
    return res


def _codewords(data, ver, ecl):
    """Data bytes -> the final sequence of data + error correction codewords, interleaved."""
    nblocks, ecclen = _BLOCKS[ecl][ver], _ECC_PER_BLOCK[ecl][ver]
    raw = _raw_modules(ver) // 8
    nshort, shortlen = nblocks - raw % nblocks, raw // nblocks
    div = _rs_divisor(ecclen)
    blocks, k = [], 0
    for i in range(nblocks):
        dat = data[k:k + shortlen - ecclen + (0 if i < nshort else 1)]
        k += len(dat)
        ecc = _rs_remainder(dat, div)
        if i < nshort:
            dat = dat + [0]
        blocks.append(dat + ecc)
    out = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != shortlen - ecclen or j >= nshort:
                out.append(blk[i])
    return out


def _alignment_positions(ver, size):
    if ver == 1:
        return []
    k = ver // 7 + 2
    step = (ver * 8 + k * 3 + 5) // (k * 4 - 4) * 2
    return [6] + sorted(size - 7 - i * step for i in range(k - 1))


class _Matrix:
    def __init__(self, ver, ecl):
        self.ver, self.ecl = ver, ecl
        self.size = n = ver * 4 + 17
        self.m = [[False] * n for _ in range(n)]
        self.fn = [[False] * n for _ in range(n)]

    def set(self, x, y, dark):
        self.m[y][x] = dark
        self.fn[y][x] = True

    def function_patterns(self):
        n = self.size
        for i in range(n):
            self.set(6, i, i % 2 == 0)
            self.set(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (n - 4, 3), (3, n - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < n and 0 <= y < n:
                        self.set(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = _alignment_positions(self.ver, n)
        last = len(pos) - 1
        for i, ax in enumerate(pos):
            for j, ay in enumerate(pos):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.set(ax + dx, ay + dy, max(abs(dx), abs(dy)) != 1)
        self.format_bits(0)
        if self.ver >= 7:
            rem = self.ver
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            bits = self.ver << 12 | rem
            for i in range(18):
                b = (bits >> i) & 1 == 1
                a, c = n - 11 + i % 3, i // 3
                self.set(a, c, b)
                self.set(c, a, b)

    def format_bits(self, mask):
        n = self.size
        data = _FORMAT[self.ecl] << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412

        def bit(i):
            return (bits >> i) & 1 == 1
        for i in range(6):
            self.set(8, i, bit(i))
        self.set(8, 7, bit(6))
        self.set(8, 8, bit(7))
        self.set(7, 8, bit(8))
        for i in range(9, 15):
            self.set(14 - i, 8, bit(i))
        for i in range(8):
            self.set(n - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self.set(8, n - 15 + i, bit(i))
        self.set(8, n - 8, True)

    def codewords(self, data):
        n, i, total = self.size, 0, len(data) * 8
        right = n - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(n):
                for j in range(2):
                    x = right - j
                    y = n - 1 - vert if ((right + 1) & 2) == 0 else vert
                    if not self.fn[y][x] and i < total:
                        self.m[y][x] = (data[i >> 3] >> (7 - (i & 7))) & 1 == 1
                        i += 1
            right -= 2

    def apply_mask(self, mask):
        f = _MASKS[mask]
        for y in range(self.size):
            for x in range(self.size):
                if not self.fn[y][x] and f(x, y):
                    self.m[y][x] = not self.m[y][x]


_MASKS = (
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
)


def _penalty(m):
    """The standard's mask score (lower is better): long runs, 2x2 blocks, finder-like patterns, dark/light balance."""
    n, score = len(m), 0
    lines = [row for row in m] + [[m[y][x] for y in range(n)] for x in range(n)]
    finder_a, finder_b = "00001011101", "10111010000"
    for line in lines:
        run, prev = 0, None
        for v in line:
            if v == prev:
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run, prev = 1, v
        if run >= 5:
            score += run - 2
        s = "0000" + "".join("1" if v else "0" for v in line) + "0000"
        score += 40 * (s.count(finder_a) + s.count(finder_b))
    for y in range(n - 1):
        for x in range(n - 1):
            if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                score += 3
    dark = sum(sum(r) for r in m)
    total = n * n
    score += 10 * ((abs(dark * 20 - total * 10) + total - 1) // total - 1)
    return score


def encode(text, ecl=None):
    """Encode ``text`` (UTF-8) as a QR code; medium error correction when it fits, else low.  Raises TooLong."""
    data = list(text.encode("utf-8")) if isinstance(text, str) else list(text)
    for level in ((ecl,) if ecl else ("M", "L")):
        for ver in range(1, 41):
            count_bits = 8 if ver < 10 else 16
            if 4 + count_bits + 8 * len(data) <= _data_codewords(ver, level) * 8:
                return _build(data, ver, level, count_bits)
    raise TooLong("too long for a QR code (%d bytes)" % len(data))


def _build(data, ver, ecl, count_bits):
    bits = [0, 1, 0, 0] + [(len(data) >> i) & 1 for i in reversed(range(count_bits))]
    for b in data:
        bits += [(b >> i) & 1 for i in reversed(range(8))]
    capacity = _data_codewords(ver, ecl) * 8
    bits += [0] * min(4, capacity - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(words) < capacity // 8:
        words.append(pad)
        pad ^= 0xEC ^ 0x11
    mat = _Matrix(ver, ecl)
    mat.function_patterns()
    mat.codewords(_codewords(words, ver, ecl))
    best = None
    for mask in range(8):
        mat.apply_mask(mask)
        mat.format_bits(mask)
        score = _penalty(mat.m)
        if best is None or score < best[0]:
            best = (score, mask)
        mat.apply_mask(mask)                     # xor again: undo
    mat.apply_mask(best[1])
    mat.format_bits(best[1])
    return mat.m


def to_text(matrix, quiet=2):
    """Render for a terminal with half blocks (two rows per line), dark on a forced light background."""
    n = len(matrix)

    def dark(x, y):
        return 0 <= x < n and 0 <= y < n and matrix[y][x]
    lines = []
    for y in range(-quiet, n + quiet, 2):
        row = ""
        for x in range(-quiet, n + quiet):
            top, bottom = dark(x, y), dark(x, y + 1)
            row += "█" if top and bottom else "▀" if top else "▄" if bottom else " "
        lines.append("\033[30;47m" + row + "\033[0m")
    return "\n".join(lines)
