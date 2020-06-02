from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
from Crypto.Random import get_random_bytes
from libnum import invmod

from collections import defaultdict


def test_p_q(p, q, e=0x10001, msg='Test'):
  assert p != q

  n = p * q
  phi = (p - 1) * (q - 1)
  d = invmod(e, phi)

  m = bytes_to_long(msg.encode('utf-8'))

  c = pow(m, e, n)
  res = pow(c, d, n)

  m2 = long_to_bytes(res).decode('utf-8')

  print(f"""
  p = {p:x}
  q = {q:x}
  d = {d:x}
  e = {e:x}
  n = {n:x}
  cipher = {c:x}
  plain = {m2}""")


def get_next_prime(start):
  # Returns prime p such that start <= p
  start_bytes = long_to_bytes(start)
  assert start_bytes[0] & 0x80 == 0x80, "Prime must have MSB set"

  def randfunc(n):
    #print(f"randfunc({start:x}, {n})")
    if n == len(start_bytes) - 1:
      # Starting bytes, big-endian, from which it iterates up
      return start_bytes[1:]

    if n == 1:
      # Bottom bits of top byte (it gets shifted right 1 and or'ed with 0x80)
      return bytes([(start_bytes[0] << 1) & 0xfe])

    if n == 65:
      # Presumably Miller-Rabin
      return get_random_bytes(1) * 65

  return getPrime(len(start_bytes) * 8, randfunc)


def primes_range(start, end):
  # Returns prime p such that start <= p < end
  n = get_next_prime(start)
  while n < end:
    n = get_next_prime(n + 1)
    yield n


# max_p[512] = 0x8000..010000
# max_n[1024] = 0x4000..010000..0100000000
# 0x8000..000000 < p < 0x8000..010000
# 0x8000..000000 < q < 0x8000..010000
# => 0x4000..000000..0000000000 < p * q < 0x4000..010000..0100000000

max_p = max_q = bytes_to_long(bytes([0x80] + [0] * 60 + [1, 0, 0]))
#max_p = max_q = bytes_to_long(bytes([0x80] + [0] * 60 + [0, 0x40, 0]))
max_n = max_p * max_q

start_p = bytes_to_long(bytes([0x80] + [0] * 63))
start_n = start_p * start_p

results = defaultdict(list)

count = 0
for p in primes_range(start_p, max_p):
  print(hex(p))
  start_q = get_next_prime(p + 1)
  for q in primes_range(start_q, max_q):
    n = p * q
    if n >= max_n:
      break

    n_middle = bytes_to_long(long_to_bytes(n)[62:64])
    results[n_middle].append((p, q))


most_pqs = max(len(pqs) for pqs in results.values())
for k, pqs in results.items():
  if len(pqs) == most_pqs:
    print(f"{k:x}: {len(pqs)}")

    for p, q in pqs:
      try:
        test_p_q(p, q)
      except Exception as e:
        print(f"{p:x}, {q:x} failed: {e}")

    print()
    print(f"middle = 0x{k:x}")
    suffixes = ', '.join([hex((p * q) & 0xffffffff) for p, q in pqs])
    print(f"suffixes = [{suffixes}]")
    break


