# -*- coding: utf-8 -*-
#!/usr/bin/env python
def range_prime(start, end):
  l = list()
  for i in range(start, end+1):
    flag = True
    for j in range(2, i):
      if i % j == 0:
        flag = False
        break
    if flag:
      l.append(i)
  return l
def generate_keys(p, q):
  #numbers = (11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
  numbers =range_prime(2, 100)
  #print(numbers)
  N = p * q
  C = (p-1) * (q-1)
  e = 0
  for n in numbers:
    if n < C and C % n > 0:
      e = n
      break
  if e==0:
    raise BaseException("e not found") #Python3中改为BaseException
  d = 0
  for n in range(2, C):
    if(e * n) % C == 1:
      d = n
      break
  if d==0:
    raise BaseException("d not found")
  return ((N, e), (N, d))
def encrypt(m, key):
  C, x = key
  return (m ** x) % C
decrypt = encrypt
def encode(s):
  if type(s) == type('A'):
    return ord(s)
  if type(s) == type(1):
    return chr(s)
if __name__ == '__main__':
  print(range_prime(2, 100))
  p = int(input("请在以上选择一个数作为p输入:\n"))
  q = int(input("请在以上选择一个数作为q输入(q>p):\n"))
  pub, pri = generate_keys(p, q)
  M = range(20, 30)
  M ='admin'
  C = [(encrypt(encode(x), pub)) for x in M]
  D = [(encrypt(x, pri)) for x in C]
  #C = map(lambda x: encrypt(x, pub), L)
  #D = map(lambda x: decrypt(x, pri), C)
  print("============================================")
  print("             公钥:N",pub)
  print("             私钥:N",pri)
  print("  加密前以字符表示:",M)
  print("  加密前以数组表示:",[(encode(x)) for x in M])
  print("====================加密=====================")
  print("  加密后以数组表示:",C)
  print("  解密后以字符表示:",''.join([(encode(x)) for x in C]))
  print("====================解密=====================")
  print("  解密后以数组表示:",D)
  print("  解密后以字符表示:",''.join([(encode(x)) for x in D]))
  print("============================================")
