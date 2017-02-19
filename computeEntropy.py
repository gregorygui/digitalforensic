#!/usr/bin/python3

from math import log

def computeEntropy(d):
	ent=0.0
	tot=sum(d.values())
	for v in d.values():
		p=float(v)/tot
		ent-=(p*log(p)/log(2))
	return ent

def extractFromFile(filename):
	f=open(filename,'rb')
	arrayByte={}
	byte=f.read(1)
	while (byte):
		if byte not in arrayByte:
			arrayByte[byte]=0
		arrayByte[byte]+=1
		byte=f.read(1)
	f.close()
	return arrayByte

def entropy(filename):
	a=extractFromFile(filename)
	return computeEntropy(a)

def main():
	file="test.txt"
	print(entropy(file))

if __name__ == '__main__':
	main()