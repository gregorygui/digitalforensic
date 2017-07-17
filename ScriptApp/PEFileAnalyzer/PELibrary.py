import pefile
import peutils

import string
import datetime
import hashlib
import uuid

from math import log

from MalwareDefinition import inconsistentCompileDate, VTScore, detectIP, inconsistentSections

criterions=dict()

criterions['compileDate']={'name':'Inconsistent Compilation Date','function':'inconsistentCompileDate', 'coef':90}
criterions['VTScore']={'name':'Virus Total Score', 'function':'VTScore', 'coef':80}
criterions['ipdetected']={'name':'IP Pattern Detected','function':'detectIP', 'coef':50}
criterions['inconsistentSections']={'name':'Inconsistent Section Name(s)', 'function':'inconsistentSections', 'coef':60}

def defaultCriterions():
	return criterions

def execute_func(f, peData):
	if f == 'inconsistentCompileDate':
		return globals()[f](peData.getDate())
	elif f == 'detectIP':
		return globals()[f](peData.getStrings())
	elif f == 'inconsistentSections':
		return globals()[f](peData.getSections())
	elif f == 'VTScore':
		return globals()[f](peData.getMD5())

class peData:
 	"""Analyze a PE file"""
 	def __init__(self, filename, sign):
 		self.filename=filename
 		self.file = pefile.PE(filename)
 		self.signatures = peutils.SignatureDatabase(sign)

 	def getOEP(self):
 		return self.file.OPTIONAL_HEADER.AddressOfEntryPoint

 	def getSections(self):
 		dictSections={}
 		for section in self.file.sections:
 			key=section.Name
 			dictSections[key.decode('ascii')]=section.VirtualAddress
 		return dictSections

 	def getImports(self):
 		if hasattr(self.file, 'DIRECTORY_ENTRY_IMPORT'):
 			listImports={}
 			
 			for entry in self.file.DIRECTORY_ENTRY_IMPORT:
 				e=entry.dll
 				
 				if entry.imports:
 					for i in entry.imports:
 						listImports[e.decode('ascii')]=(i.name).decode('ascii')
 			
 			return listImports
 		
 		else:
 			return None

 	def getExports(self):
 		listExports=[]
 		if hasattr(self.file, 'DIRECTORY_ENTRY_EXPORT'):
 			for e in self.file.DIRECTORY_ENTRY_EXPORT.symbols:
 				listExports+=(e.name).decode('ascii')
 			return listExports
 		else:
 			return None

 	def isPacked(self):
 		try:
 			return self.signatures.match(self.file, ep_only=True)[0]
 		except:
 			return ""

 	def getStrings(self):
 		strings=list()
 		f=open(self.filename,errors="ignore")
 		s=""
 		for c in f.read():
 			if c in string.printable:
 				s+=c
 				continue
 			if len(s)>=4:
 				strings.append(s)
 			s=""
 		if len(s)>=4:
 			strings.append(s)
 		f.close()

 		return strings

 	def getDate(self):
 		timestamp=self.file.FILE_HEADER.TimeDateStamp
 		return datetime.datetime.fromtimestamp(timestamp)

 	def extractFromFile(self, filename):
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

 	def getEntropy(self):
 		d=self.extractFromFile(self.filename)
 		ent=0.0
 		tot=sum(d.values())
 		for v in d.values():
 			p=float(v)/tot
 			ent-=(p*log(p)/log(2))
 		return ent

 	def getMD5(self):
 		return hashlib.md5(open(self.filename, 'rb').read()).hexdigest()

 	def getSHA256(self):
 		return hashlib.sha256(open(self.filename, 'rb').read()).hexdigest()

 	def getCriterions(self):
 		crit=dict()

 		for c in criterions:
 			val=criterions[c]
 			sc=execute_func(val['function'], self)
 			
 			if sc > 0:
 				val['score']=sc
 				crit[c]=val

 		return crit

def main():

	signatures = peutils.SignatureDatabase('/home/harrapx/Desktop/digitalforensic/MalwareAnalysis/MalwareAnalysis/userdb.txt')
	

	file="/home/harrapx/Documents/MalwareLabs/BinaryCollection/Chapter_1L/Lab01-02.exe"
	Packedfile="/home/harrapx/Documents/MalwareLabs/BinaryCollection/Chapter_11L/Lab11-03.exe"
	pe=peData(file, '/home/harrapx/Desktop/digitalforensic/MalwareAnalysis/MalwareAnalysis/userdb.txt')
	
	t=pefile.PE(file)
	#print(signatures.match(t, ep_only=True)[0])

	print(pe.getCriterions())

if __name__ == '__main__':
	main()