import pefile
import peutils

import string
import datetime
import hashlib
import uuid
import re

from math import log

from PEFileAnalyzer.MalwareDefinition import inconsistentCompileDate, VTScore, get_size, detectRemoteConnection, inconsistentSections, stringsScore, functionScore, sectionsOverflow, overSized

criterions=dict()

criterions['compileDate']={'name':'Inconsistent Compilation Date','function':'inconsistentCompileDate', 'coef':90}
criterions['VTScore']={'name':'Virus Total Score', 'function':'VTScore', 'coef':80}
criterions['inconsistentSections']={'name':'Inconsistent Section Name(s)', 'function':'inconsistentSections', 'coef':60}
criterions['maliciousFunction']={'name':'Malicious Function(s)', 'function':'functionScore', 'coef':70}
criterions['overSized']={'name':'Oversized File', 'function':'overSized', 'coef':30}
# criterions['ipdetected']={'name':'IP Pattern Detected','function':'detectIP', 'coef':50}
criterions['remoteconnection']={'name':'Remote Connection detected', 'function':'detectRemoteConnection', 'coef':70}
criterions['maliciousStrings']={'name':'Malicious String(s)', 'function':'stringsScore', 'coef':70}

def defaultCriterions():
	return criterions

def execute_func(f, peData):
	if f == 'inconsistentCompileDate':
		return globals()[f](peData.getDate())
	elif f == 'detectRemoteConnection':
		return globals()[f](peData.getStrings())
	elif f == 'inconsistentSections':
		return globals()[f](peData.getSections())
	elif f == 'VTScore':
		return globals()[f](peData.getMD5())
	elif f == 'functionScore':
		return globals()[f](peData.getImports())
	elif f == 'overSized':
		return globals()[f](peData.filename)
	elif f == 'sectionsOverflow':
		return globals()[f](peData.getSections())
	elif f == 'stringsScore':
		return globals()[f](peData.getDefStr(), peData.getStrings())

class peData:
 	"""Analyze a PE file"""
 	def __init__(self, filename, sign, strDict=None):
 		self.filename=filename
 		self.file = pefile.PE(filename)
 		self.signatures = peutils.SignatureDatabase(sign)
 		self.strDict=strDict

 	def getOEP(self):
 		return self.file.OPTIONAL_HEADER.AddressOfEntryPoint

 	def getSections(self):
 		dictSections={}
 		for section in self.file.sections:
 			key=section.Name
 			dictSections[(key.decode('ascii')).rstrip('\x00')]=section.VirtualAddress
 		return dictSections

 	def getImports(self):
 		if hasattr(self.file, 'DIRECTORY_ENTRY_IMPORT'):
 			dictImports={}
 			
 			for entry in self.file.DIRECTORY_ENTRY_IMPORT:
 				e=entry.dll
 				listImports=[]
 				
 				if entry.imports and entry.dll:
 					for i in entry.imports:
 						listImports.append((i.name).decode('ascii'))

 				dictImports[e.decode('ascii')]=listImports
 			return dictImports
 		
 		else:
 			return None

 	def getSize(self):
 		return get_size(self.filename)

 	def getExports(self):
 		listExports=[]
 		if hasattr(self.file, 'DIRECTORY_ENTRY_EXPORT'):

 			for e in self.file.DIRECTORY_ENTRY_EXPORT.symbols:
 				listExports.append(e.name.decode('ascii'))
 			return listExports
 		else:
 			return None

 	def isPacked(self):
 		try:
 			return self.signatures.match(self.file, ep_only=True)[0]
 		except:
 			return "None"

 	def getStrings(self):
 		strings=list()
 		f=open(self.filename,errors="ignore")
 		s=""
 		regS='\w{4,}'

 		for c in f.read():
 			if c in string.printable:
 				s+=c
 				continue
 		
 			if re.match(regS, s, flags=re.IGNORECASE):
 				strings.append(s)
 		
 			s=""
 		
 		if len(s)>=4:
 			strings.append(s)

 		f.close()

 		return strings

 	def getDefStr(self):
 		return self.strDict

 	def setDefStr(self, d):
 		self.strDict=d

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