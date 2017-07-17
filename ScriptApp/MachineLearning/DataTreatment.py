import sqlite3
import numpy as np

def listTreatment(c):
	l=[]

	for v in c.fetchall():
		l+=v
	
	return l

def get_default_criterion(c):
	l=[]
	c.execute("SELECT name FROM classification_defaultcriterion")
	
	return listTreatment(c)

def get_criterions(c, fid):
	l=[]
	t=(fid,)
	c.execute("SELECT name FROM classification_filecriterion WHERE file_id=?", t)

	return listTreatment(c)

def get_files(c):
	l=[]
	c.execute("SELECT id FROM classification_file")

	return listTreatment(c)

def isMalicious(c, fid):
	t=(fid,)
	c.execute("SELECT maliciousness FROM classification_file WHERE id=?", t)
	m = (listTreatment(c))[0]

	if m > 7:
		return True
	else:
		return False

def get_data(c):
	dc = get_default_criterion(c)
	ar=[]
	for fid in get_files(c):
		row = [0] * (len(dc)+1)
		
		for crit in get_criterions(c, fid):
			row[dc.index(crit)]=1

		if isMalicious(c, fid):
			row[-1]=1
		else:
			row[-1]=0
		
		ar.append(row)
	
	return ar

def build_dataset():
	db = sqlite3.connect('samples.sqlite3')
	c = db.cursor()
	
	dataset={}
	dataset['features_names'] = get_default_criterion(c)
	dataset['data'] = (get_data(c))[:-1]
	dataset['targets'] = False
	dataset['description'] = "Automatic built dataset based on malware samples from the web application. Features are criterions to define if it is malicious or not"

	db.close()
	print(dataset)

	return dataset

if __name__ == '__main__':
	build_dataset()