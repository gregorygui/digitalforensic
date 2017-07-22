'''
Created on 15 juil. 2017

@author: Gregory
'''
import sqlite3
import requests
import os
import shutil
import time
import yaml

from MachineLearning import build_dataset, RandomForest, Bayesian

config = yaml.load(open('config.yml', 'r'))

def purgeDB(dbname):
	try:
		db = sqlite3.connect(dbname)
		c = db.cursor()

		l=[]

		c.execute("SELECT name FROM sqlite_master WHERE type='table';")

		for t in c.fetchall():
			l+=t

		for t in l:
			if 'sqlite' in t:
				continue
			elif 'classification' not in t:
				print("Deleting "+t+ " table...")
				c.execute("DROP TABLE IF EXISTS %s" % t)
		
		db.commit()

		db.close()

		return 1
	except:
		return -1

def uploadFile(f):
	start = time.clock()
	print("Uploading \""+f+"\" ...")
	base_url = config['HOST']
	client = requests.session()
	client.get(base_url)
	
	headers={'Referer':base_url+'add/'}
	files={'f':open(f, 'rb')}
	data={'csrfmiddlewaretoken':client.cookies['csrftoken'], 'Content-Type':'multipart/form-data'}

	r = client.post(base_url+'add/', headers=headers, data=data, files=files)

	if r.ok:
		if "files/details" in r.text:
			print(f+" has been uploaded...")
		else:
			print("Error was redirected to / for "+f)
	else:
		print("### ERROR during upload process of "+f+" ###")

def main():
	dbname = 'samples.sqlite3'
	
	try:
		DIR=config['SAMPLES_DIRECTORY']
		
		for f in os.listdir(DIR):
			start = time.clock()
			uploadFile(DIR+"/"+f)
			print("("+str(round(time.clock()-start,3))+"s)\n\n")
		
		shutil.copy2(config['DB_PATH'], dbname)
		purgeDB(dbname)
		print("Database purged...\nEnd of process...")
			
	except Exception as e:
		print("No database "+dbname+ "\nException: "+str(e))
    
if __name__ == '__main__':
    main()