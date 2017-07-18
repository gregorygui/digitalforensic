#!../venv3/bin/python

import sqlite3
import sys

from optparse import OptionParser

def main(argv):
	if len(argv)==1:
		db = sqlite3.connect(argv[0])
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
	else:
		print("usage: purgeDB.py <db_name>")

if __name__ == '__main__':
	main(sys.argv[1:])