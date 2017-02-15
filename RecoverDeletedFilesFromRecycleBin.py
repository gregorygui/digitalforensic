import os
import winreg as wreg

def sid2user(sid):
	try:
		key=wreg.OpenKey(wreg.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"+'\\'+sid)
		(value, type) = wreg.QueryValueEx(key, 'ProfileImagePath')
		print(value)
		user = value.split('\\')[-1]
		return user
	except:
		return sid

def returnDir():
	dirs=['C:\\Recycler\\','C:\\Recycled\\','C:\\$Recycle.Bin\\']
	for recycleDir in dirs:
		if os.path.isdir(recycleDir):
			return recycleDir
	return None

def listFiles(dir):
	return os.listdir(dir)

def findRecycled(dir):
	people=listFiles(dir)
	for sid in people:
		try:
			files=listFiles(dir+sid)
			user=sid2user(sid)
			print('\n[*] Listing Files For User: ' + str(user))
			for f in files:
				print('[+] Found File: ' + str(f))
		except:
			continue

def main():
	rBin=returnDir()
	findRecycled(rBin)

if __name__ == '__main__':
	main()