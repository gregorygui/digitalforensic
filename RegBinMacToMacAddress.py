from winreg import *
import mechanize, urllib, re, urlparse

# Transform regbin mac address value in common mac address value
def val2macaddr(val):
	addr=""
	for c in val:
		addr+=("%02x "% ord(ch))
	addr=addr.strip(" ").replace(" ",":")[0:17]
	return addr

# Connect to wigle with credentials to get the geolocalisation of the mac address
def wiglePrint(username, password, netid):
	browser = mechanize.Browser()
	browser.open('http://wigle.net')
	reqData = urllib.urlencode({'credential_0': username,'credential_1': password})
	browser.open('https://wigle.net/gps/gps/main/login', reqData)
	params = {}
	params['netid'] = netid
	reqParams = urllib.urlencode(params)
	respURL = 'http://wigle.net/gps/gps/main/confirmquery/'
	resp = browser.open(respURL, reqParams).read()
	mapLat = 'N/A'
	mapLon = 'N/A'
	rLat = re.findall(r'maplat=.*\&', resp)
	if rLat:
		mapLat = rLat[0].split('&')[0].split('=')[1]
	rLon = re.findall(r'maplon=.*\&', resp)
	if rLon:
		mapLon = rLon[0].split
	print('[-] Lat: ' + mapLat + ', Lon: ' + mapLon)

# Get networks registered in windows registry to print and geolocalise them
def printNets(username,password):
	net = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\\NetworkList\Signatures\\Unmanaged"
	print(net)
	key=OpenKey(HKEY_LOCAL_MACHINE,net)
	print('\n[*] Networks You have Joined.')
	for i in range(100):
		try:
			guid = EnumKey(key, i)
			netKey = OpenKey(key, str(guid))
			(n, addr, t) = EnumValue(netKey, 5)
			(n, name, t) = EnumValue(netKey, 4)
			macAddr = val2addr(addr)
			netName = str(name)
			print('[+] ' + netName + ' ' + macAddr)
			wiglePrint(username, password, macAddr)
			CloseKey(netKey)
		except:
			break

# Main function of the script with arguments parsing
def main():
	parser = optparse.OptionParser("usage%prog "+"-u <wigle username> -p <wigle password>")
	parser.add_option('-u', dest='username', type='string',help='specify wigle password')
	parser.add_option('-p', dest='password', type='string',help='specify wigle username')
	(options, args) = parser.parse_args()
	username = options.username
	password = options.password
	if username == None or password == None:
		print(parser.usage)
		exit(0)
	else:
		printNets(username, password)

if __name__=="__main__":
	main()