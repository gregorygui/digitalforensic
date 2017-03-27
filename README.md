# A clever Malware Analysis Platform
Investigation of Digital Forensic Techniques - University of Manchester Master's Project

## Description

As part of my master's project about malware detection and classification, I build this WebApp to perform classification and detection of different malware.
Any help or requests can be made. The App was built, as far as possible, with scalabality allowing anyone to add a plugin (notably in machien elarning algorithm).

## Installation

OS X & Linux:

```sh
sudo apt-get install python3 python3-pip python3-pyvenv python3-virtualenv
sudo apt-get install python3-autoenv
mkdir PATH/DIRECTORY
cd PATH/DIRECTORY
git clone https://github.com/gregorygui/digitalforensic.git
pyvenv env
echo "source $(pwd)/env/bin/activate">.env
source env/bin/activate
pip install django bs4 requests scipy numpy scikit-learn
```

***

## Usage example

## Development setup

To launch the django server, execute the script ```LaunchServer.sh``` in MalwareAnalysis directory. By default the server uses **port 8080**.
```sh
./LaunchServer
```

## Contributors

Grégory Guillermin | https://winto.xyz | gregory.guillermin@postgrad.manchester.ac.uk

http://scikit-learn.org - Scikit API

http://vxheaven.org/ - VX Heaven Dataset

## Licence
