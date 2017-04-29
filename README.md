# A clever Malware Analysis Platform
Investigation of Digital Forensic Techniques - University of Manchester Master's Project

## Description

As part of my master's project about malware detection and classification, I build this WebApp to perform classification and detection of different malware.
Any help or requests can be made. The App was built, as far as possible, with scalabality allowing anyone to add a plugin (notably in machine learning algorithm).

## Installation

OS X & Linux:

```sh
sudo apt-get install python3 python3-pip virtualenv 
pip install autoenv
echo `which activate.sh` >> ~/.bashrc
git clone https://github.com/gregorygui/digitalforensic.git
virtualenv -p python3.5 venv
echo "source $(pwd)/venv/bin/activate">.env
source venv/bin/activate
pip install --upgrade pip
pip install -U pip setuptools
pip install -r requirements.txt
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