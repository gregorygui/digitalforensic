# A clever Malware Analysis Platform
Investigation of Digital Forensic Techniques - University of Manchester Master's Project

## Description

As part of my master's project about malware detection and classification, I build this WebApp to perform classification and detection of different malware.
Any help or requests can be made. The App was built, as far as possible, with scalabality allowing anyone to add a plugin (notably in machien elarning algorithm).

## Installation

Download the project with https or git.
```sh
git clone https://github.com/gregorygui/digitalforensic.git
```

OS X & Linux:

```sh
sudo apt-get install python3 python3-pip
sudo pip3 install django scipy numpy scikit-learn
```

You also have to define your default version of python to 3.
The best way is to add an alias to your ```.bashrc``` located in your home. (You can do the same thing for pip)

```sh
alias python='python3'
alias pip='pip3'
```

***

## Usage example

## Development setup

To launch the django server, execute the script ```LaunchServer.sh``` in MalwareAnalysis directory. By default the server uses **port 8080**.
```sh
./LaunchServer
```

## Contributors

[mailto:gregory.guillermin@postgrad.manchester.ac.uk]Grégory Guillermin @ [https://winto.xyz]Winto

[http://scikit-learn.org] Scikit API

[http://vxheaven.org/] VX Heaven Dataset

## Licence