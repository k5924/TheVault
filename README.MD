# The Vault

## Introduction

> This is an offline password manager as most online password managers store a users information on centralized servers. This gives an end user the ability to take control of how there data is being used and allows end users' to keep hold of their private data whilst interacting with a password manager with an easy to use interface. This project was made for coursework while i was in my 2nd Year of studying Computer Science at LSBU for the Software Engineering module.

## Installation

> If you are compiling the code from source then ensure that python is installed on the machine with pip added to Path in the environment variables on windows. Through pip Run:
<pre><code>pip install pyqt5 pycryptodome</pre></code>
> If pycryptodome fails to install, try running:
<pre><code>pip uninstall crypto cryptography pycrypto pycryptodomex</pre></code>
> Then re-run:
<pre><code>pip install pycryptodome</pre></code>
> This should install pycryptodome and PyQt5 for an end user to modify how the software works.<br><br>
Additionally, you could run:
<pre><code>pip install pyqt5-tools</pre></code>
> This will give you PyQt tools such as designer which will allow you to create the user interface via a drag an drop program.<br>
To export the interface that you have created in Qt Designer as a python file, Run:
<pre><code>pyuic5 -o "nameOfOutputFile.py" "path/to/ui/file.ui"</pre></code>
> Or to get the interface you made as a python file that you want to run without another file to setup the interface run:
<pre><code>pyuic5 -x -o "nameOfOutputFile.py" "path/to/ui/file.ui"</pre></code>

## Demo
>[![Demonstration Video](https://img.youtube.com/vi/mEqxIAc4rQM/0.jpg)](https://www.youtube.com/watch?v=mEqxIAc4rQM)

<h3 align="left">Languages and Tools:</h3>
<p align="left"> <a href="https://www.python.org" target="_blank"> <img src="https://devicons.github.io/devicon/devicon.git/icons/python/python-original.svg" alt="python" width="40" height="40"/> </a> <a href="https://www.riverbankcomputing.com/software/pyqt/" target="_blank"> <img src="https://upload.wikimedia.org/wikipedia/commons/0/0b/Qt_logo_2016.svg" alt="qt" width="40" height="40"/> </a> </p>
