import sys
import os
from platform import system
from string import ascii_uppercase, ascii_lowercase, digits, punctuation
from startPage import Ui_startPage
from genPassPage import Ui_passwordGen
from PyQt5 import QtWidgets, QtCore
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

global KEYPATH, VAULTPATH   # global variabls to store paths to vault and key file


class MainWindow(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ui = Ui_startPage()
        self.ui.setupUi(self)   # initializes start page
        self.ui.startButton.clicked.connect(self.createVaultFiles)
        self.ui.selectKeyFile.clicked.connect(self.getKeyFile)
        self.ui.selectVaultFile.clicked.connect(self.getVaultFile)
        self.ui.openButton.clicked.connect(self.openVaultFiles)
        # button variabls which execute a specific function

    def createVaultFiles(self):
        key = get_random_bytes(32)  # 32 bytes is 256 bits
        data = b''  # basic data for file to encrypt
        desktopPath = getPathToDesktop()    # gets path to desktop
        keyFile = open(desktopPath + "\\key.bin", "wb")
        keyFile.write(key)  # writes encryption key to file
        keyFile.close
        cipher = AES.new(key, AES.MODE_CBC)
        ciphered_data = cipher.encrypt(pad(data, AES.block_size))
        vaultFile = open(desktopPath + "\\vault.bin", "wb")     # creates vault file
        vaultFile.write(cipher.iv)
        vaultFile.write(ciphered_data)
        vaultFile.close()
        Alert("Process Completed", QtWidgets.QMessageBox.Information, "Created vault.bin and key.bin")
        # Alert function to reuse the code to generate a QMessageBox

    def getKeyFile(self):
        file = QtWidgets.QFileDialog.getOpenFileName(
            self, 'Open file', "~", "All Files (*)")  # lets user choose files from explorer
        url = QtCore.QUrl.fromLocalFile(file[0])    # gets path to file and stores it as an object
        self.ui.keyFileLabel.setText(url.fileName())    # adjusts file name in gui
        self.ui.keyFileLabel.adjustSize()   # adjusts size of text wrapper for file name in gui
        self.keyPath = file[0]  # makes keyPath accessible in all of MainWindow class

    def getVaultFile(self):
        file = QtWidgets.QFileDialog.getOpenFileName(
            self, 'Open file', "~", "All Files (*)")  # lets user choose files from explorer
        url = QtCore.QUrl.fromLocalFile(file[0])    # gets path to file and stores it as an object
        self.ui.vaultFileLabel.setText(url.fileName())   # adjusts file name in gui
        self.ui.vaultFileLabel.adjustSize()     # adjusts size of text wrapper for file name in gui
        self.vaultPath = file[0]    # makes vaultPath accessible in all of MainWindow class

    def openVaultFiles(self):
        keyFile = self.ui.keyFileLabel.text()
        vaultFile = self.ui.vaultFileLabel.text()
        if (keyFile == "Key File") or (vaultFile == "Vault File"):
            # checks that a Key File or Vault file have been selected
            Alert("Error", QtWidgets.QMessageBox.Critical,
                  "Either one or no files were selected. Please select files to open the vault")
            # Alert function to display error QMessageBox
        else:
            # exception handling
            try:
                getData(self.keyPath, self.vaultPath)
                # display new window for generating password or viewing accounts
                self.newWindow = generatePasswordWin()
                self.newWindow.show()   # show new window
                self.hide()  # close old window
            except ValueError:
                Alert("Error", QtWidgets.QMessageBox.Critical, "Incorrect files selected")
                # Alert function to show error message


class generatePasswordWin(QtWidgets.QWidget):
    # displays generate password window when vault is open
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ui = Ui_passwordGen()
        self.ui.setupUi(self)
        self.ui.genBtn.clicked.connect(self.genPassword)

    def genPassword(self):
        passwordOptions = ""
        if self.ui.lowerCaseCheck.isChecked():
            passwordOptions += ascii_lowercase
        if self.ui.upperCaseCheck.isChecked():
            passwordOptions += ascii_uppercase
        if self.ui.numbersCheck.isChecked():
            passwordOptions += digits
        if self.ui.numbersCheck.isChecked():
            passwordOptions += punctuation
        print(passwordOptions)


def getPathToDesktop():
    # path to desktop is different on windows and unix systems as on windows the drive the desktop is on can be changed
    if system() == 'Windows':
        desktopPath = os.environ["HOMEPATH"] + "\Desktop"  # finds path to desktop
        for driveLetter in ascii_uppercase:  # find drive desktop folder is on
            if os.path.exists("{0}:{1}".format(driveLetter, desktopPath)):
                desktopPath = "{0}:{1}".format(driveLetter, desktopPath)
    else:
        desktopPath = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
    return desktopPath


def Alert(title, icon, text):
    # creates QMessageBox based on arguements in function
    message = QtWidgets.QMessageBox()
    message.setWindowTitle(title)
    message.setIcon(icon)
    message.setText(text)
    message.exec_()


def getData(pathToKey, pathToVault):    # allows me to access Paths throughout document
    global KEYPATH, VAULTPATH
    KEYPATH, VAULTPATH = pathToKey, pathToVault
    readVaultFile = open(VAULTPATH, 'rb')  # Open the file to read bytes
    iv = readVaultFile.read(16)  # Read the iv out - this is 16 bytes long
    ciphered_data = readVaultFile.read()  # Read the rest of the data
    readVaultFile.close()
    readKeyFile = open(KEYPATH, 'rb')
    key = readKeyFile.read()
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)  # Setup cipher
    # Decrypt and then up-pad the result
    data = unpad(cipher.decrypt(ciphered_data), AES.block_size)
    return data


if __name__ == "__main__":
    # displays when starting application
    app = QtWidgets.QApplication(sys.argv)
    startPage = MainWindow()
    startPage.show()
    sys.exit(app.exec_())
