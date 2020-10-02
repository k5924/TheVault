import sys
import os
import random
from platform import system
from string import ascii_uppercase, ascii_lowercase, digits, punctuation
from startPage import Ui_startPage
from genPassPage import Ui_passwordGen
from allAccountsPage import Ui_allAccounts
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
        data = ''.encode('utf-8')  # basic data for file to encrypt
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
            self, 'Open file', "", "All Files (*)")  # lets user choose files from explorer
        url = QtCore.QUrl.fromLocalFile(file[0])    # gets path to file and stores it as an object
        self.ui.keyFileLabel.setText(url.fileName())    # adjusts file name in gui
        self.ui.keyFileLabel.adjustSize()   # adjusts size of text wrapper for file name in gui
        self.keyPath = file[0]  # makes keyPath accessible in all of MainWindow class

    def getVaultFile(self):
        file = QtWidgets.QFileDialog.getOpenFileName(
            self, 'Open file', "", "All Files (*)")  # lets user choose files from explorer
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
                key, iv, data = getData(self.keyPath, self.vaultPath)
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
        self.ui.saveBtn.clicked.connect(self.savePassword)
        self.ui.viewAccountsTab.clicked.connect(self.openAccountsPage)

    def genPassword(self):
        passwordOptions = ""
        if self.ui.lowerCaseCheck.isChecked() or self.ui.upperCaseCheck.isChecked() or self.ui.numbersCheck.isChecked() or self.ui.specialCharsCheck.isChecked():
            if self.ui.lowerCaseCheck.isChecked():
                passwordOptions += ascii_lowercase
            if self.ui.upperCaseCheck.isChecked():
                passwordOptions += ascii_uppercase
            if self.ui.numbersCheck.isChecked():
                passwordOptions += digits
            if self.ui.specialCharsCheck.isChecked():
                passwordOptions += punctuation
            lengths = [i for i in range(8, 17)]
            passLength = random.choice(lengths)
            password = ""
            for i in range(0, passLength):
                password += random.choice(passwordOptions)
            self.ui.generatedPassLabel.setText(password)
            self.ui.nameOfAccountEdit.setEnabled(True)
            self.ui.usernameEdit.setEnabled(True)
            self.ui.saveBtn.setEnabled(True)
        else:
            Alert("Error", QtWidgets.QMessageBox.Critical, "No options to generate password from")

    def savePassword(self):
        if (self.ui.nameOfAccountEdit.text() == (None or "")) or (self.ui.usernameEdit.text() == (None or "")):
            Alert("Error", QtWidgets.QMessageBox.Critical,
                  "Account name or Username has been left empty")
        else:  # displays any error message if the user input fields are empty or incorrectly entered
            if (self.ui.nameOfAccountEdit.text()[0] == " ") or (self.ui.nameOfAccountEdit.text()[-1] == " "):
                Alert("Error", QtWidgets.QMessageBox.Critical,
                      "Please remove spaces from the beginning or end of Account name")
            elif " " in self.ui.usernameEdit.text():
                Alert("Error", QtWidgets.QMessageBox.Critical,
                      "Please remove spaces from Username")
            else:
                nameOfAccount = self.ui.nameOfAccountEdit.text()
                username = self.ui.usernameEdit.text()
                password = self.ui.generatedPassLabel.text()
                writeData(nameOfAccount, username, password)
                Alert("Process Completed", QtWidgets.QMessageBox.Information, "Account saved")
                # reset check boxes after saving accounts
                self.ui.lowerCaseCheck.setChecked(False)
                self.ui.upperCaseCheck.setChecked(False)
                self.ui.numbersCheck.setChecked(False)
                self.ui.specialCharsCheck.setChecked(False)
                # the code below resets that generatedPassLabel, nameOfAccount input and username input after saving
                self.ui.generatedPassLabel.setText("")
                self.ui.nameOfAccountEdit.setText("")
                self.ui.usernameEdit.setText("")
                self.ui.nameOfAccountEdit.setEnabled(False)
                self.ui.usernameEdit.setEnabled(False)

    def openAccountsPage(self):  # opens window to view all accounts
        self.newWindow = allAccountsWin()
        self.newWindow.show()   # show new window
        self.hide()  # close old window


class allAccountsWin(QtWidgets.QWidget):    # view all accounts window
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ui = Ui_allAccounts()
        self.ui.setupUi(self)
        # button which links to generate password window
        self.ui.genPassTab.clicked.connect(self.openGeneratePassTab)

    def openGeneratePassTab(self):  # open generate password window
        self.newWindow = generatePasswordWin()
        self.newWindow.show()   # show new window
        self.hide()  # close old window


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
    readKeyFile.close()
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)  # Setup cipher
    # Decrypt and then up-pad the result
    data = unpad(cipher.decrypt(ciphered_data), AES.block_size)
    return key, iv, data


def writeData(nameOfAccount, username, password):   # writes name of account, username and password to vaultFile
    global KEYPATH, VAULTPATH
    key, iv, data = getData(KEYPATH, VAULTPATH)
    data += ("{},{},{}\n".format(nameOfAccount, username, password)).encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphered_data = cipher.encrypt(pad(data, AES.block_size))
    vaultFile = open(VAULTPATH, "wb")     # creates vault file
    vaultFile.write(cipher.iv)
    vaultFile.write(ciphered_data)
    vaultFile.close()


if __name__ == "__main__":
    # displays when starting application
    app = QtWidgets.QApplication(sys.argv)
    startPage = MainWindow()
    startPage.show()
    sys.exit(app.exec_())
