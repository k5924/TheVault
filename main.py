import sys
import os
import random
import csv
import json
from platform import system
from string import ascii_uppercase, ascii_lowercase, digits, punctuation
from startPage import Ui_startPage
from genPassPage import Ui_passwordGen
from allAccountsPage import Ui_allAccounts
from AddAccountPage import Ui_addAccount
from viewAccountPage import Ui_viewAccount
from changePassPage import Ui_changePass
from importAccountsPage import Ui_importAccounts
from PyQt5 import QtWidgets, QtCore, QtGui
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# global variabls to store paths to vault and key file
global KEYPATH, VAULTPATH, VIEWEDITEM


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
            except (ValueError, FileNotFoundError) as e:
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
                passwordOptions += punctuation.replace(',', '')
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
            elif ("," in self.ui.nameOfAccountEdit.text()) or ("," in self.ui.usernameEdit.text()):
                Alert("Error", QtWidgets.QMessageBox.Critical,
                      "Please remove commas from name of account or username")
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
        self.loadAccounts()
        self.ui.accountsTable.itemClicked.connect(self.viewItem)
        self.ui.addAccountBtn.clicked.connect(self.addAccountManually)
        self.ui.searchBox.returnPressed.connect(self.searchAccounts)
        self.ui.importBtn.clicked.connect(self.importAccounts)

    def openGeneratePassTab(self):  # open generate password window
        self.newWindow = generatePasswordWin()
        self.newWindow.show()   # show new window
        self.hide()  # close old window

    def loadAccounts(self):  # added feature to read accounts from file
        global KEYPATH, VAULTPATH
        self.searchedAccounts = {}
        self.ui.accountsTable.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        key, iv, data = getData(KEYPATH, VAULTPATH)
        data = data.decode('utf-8')
        self.count = 1  # count for resetting all accounts view
        if data != "":
            row = data.split('\n')
            self.accounts = {}
            i = 0
            for value in row:
                if value != "":
                    self.accounts[i] = value.split(',')
                    i += 1
            self.ui.accountsTable.setRowCount(0)    # removes all data in table before making table
            for n, key in enumerate(sorted(self.accounts.keys())):  # displays code in table in window
                self.ui.accountsTable.insertRow(n)
                newitem = QtWidgets.QTableWidgetItem(self.accounts[key][0])
                viewLabel = QtWidgets.QTableWidgetItem("View")
                viewLabel.setTextAlignment(QtCore.Qt.AlignCenter)
                self.ui.accountsTable.setItem(n, 0, newitem)
                self.ui.accountsTable.setItem(n, 1, viewLabel)
                viewLabel.setBackground(QtGui.QColor(210, 210, 210))
                viewLabel.setFlags(viewLabel.flags() ^ QtCore.Qt.ItemIsEditable)
        else:   # else disables table
            self.ui.accountsTable.setEnabled(False)
            self.ui.searchBox.setEnabled(False)

    def viewItem(self):
        global VIEWEDITEM
        if (self.ui.accountsTable.currentItem().text() == "View") and (self.ui.accountsTable.currentColumn() == 1):
            row = self.ui.accountsTable.currentRow()
            if not(self.searchedAccounts):   # checks if searchedAccounts is empty
                VIEWEDITEM = self.accounts[row]
            else:
                for n, key in enumerate(sorted(self.searchedAccounts.keys())):
                    if row == n:
                        VIEWEDITEM = self.accounts[key]
            self.newWindow = viewAccountWin()
            self.newWindow.show()
            self.hide()

    def addAccountManually(self):
        self.newWindow = addAccountWin()
        self.newWindow.show()   # show new window
        self.hide()

    def searchAccounts(self):
        term = self.ui.searchBox.text()
        if term != (None or ""):
            self.searchedAccounts = self.accounts.copy()  # copy sets values to new variable to edit
            self.count -= 1  # decreases count for table to reset when nothing in searchBox
            self.ui.accountsTable.setRowCount(0)    # deletes tables contents
            for n, key in enumerate(sorted(self.accounts.keys())):  # displays code in table in window
                if not(term.lower() in self.accounts[key][0].lower()):
                    self.searchedAccounts.pop(key)   # removes values not in search
            # code below works just like in loadAccounts but with search terms
            for n, key in enumerate(sorted(self.searchedAccounts.keys())):
                self.ui.accountsTable.insertRow(n)
                newitem = QtWidgets.QTableWidgetItem(self.searchedAccounts[key][0])
                viewLabel = QtWidgets.QTableWidgetItem("View")
                viewLabel.setTextAlignment(QtCore.Qt.AlignCenter)
                self.ui.accountsTable.setItem(n, 0, newitem)
                self.ui.accountsTable.setItem(n, 1, viewLabel)
                viewLabel.setBackground(QtGui.QColor(210, 210, 210))
                viewLabel.setFlags(viewLabel.flags() ^ QtCore.Qt.ItemIsEditable)
        else:   # if search box is empty
            if self.count <= 0:  # comparison to make sure you only run loadAccounts after a search
                self.searchedAccounts = {}
                self.loadAccounts()

    def importAccounts(self):
        self.newWindow = importWin()
        self.newWindow.show()   # show new window
        self.hide()


class addAccountWin(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ui = Ui_addAccount()
        self.ui.setupUi(self)
        self.ui.cancelBtn.clicked.connect(self.goBack)
        self.ui.saveBtn.clicked.connect(self.saveAccount)

    def goBack(self):
        self.newWindow = allAccountsWin()
        self.newWindow.show()
        self.hide()

    def saveAccount(self):
        if (self.ui.nameOfAccountEdit.text() == (None or "")) or (self.ui.usernameEdit.text() == (None or "")) or (self.ui.passwordEdit.text() == (None or "")):
            Alert("Error", QtWidgets.QMessageBox.Critical,
                  "Account name, Username or the Password field has been left empty")
        else:  # displays any error message if the user input fields are empty or incorrectly entered
            if (self.ui.nameOfAccountEdit.text()[0] == " ") or (self.ui.nameOfAccountEdit.text()[-1] == " "):
                Alert("Error", QtWidgets.QMessageBox.Critical,
                      "Please remove spaces from the beginning or end of Account name")
            elif (" " in self.ui.usernameEdit.text()) or (" " in self.ui.passwordEdit.text()):
                Alert("Error", QtWidgets.QMessageBox.Critical,
                      "Please remove spaces from Username or Password")
            elif ("," in self.ui.nameOfAccountEdit.text()) or ("," in self.ui.usernameEdit.text()) or ("," in self.ui.passwordEdit.text()):
                Alert("Error", QtWidgets.QMessageBox.Critical,
                      "Please remove commas from Name of account, Username or Password")
            else:
                nameOfAccount = self.ui.nameOfAccountEdit.text()
                username = self.ui.usernameEdit.text()
                password = self.ui.passwordEdit.text()
                writeData(nameOfAccount, username, password)
                Alert("Process Completed", QtWidgets.QMessageBox.Information, "Account saved")
                self.goBack()


class viewAccountWin(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ui = Ui_viewAccount()
        self.ui.setupUi(self)
        self.ui.backBtn.clicked.connect(self.goBack)
        self.ui.nameOfAccountLbl.setText(VIEWEDITEM[0])
        self.ui.nameOfAccountLbl.adjustSize()
        self.ui.usernameLbl.setText(VIEWEDITEM[1])
        self.ui.usernameLbl.adjustSize()
        self.ui.passwordLbl.setText(VIEWEDITEM[2])
        self.ui.passwordLbl.adjustSize()
        self.ui.copyUserBtn.clicked.connect(self.copyUsername)
        self.ui.copyPassBtn.clicked.connect(self.copyPassword)
        self.ui.changePassBtn.clicked.connect(self.changePassword)
        self.ui.deleteBtn.clicked.connect(self.deleteAccount)

    def goBack(self):
        self.newWindow = allAccountsWin()
        self.newWindow.show()
        self.hide()

    def copyUsername(self):
        cb = QtGui.QGuiApplication.clipboard()
        cb.setText(self.ui.usernameLbl.text(), mode=cb.Clipboard)
        Alert("Confirmed", QtWidgets.QMessageBox.Information,
              "Username copied to clipboard")

    def copyPassword(self):
        cb = QtGui.QGuiApplication.clipboard()
        cb.setText(self.ui.passwordLbl.text(), mode=cb.Clipboard)
        Alert("Confirmed", QtWidgets.QMessageBox.Information,
              "Password copied to clipboard")

    def changePassword(self):
        self.newWindow = changePassWin()
        self.newWindow.show()
        self.hide()

    def deleteAccount(self):
        message = QtWidgets.QMessageBox()
        message.setWindowTitle("Warning")
        message.setIcon(QtWidgets.QMessageBox.Warning)
        message.setText("Are you sure you want to delete the account?")
        message.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.Cancel)
        message.setDefaultButton(QtWidgets.QMessageBox.Cancel)
        message.buttonClicked.connect(self.confirmDelete)
        message.exec_()

    def confirmDelete(self, clickedBtn):
        if clickedBtn.text() == "&Yes":
            key, iv, data = getData(KEYPATH, VAULTPATH)
            data = data.decode('utf-8')
            row = data.split('\n')
            accounts = []
            for value in row:
                if value != "":
                    # stores accounts as nested lists seperated by value
                    accounts.append(value.split(','))
            for account in accounts:
                if account == VIEWEDITEM:
                    index = accounts.index(account)
                    accounts.pop(index)
                    # when this code was a for loop in range len(accounts) sometimes it would give
                    # a random error when lots of accounts were added and then someone attempts to delete an account
                    # although the code is now longer, this fixes the index error issue
            updateAccounts(accounts)    # calls updateAccounts
            self.goBack()


class changePassWin(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ui = Ui_changePass()
        self.ui.setupUi(self)
        self.ui.nameOfAccountLbl.setText(VIEWEDITEM[0])
        self.ui.usernameLbl.setText(VIEWEDITEM[1])
        self.ui.cancelBtn.clicked.connect(self.goBack)
        self.ui.changePassBtn.clicked.connect(self.changePassword)

    def goBack(self):
        self.newWindow = viewAccountWin()
        self.newWindow.show()
        self.hide()

    def changePassword(self):
        if (self.ui.passwordEdit.text() == (None or "")) or (self.ui.confirmPassEdit.text() == (None or "")):
            Alert("Error", QtWidgets.QMessageBox.Critical,
                  "One or Both of the password fields are empty")
        else:
            if self.ui.passwordEdit.text() != self.ui.confirmPassEdit.text():
                Alert("Error", QtWidgets.QMessageBox.Critical, "Passwords dont match")
            elif (" " in self.ui.passwordEdit.text()) or (" " in self.ui.confirmPassEdit.text()):
                Alert("Error", QtWidgets.QMessageBox.Critical, "Remove spaces from password fields")
            elif ("," in self.ui.passwordEdit.text()) or ("," in self.ui.confirmPassEdit.text()):
                Alert("Error", QtWidgets.QMessageBox.Critical, "Remove commas from password fields")
            else:
                key, iv, data = getData(KEYPATH, VAULTPATH)
                data = data.decode('utf-8')
                row = data.split('\n')
                accounts = []
                for value in row:
                    if value != "":
                        # stores accounts as nested lists seperated by value
                        accounts.append(value.split(','))
                for i in range(len(accounts)):
                    if accounts[i] == VIEWEDITEM:
                        VIEWEDITEM[2] = self.ui.passwordEdit.text()  # updates the item being viewed
                        accounts[i] = VIEWEDITEM    # updates the item in the accounts nested list
                updateAccounts(accounts)    # calls updateAccounts
                Alert("Confirmed", QtWidgets.QMessageBox.Information, "Password Changed")
                self.goBack()   # go to view account page after password is changed successfully


class importWin(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ui = Ui_importAccounts()
        self.ui.setupUi(self)
        self.ui.cancelBtn.clicked.connect(self.goBack)
        self.ui.selectFileBtn.clicked.connect(self.getFile)
        self.ui.importBtn.clicked.connect(self.importData)

    def goBack(self):
        self.newWindow = allAccountsWin()
        self.newWindow.show()   # show new window
        self.hide()

    def getFile(self):
        file = QtWidgets.QFileDialog.getOpenFileName(
            self, 'Open file', "", "All Files (*)")  # lets user choose files from explorer
        url = QtCore.QUrl.fromLocalFile(file[0])    # gets path to file and stores it as an object
        self.ui.fileLbl.setText(url.fileName())   # adjusts file name in gui
        self.ui.fileLbl.adjustSize()     # adjusts size of text wrapper for file name in gui
        self.Path = file[0]    # makes path accessible in importWin

    def importData(self):
        if self.ui.fileLbl.text() == "Select file to import from":
            # checks that a Key File or Vault file have been selected
            Alert("Error", QtWidgets.QMessageBox.Critical,
                  "No file was selected. Please select a file to import from")
            # Alert function to display error QMessageBox
        else:
            accounts = []
            if self.ui.fileLbl.text().lower().endswith(".csv"):
                with open(self.Path, 'r') as csvFile:
                    reader = csv.DictReader(csvFile, delimiter=',')
                    for row in reader:
                        if ('name' in row) and ('username' in row) and ('password' in row):  # lastpass format
                            if (row['username'] != "") and (row['password'] != "") and (row['name'] != ""):
                                values = [row['name'], row['username'], row['password']]
                                accounts.append(values)
                        elif ('name' in row) and ('login_username' in row) and ('login_password' in row):   # bitwarden format
                            if (row['name'] != "") and (row['login_username'] != "") and (row['login_password'] != ""):
                                values = [row['name'], row['login_username'], row['login_password']]
                                accounts.append(values)
                if len(accounts) < 1:
                    Alert("Error", QtWidgets.QMessageBox.Critical,
                          "CSV file format not supported or no data to import was found")
                else:
                    for item in accounts:
                        writeData(item[0], item[1], item[2])
                    Alert("Confirmed", QtWidgets.QMessageBox.Information,
                          "Imported accounts from .CSV")
                    self.goBack()
            elif self.ui.fileLbl.text().lower().endswith(".json"):
                with open(self.Path) as jsonFile:
                    data = json.load(jsonFile)
                    if 'items' in data:
                        for item in data['items']:  # checks for bitwarden format
                            if 'login' in item:
                                if ('username' in item['login']) and ('password' in item['login']):
                                    if (item['login']['username'] is not None) and (item['login']['password'] is not None):
                                        values = [item['name'], item['login']
                                                  ['username'], item['login']['password']]
                                        accounts.append(values)
                    else:
                        Alert("Error", QtWidgets.QMessageBox.Critical,
                              "JSON file format not supported")
                if len(accounts) < 1:
                    Alert("Error", QtWidgets.QMessageBox.Critical,
                          "JSON file has no data to import")
                else:
                    for item in accounts:
                        writeData(item[0], item[1], item[2])
                    Alert("Confirmed", QtWidgets.QMessageBox.Information,
                          "Imported accounts from .JSON")
                    self.goBack()
            else:
                Alert("Error", QtWidgets.QMessageBox.Critical, "File format not supported")


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


def updateAccounts(data):
    global KEYPATH, VAULTPATH
    key, iv, oldData = getData(KEYPATH, VAULTPATH)
    accounts = []
    for value in data:
        row = ','.join(value)
        accounts.append(row)
    newData = b''
    for line in accounts:
        newData += ("{}\n".format(line)).encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphered_data = cipher.encrypt(pad(newData, AES.block_size))
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
