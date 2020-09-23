import sys
import os
from platform import system
from string import ascii_uppercase
from startPage import Ui_startPage
from PyQt5 import QtWidgets
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class MainWindow(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ui = Ui_startPage()
        self.ui.setupUi(self)
        self.ui.startButton.clicked.connect(self.createVaultFiles)

    def createVaultFiles(self):
        key = get_random_bytes(32)  # 32 bytes is 256 bits
        data = b''  # basic data for fiel to encrypt
        desktopPath = getPathToDesktop()
        keyFile = open(desktopPath + "\\key.bin", "wb")
        keyFile.write(key)  # writes encryption key to file
        keyFile.close
        cipher = AES.new(key, AES.MODE_CBC)
        ciphered_data = cipher.encrypt(pad(data, AES.block_size))
        vaultFile = open(desktopPath + "\\vault.bin", "wb")
        vaultFile.write(cipher.iv)
        vaultFile.write(ciphered_data)
        vaultFile.close()
        message = QtWidgets.QMessageBox()
        message.setWindowTitle("Process Completed")
        message.setText("Created vault.bin and key.bin")
        message.setIcon(QtWidgets.QMessageBox.Information)
        message.setDefaultButton(QtWidgets.QMessageBox.Ok)
        message.exec_()


def getPathToDesktop():
    if system() == 'Windows':
        desktopPath = os.environ["HOMEPATH"] + "\Desktop"  # finds path to desktop
        for driveLetter in ascii_uppercase:  # find drive desktop folder is on
            if os.path.exists("{0}:{1}".format(driveLetter, desktopPath)):
                desktopPath = "{0}:{1}".format(driveLetter, desktopPath)
    else:
        desktopPath = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
    return desktopPath


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    startPage = MainWindow()
    startPage.show()
    sys.exit(app.exec_())
