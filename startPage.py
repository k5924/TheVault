# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\src\templates\startPage.ui'
#
# Created by: PyQt5 UI code generator 5.15.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_startPage(object):
    def setupUi(self, startPage):
        startPage.setObjectName("startPage")
        startPage.resize(1080, 720)
        startPage.setMinimumSize(QtCore.QSize(1080, 720))
        startPage.setMaximumSize(QtCore.QSize(1080, 720))
        startPage.setBaseSize(QtCore.QSize(1080, 720))
        self.createVault = QtWidgets.QFrame(startPage)
        self.createVault.setGeometry(QtCore.QRect(0, 0, 540, 720))
        self.createVault.setStyleSheet("background-color: rgb(2, 13, 165);")
        self.createVault.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.createVault.setFrameShadow(QtWidgets.QFrame.Raised)
        self.createVault.setObjectName("createVault")
        self.createVaultLabel = QtWidgets.QLabel(self.createVault)
        self.createVaultLabel.setGeometry(QtCore.QRect(110, 130, 321, 61))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(40)
        self.createVaultLabel.setFont(font)
        self.createVaultLabel.setStyleSheet("color: rgb(255, 255, 255);")
        self.createVaultLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.createVaultLabel.setObjectName("createVaultLabel")
        self.explainCreateVault = QtWidgets.QLabel(self.createVault)
        self.explainCreateVault.setGeometry(QtCore.QRect(20, 210, 501, 291))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(20)
        self.explainCreateVault.setFont(font)
        self.explainCreateVault.setStyleSheet("color: rgb(255, 255, 255);")
        self.explainCreateVault.setAlignment(QtCore.Qt.AlignCenter)
        self.explainCreateVault.setWordWrap(True)
        self.explainCreateVault.setObjectName("explainCreateVault")
        self.startButton = QtWidgets.QPushButton(self.createVault)
        self.startButton.setGeometry(QtCore.QRect(190, 540, 161, 41))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(14)
        self.startButton.setFont(font)
        self.startButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.startButton.setStyleSheet(";\n"
                                       "background-color: rgb(204, 204, 204);")
        self.startButton.setObjectName("startButton")
        self.openVault = QtWidgets.QFrame(startPage)
        self.openVault.setGeometry(QtCore.QRect(540, 0, 540, 720))
        self.openVault.setStyleSheet("")
        self.openVault.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.openVault.setFrameShadow(QtWidgets.QFrame.Raised)
        self.openVault.setObjectName("openVault")
        self.openVaultLabel = QtWidgets.QLabel(self.openVault)
        self.openVaultLabel.setGeometry(QtCore.QRect(130, 190, 281, 71))
        self.openVaultLabel.setStyleSheet("color: rgb(2, 13, 165);\n"
                                          "font: 40pt \"Open Sans\";")
        self.openVaultLabel.setObjectName("openVaultLabel")
        self.keyFileContainer = QtWidgets.QFrame(self.openVault)
        self.keyFileContainer.setGeometry(QtCore.QRect(110, 300, 301, 31))
        self.keyFileContainer.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.keyFileContainer.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.keyFileContainer.setFrameShadow(QtWidgets.QFrame.Raised)
        self.keyFileContainer.setObjectName("keyFileContainer")
        self.keyFileLabel = QtWidgets.QLabel(self.keyFileContainer)
        self.keyFileLabel.setGeometry(QtCore.QRect(10, 0, 71, 31))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(14)
        self.keyFileLabel.setFont(font)
        self.keyFileLabel.setStyleSheet("color: rgb(124, 124, 124);")
        self.keyFileLabel.setObjectName("keyFileLabel")
        self.selectKeyFile = QtWidgets.QPushButton(self.keyFileContainer)
        self.selectKeyFile.setGeometry(QtCore.QRect(260, 0, 41, 31))
        self.selectKeyFile.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.selectKeyFile.setStyleSheet("")
        self.selectKeyFile.setText("")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(
            ".\\src\\templates\\../images/Icon awesome-folder-open.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.selectKeyFile.setIcon(icon)
        self.selectKeyFile.setIconSize(QtCore.QSize(32, 32))
        self.selectKeyFile.setObjectName("selectKeyFile")
        self.vaultFileContainer = QtWidgets.QFrame(self.openVault)
        self.vaultFileContainer.setGeometry(QtCore.QRect(110, 370, 301, 31))
        self.vaultFileContainer.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.vaultFileContainer.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.vaultFileContainer.setFrameShadow(QtWidgets.QFrame.Raised)
        self.vaultFileContainer.setObjectName("vaultFileContainer")
        self.vaultFileLabel = QtWidgets.QLabel(self.vaultFileContainer)
        self.vaultFileLabel.setGeometry(QtCore.QRect(10, 0, 91, 31))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(14)
        self.vaultFileLabel.setFont(font)
        self.vaultFileLabel.setStyleSheet("color: rgb(124, 124, 124);")
        self.vaultFileLabel.setObjectName("vaultFileLabel")
        self.selectVaultFile = QtWidgets.QPushButton(self.vaultFileContainer)
        self.selectVaultFile.setGeometry(QtCore.QRect(260, 0, 41, 31))
        self.selectVaultFile.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.selectVaultFile.setStyleSheet("")
        self.selectVaultFile.setText("")
        self.selectVaultFile.setIcon(icon)
        self.selectVaultFile.setIconSize(QtCore.QSize(32, 32))
        self.selectVaultFile.setObjectName("selectVaultFile")
        self.openButton = QtWidgets.QPushButton(self.openVault)
        self.openButton.setGeometry(QtCore.QRect(180, 460, 161, 41))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(14)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.openButton.setFont(font)
        self.openButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.openButton.setStyleSheet("color: rgb(255, 255, 255);\n"
                                      "font: 14pt \"Open Sans\";\n"
                                      "background-color: rgb(2, 13, 165);")
        self.openButton.setDefault(False)
        self.openButton.setFlat(False)
        self.openButton.setObjectName("openButton")

        self.retranslateUi(startPage)
        QtCore.QMetaObject.connectSlotsByName(startPage)

    def retranslateUi(self, startPage):
        _translate = QtCore.QCoreApplication.translate
        startPage.setWindowTitle(_translate("startPage", "The Vault"))
        self.createVaultLabel.setText(_translate("startPage", "Create Vault"))
        self.explainCreateVault.setText(_translate(
            "startPage", "This will create an encrypted file to store your account details and a key file used to access the vault which can be found on the Desktop as vault and key. The next time you use the application you will need these files to access your accounts. If you wish to proceed, press start."))
        self.startButton.setText(_translate("startPage", "Start"))
        self.openVaultLabel.setText(_translate("startPage", "Open Vault"))
        self.keyFileLabel.setText(_translate("startPage", "Key File"))
        self.vaultFileLabel.setText(_translate("startPage", "Vault File"))
        self.openButton.setText(_translate("startPage", "Open"))
