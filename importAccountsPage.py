# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\src\templates\importAccountsPage.ui'
#
# Created by: PyQt5 UI code generator 5.15.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_importAccounts(object):
    def setupUi(self, importAccounts):
        importAccounts.setObjectName("importAccounts")
        importAccounts.resize(1080, 720)
        importAccounts.setMinimumSize(QtCore.QSize(1080, 720))
        importAccounts.setMaximumSize(QtCore.QSize(1080, 720))
        importAccounts.setStyleSheet("background-color: rgb(2, 13, 165);")
        self.importContainer = QtWidgets.QFrame(importAccounts)
        self.importContainer.setGeometry(QtCore.QRect(300, 120, 480, 480))
        self.importContainer.setStyleSheet("border-radius: 25;\n"
"background-color: rgb(255, 255, 255);")
        self.importContainer.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.importContainer.setFrameShadow(QtWidgets.QFrame.Raised)
        self.importContainer.setObjectName("importContainer")
        self.windowTitle = QtWidgets.QLabel(self.importContainer)
        self.windowTitle.setGeometry(QtCore.QRect(30, 80, 411, 71))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(40)
        self.windowTitle.setFont(font)
        self.windowTitle.setStyleSheet("color: rgb(2, 13, 165);")
        self.windowTitle.setObjectName("windowTitle")
        self.containerForLbl = QtWidgets.QFrame(self.importContainer)
        self.containerForLbl.setGeometry(QtCore.QRect(80, 190, 296, 41))
        self.containerForLbl.setStyleSheet("border: 1 solid grey;\n"
"border-radius: 0;")
        self.containerForLbl.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.containerForLbl.setFrameShadow(QtWidgets.QFrame.Raised)
        self.containerForLbl.setObjectName("containerForLbl")
        self.fileLbl = QtWidgets.QLabel(self.containerForLbl)
        self.fileLbl.setGeometry(QtCore.QRect(10, 10, 241, 21))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(14)
        self.fileLbl.setFont(font)
        self.fileLbl.setStyleSheet("color: grey;\n"
"border: none;")
        self.fileLbl.setObjectName("fileLbl")
        self.selectFileBtn = QtWidgets.QPushButton(self.containerForLbl)
        self.selectFileBtn.setGeometry(QtCore.QRect(255, 0, 41, 41))
        self.selectFileBtn.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.selectFileBtn.setText("")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(".\\src\\templates\\../images/Icon awesome-folder-open.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.selectFileBtn.setIcon(icon)
        self.selectFileBtn.setIconSize(QtCore.QSize(27, 20))
        self.selectFileBtn.setObjectName("selectFileBtn")
        self.disclaimer = QtWidgets.QLabel(self.importContainer)
        self.disclaimer.setGeometry(QtCore.QRect(90, 260, 271, 31))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(14)
        self.disclaimer.setFont(font)
        self.disclaimer.setStyleSheet("color: rgba(2, 13, 165, 0.5);")
        self.disclaimer.setObjectName("disclaimer")
        self.cancelBtn = QtWidgets.QPushButton(self.importContainer)
        self.cancelBtn.setGeometry(QtCore.QRect(40, 360, 127, 37))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(20)
        self.cancelBtn.setFont(font)
        self.cancelBtn.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.cancelBtn.setStyleSheet("color: rgb(255, 255, 255);\n"
"background-color: rgb(255, 0, 0);")
        self.cancelBtn.setObjectName("cancelBtn")
        self.importBtn = QtWidgets.QPushButton(self.importContainer)
        self.importBtn.setGeometry(QtCore.QRect(300, 360, 127, 37))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(20)
        self.importBtn.setFont(font)
        self.importBtn.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.importBtn.setStyleSheet("color: rgb(255, 255, 255);\n"
"background-color: rgb(2, 165, 7);")
        self.importBtn.setObjectName("importBtn")

        self.retranslateUi(importAccounts)
        QtCore.QMetaObject.connectSlotsByName(importAccounts)

    def retranslateUi(self, importAccounts):
        _translate = QtCore.QCoreApplication.translate
        importAccounts.setWindowTitle(_translate("importAccounts", "Import Accounts"))
        self.windowTitle.setText(_translate("importAccounts", "Import Accounts"))
        self.fileLbl.setText(_translate("importAccounts", "Select file to import from"))
        self.disclaimer.setText(_translate("importAccounts", "The file must be .CSV or .JSON"))
        self.cancelBtn.setText(_translate("importAccounts", "Cancel"))
        self.importBtn.setText(_translate("importAccounts", "Import"))
