# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\src\templates\addAccountPage.ui'
#
# Created by: PyQt5 UI code generator 5.15.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_addAccount(object):
    def setupUi(self, addAccount):
        addAccount.setObjectName("addAccount")
        addAccount.resize(1080, 720)
        addAccount.setMinimumSize(QtCore.QSize(1080, 720))
        addAccount.setMaximumSize(QtCore.QSize(1080, 720))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(14)
        addAccount.setFont(font)
        addAccount.setStyleSheet("background-color: rgb(2, 13, 165);")
        self.accountForm = QtWidgets.QFrame(addAccount)
        self.accountForm.setGeometry(QtCore.QRect(300, 120, 480, 480))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        self.accountForm.setFont(font)
        self.accountForm.setStyleSheet("background-color: rgb(255, 255, 255);\n"
"border-radius: 25;")
        self.accountForm.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.accountForm.setFrameShadow(QtWidgets.QFrame.Raised)
        self.accountForm.setObjectName("accountForm")
        self.addAccountLbl = QtWidgets.QLabel(self.accountForm)
        self.addAccountLbl.setGeometry(QtCore.QRect(80, 68, 311, 51))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(40)
        self.addAccountLbl.setFont(font)
        self.addAccountLbl.setStyleSheet("color: rgb(2, 13, 165);")
        self.addAccountLbl.setObjectName("addAccountLbl")
        self.nameOfAccountEdit = QtWidgets.QLineEdit(self.accountForm)
        self.nameOfAccountEdit.setGeometry(QtCore.QRect(80, 136, 296, 32))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(16)
        self.nameOfAccountEdit.setFont(font)
        self.nameOfAccountEdit.setStyleSheet("border: 1 solid grey;")
        self.nameOfAccountEdit.setObjectName("nameOfAccountEdit")
        self.usernameEdit = QtWidgets.QLineEdit(self.accountForm)
        self.usernameEdit.setGeometry(QtCore.QRect(80, 204, 296, 32))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(16)
        self.usernameEdit.setFont(font)
        self.usernameEdit.setStyleSheet("border: 1 solid grey;")
        self.usernameEdit.setObjectName("usernameEdit")
        self.passwordEdit = QtWidgets.QLineEdit(self.accountForm)
        self.passwordEdit.setGeometry(QtCore.QRect(80, 272, 296, 32))
        font = QtGui.QFont()
        font.setFamily("Open Sans")
        font.setPointSize(16)
        self.passwordEdit.setFont(font)
        self.passwordEdit.setStyleSheet("border: 1 solid grey;")
        self.passwordEdit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.passwordEdit.setObjectName("passwordEdit")
        self.cancelBtn = QtWidgets.QPushButton(self.accountForm)
        self.cancelBtn.setGeometry(QtCore.QRect(80, 340, 120, 32))
        self.cancelBtn.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.cancelBtn.setStyleSheet("background-color: rgb(255, 0, 0);\n"
"color: rgb(255, 255, 255);\n"
"font: 20pt \"Open Sans\";")
        self.cancelBtn.setObjectName("cancelBtn")
        self.saveBtn = QtWidgets.QPushButton(self.accountForm)
        self.saveBtn.setGeometry(QtCore.QRect(260, 340, 120, 32))
        self.saveBtn.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.saveBtn.setStyleSheet("font: 20pt \"Open Sans\";\n"
"background-color: rgb(4, 207, 10);\n"
"color: rgb(255, 255, 255);")
        self.saveBtn.setObjectName("saveBtn")

        self.retranslateUi(addAccount)
        QtCore.QMetaObject.connectSlotsByName(addAccount)

    def retranslateUi(self, addAccount):
        _translate = QtCore.QCoreApplication.translate
        addAccount.setWindowTitle(_translate("addAccount", "Add Account Manually"))
        self.addAccountLbl.setText(_translate("addAccount", "Add Account"))
        self.nameOfAccountEdit.setPlaceholderText(_translate("addAccount", "Name of account"))
        self.usernameEdit.setPlaceholderText(_translate("addAccount", "Username"))
        self.passwordEdit.setPlaceholderText(_translate("addAccount", "Password"))
        self.cancelBtn.setText(_translate("addAccount", "Cancel"))
        self.saveBtn.setText(_translate("addAccount", "Save"))