import sys
from startPage import Ui_startPage
from PyQt5 import QtWidgets

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    startPage = QtWidgets.QMainWindow()
    ui = Ui_startPage()
    ui.setupUi(startPage)
    startPage.show()
    sys.exit(app.exec_())
