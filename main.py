import sys
from startPage import Ui_startPage
from PyQt5 import QtWidgets


class MainWindow(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ui = Ui_startPage()
        self.ui.setupUi(self)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    startPage = MainWindow()
    startPage.show()
    sys.exit(app.exec_())
