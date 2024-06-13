import os
import threading

from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWidgets import *

from scanner import Scanner
from utils import Label, Button


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setFixedSize(QSize(700, 500))
        self.setWindowTitle('CollapseScanner')

        layout = QGridLayout(self)
        layout.setRowStretch(10, 10)

        self.header = Label('CollapseScanner // Drag n drop file', 18)
        layout.addWidget(self.header, 0, 0, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

        # self.file = Label('Drag n drop file', 9)
        # layout.addWidget(self.file, 1, 0)

        # layout.addWidget(Button('Scan', lambda x: 1, (70, 40), 12), 10, 0, Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft)
        self.log = Label('', 10)
        self.log.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.log.setMargin(10)
        scroll_area = QScrollArea()
        scroll_area.setWidget(self.log)
        scroll_area.setFixedSize(670, 300)
        scroll_area.setWidgetResizable(True)

        layout.addWidget(scroll_area, 2, 0, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        
        self.report = Label('')
        layout.addWidget(self.report, 9, 0, Qt.AlignmentFlag.AlignLeft)

        self.view_links_button = Button('View links', self.view_links, (100, 30), 12)
        layout.addWidget(self.view_links_button, 9, 1, Qt.AlignmentFlag.AlignLeft)

        self.copy_button = Button('Copy logs', lambda x: self.copy_logs(), (50, 30), 12)
        layout.addWidget(self.copy_button, 10, 0, Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignLeft)

        # Scanner('file:///C:\\Users\\Purpl3\\Downloads\\aristois-latest.jar', self.log, self.report).scan()

    def view_links(self):
        try:
            text = QPlainTextEdit()

            window = QMainWindow()
            window.setCentralWidget(text)
            window.setFixedSize(QSize(400, 200))
            window.setWindowTitle("Links Viewer")

            # Make the window instance a class attribute to keep a reference
            self.window = window

            window.show()
            window.raise_()
            window.activateWindow()

            text.setPlainText('\n'.join(self.report.links))
        except AttributeError:
            return

    def copy_logs(self):
        QGuiApplication.clipboard().setText(self.log.text())

        msg = QMessageBox()
        msg.setText('Logs copied to clipboard')
        msg.exec()

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().text().endswith('.jar'):
            e.accept()
            return
        
        e.ignore()
        
    def dropEvent(self, e: QDropEvent):
        if e.mimeData().text().endswith('.jar'):
            e.accept()

            self.report.links = 0

            scanner = Scanner(e.mimeData().text(), self.log, self.report)

            confirm = QMessageBox()
            confirm.setText('Scan file for links?')
            confirm.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if confirm.exec() == QMessageBox.StandardButton.Yes:
                scanner.scan_links = True

            self.log.setText('')
            self.header.setText(f'CollapseScanner // {os.path.basename(e.mimeData().text())}')

            thread = threading.Thread(target=scanner.scan)
            thread.daemon = True
            thread.start()
            
            return
        
        e.ignore()

app = QApplication([])
w = Window()
w.show()
app.exec()
