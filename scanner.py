from zipfile import ZipFile 
from PyQt6.QtWidgets import QLabel
import re

class Scanner:
    def __init__(self, file: str, log_label: QLabel, report_label: QLabel):
        self.file = file.replace('file:///', '') # remove protocol
        self.log_label = log_label
        self.report_label = report_label
        self.discord = False
        self.minecraft = False
        self.scan_links = True
        self.links = []

    def log(self, msg: str,):
        print(f'[Scanner] {msg}')
        self.log_label.setText(self.log_label.text() + f'\n{msg}')

    def report(self):
        text = ''

        text += f'Links: {len(self.links)}'

        self.report_label.setText(text)
        self.report_label.links = self.links

    def scan(self):
        self.log(f'Scanning: {self.file}...')

        with ZipFile(self.file, 'r') as zip: 
            manifest = zip.read('META-INF/MANIFEST.MF').decode()

            if 'Main-Class' in manifest:
                self.log(f"{manifest[manifest.find('Main-Class:'):manifest.find('\nDev:')]}")
            
            for file in zip.filelist:
                if 'net/minecraft' in file.filename.lower() and not self.minecraft:
                    self.log('Jar is minecraft executable')
                    self.minecraft = True

                if any(keyword in file.filename.lower() for keyword in ['discord', 'rpc']) and not self.discord:
                    self.log(f'Found discord rpc: {file.filename}')
                    self.discord = True

                if file.filename.endswith('.class') and not 'net/minecraft' in file.filename and self.scan_links:
                    data = zip.read(file.filename).decode(errors='ignore')

                    match = re.search(r'(http|https|ftp)\://([a-zA-Z0-9\-\.]+\.+[a-zA-Z]{2,3})(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~]*)[^\.\,\)\(\s]?', data)
                    if match != None:
                        link = ''.join(letter for letter in match.group(0) if letter.isprintable())
                        self.links.append(link)
                        self.log(f'Found link: {link}')

        self.log('Scan completed')
        self.log(f'Found {len(self.links)} links')

        self.report()