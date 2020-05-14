# this code is writen by:
# Name: Yousef Talal Alzahrani
# ID: 1637129
# Name: Nawaf Sami Alaamri
# ID: 1637020
# Name: Abdullah Mohammed Basheer
# ID: 1637363

import pickle
import os
import math
import re
import base64
import binascii
from PyQt5 import QtCore, QtGui, QtWidgets
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken,InvalidSignature

# Home Page
class Ui_Dialog1(object):

    def setupUi(self, Dialog1):
        Dialog1.setObjectName("Dialog")
        Dialog1.setFixedSize(640, 480)
        Dialog1.setStyleSheet("background-color: rgb(237, 241, 254);")
        Dialog1.setWindowFlag(QtCore.Qt.WindowMinimizeButtonHint)
        Dialog1.setWindowIcon(QtGui.QIcon('output-onlinepngtools.ico'))
        self.frame_3 = QtWidgets.QFrame(Dialog1)
        self.frame_3.setGeometry(QtCore.QRect(40, 0, 41, 491))
        self.frame_3.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.frame_3.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_3.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_3.setObjectName("frame_3")
        self.frame_5 = QtWidgets.QFrame(Dialog1)
        self.frame_5.setGeometry(QtCore.QRect(560, 0, 41, 491))
        self.frame_5.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.frame_5.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_5.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_5.setObjectName("frame_5")
        self.label = QtWidgets.QLabel(Dialog1)
        self.label.setGeometry(QtCore.QRect(230, 40, 181, 71))
        self.label.setText("")
        self.label.setPixmap(QtGui.QPixmap("output-onlinepngtools.png"))
        self.label.setScaledContents(True)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(Dialog1)
        self.label_2.setGeometry(QtCore.QRect(170, 140, 301, 16))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(Dialog1)
        self.label_3.setGeometry(QtCore.QRect(180, 180, 261, 16))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(Dialog1)
        self.label_4.setGeometry(QtCore.QRect(140, 160, 371, 21))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.SmartSearch = QtWidgets.QCommandLinkButton(Dialog1)
        self.SmartSearch.setGeometry(QtCore.QRect(220, 260, 201, 61))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("search.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.SmartSearch.setIcon(icon)
        self.SmartSearch.setIconSize(QtCore.QSize(40, 40))
        self.SmartSearch.setObjectName("SmartSearch")
        self.Encrypt_Decrypt = QtWidgets.QCommandLinkButton(Dialog1)
        self.Encrypt_Decrypt.setGeometry(QtCore.QRect(220, 340, 201, 61))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("lock.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Encrypt_Decrypt.setIcon(icon1)
        self.Encrypt_Decrypt.setIconSize(QtCore.QSize(40, 40))
        self.Encrypt_Decrypt.setObjectName("Encrypt_Decrypt")

        self.retranslateUi(Dialog1)
        QtCore.QMetaObject.connectSlotsByName(Dialog1)
        Dialog1.setTabOrder(self.SmartSearch, self.Encrypt_Decrypt)

    def retranslateUi(self, Dialog1):
        _translate = QtCore.QCoreApplication.translate
        Dialog1.setWindowTitle(_translate("Dialog", "Cyber Hunter - Home Page"))
        self.label_2.setText(_translate("Dialog", "WELCOME TO YOUR SECURITY COMPANION APP"))
        self.label_3.setText(_translate("Dialog", "THAT WILL HELP KEEP YOUR FILES SAFE."))
        self.label_4.setText(_translate("Dialog", "THIS TAB ALLOWS YOU TO CHOOSE ONE OF THE FEATURES "))
        self.SmartSearch.setText(_translate("Dialog", "Smart Search"))
        self.Encrypt_Decrypt.setText(_translate("Dialog", "Encrypt / Decrypt"))

#--------------------------------

# Smart Search Page
class Ui_Dialog2(object):

    def validate_credit_card_number(card_number):
        temp_list = [int(c) for c in str(card_number)]

        list1 = temp_list[-2::-2]
        list2 = temp_list[::-2]

        total_sum = sum(list2)
        for el in list1:
            el *= 2
            while el:
                el, rem = divmod(el, 10)
                total_sum += rem

        return total_sum % 10 == 0

    def count_chars(txt):
        r = 0
        for c in txt:
            r = r + 1
        return r

    def phone(x):
        t = 0
        if (x < 1):
            t = 0
        elif (x < 4):
            t = 1
        elif (x < 15):
            t = 2
        else:
            t = 3
        return t

    def fileSize(x):
        t = 0
        if (x < 1):
            t = 0
        elif (x < 8):
            t = 1
        elif (x < 28):
            t = 2
        else:
            t = 3
        return t

    def password(x):
        t = 0
        if (x < 1):
            t = 0
        elif (x < 4):
            t = 1
        elif (x < 15):
            t = 2
        else:
            t = 3
        return t

    def visa(x):
        t = 0
        if (x < 1):
            t = 0
        elif (x < 2):
            t = 1
        elif (x < 8):
            t = 2
        else:
            t = 3

        return t

    def scan_file(t):
        v = 0;
        max = 0;
        char = 0;
        lCounter = 0;
        j = 0;
        Strange = 0;
        ph = 0;
        pas = 0
        row = ['file_Name', 'file_size', 'avg', 'max', 'Visa', 'phone', 'Password']
        Size_avg = 0;
        file_c = 0;
        msg="Analysing Files....\n"
        with open(t, encoding='utf-8', errors='ignore') as f:
            lines = f.readlines();
            max = 0
            char = 0
            lCounter = 0
            v = 0
            Strange = 0
            ph = 0
            pas = 0
            for l in lines:
                Visa = re.findall("4[0-9]{15}", l)
                Phone = re.findall("05([0-1]|[3-9])[0-9]{7}", l)
                phon = re.findall("\+9665([0-1]|[3-9])[0-9]{7}", l)
                stg = re.findall("(?=[^\s]*[+%^#=@#$&*])[^\s]{6,40}", l)
                WPs = re.findall(
                    "^(?=[^\s\-,:.;'\"{}[\]()/\\?><=+_]*[%^#=@#$&*][^\s\-,:.;'\"{}[\]()/\\?><=+_]*)(?=[^\s\-,:.;'\"{}[\]()/\\?><=+_]*)[^\s\-,:.;'\"{}[\]()/\\?><=+_]{8,40}",
                    l)
                Wp = re.findall(
                    "(?=[^\s\-,:.;'\"{}[\]()/\\?><=+_]*[%^#=@#$&*][^\s\-,:.;'\"{}[\]()/\\?><=+_]*)(?=[^\s\-,:.;'\"{}[\]()/\\?><=+_]*)[^\s\-,:.;'\"{}[\]()/\\?><=+_]{8,40}$",
                    l)
                SAph = re.findall("\+966-5([0-1]|[3-9])[0-9]{1}-[0-9]{3}-[0-9]{3}", l)

                for vis in Visa:
                    vi = Ui_Dialog2.validate_credit_card_number(vis)
                    if vi:
                        v = v + 1

                lCounter = lCounter + 1
                ch = Ui_Dialog2.count_chars(l.strip('\n'))
                char = char + ch

                Phlen = len(Phone)
                ph = ph + Phlen

                Phlen1 = len(phon)
                ph = ph + Phlen1

                Phlen1 = len(SAph)
                ph = ph + Phlen1

                Passwords = len(WPs)
                pas = pas + Passwords

                Passwords = len(Wp)
                pas = pas + Passwords

                if max < ch:
                    max = ch
        file_c = file_c + 1
        filename = t.replace('Desktop\\python\\sss', '')
        filesize = os.path.getsize(t)
        inKilobyte = filesize / 1024
        inKilobyte = math.ceil(inKilobyte)
        Size_avg = Size_avg + inKilobyte
        avg = char / lCounter
        avg = round(avg)

        row = [filename, Ui_Dialog2.fileSize(inKilobyte), avg, max, Ui_Dialog2.visa(v), Ui_Dialog2.phone(ph), Ui_Dialog2.password(pas),msg]
        return row

    def SSearch2(self):
        Scounter=0
        result = ""
        print("Start Smart Search")
        path = self.dirEntry.text()
        pickle_in = open("CyberHunter997.pickle", "rb")
        CyperHunter = pickle.load(pickle_in)
        #print("1")
        t = Ui_Dialog2.scan_file(path)
        #print("2")
        result=t[7]+"Running Random Forest algorithm on files....\nSensitive Files Names:\n"
        p = CyperHunter.predict([[t[1], t[2], t[3], t[4], t[5], t[6]]])
        #print("3")
        if (round(p[0]) == 1):
            Scounter=Scounter+1
            result = result + str(t[0]) + "\n"
            result = result + "File scanned: \n" + path + "\nIt's Sensitive\nFinished scanning."

        else:
            result=result+t[0]+"\nIt's not Sensitive\nFinished scanning."


        #print("result :     ", result)
        self.resultEntry.setPlainText(result)
        if(path==""):
            self.Popmsg("Please enter a path")
        else:
            self.Popmsg("Finished searching through the file")

    def msgEdit(self,t,msg):
        if(t==1):
            msg=msg+"Running Random Forest algorithm on files....\nSensitive Files Names:\n"
            return msg
        else:
            return ""

    def SSearch(self):
        fileCounter=0
        c=1
        Scounter=0
        result=""
        print("Start Smart Search")
        path2=self.dirEntry.text()
        pickle_in = open("CyberHunter997.pickle", "rb")
        CyperHunter = pickle.load(pickle_in)
        for root, dirs, files in os.walk(path2):
            for file in files:
                if file.endswith(".txt"):
                    fileCounter=fileCounter+1
                    path = os.path.join(root, file)
                    t = Ui_Dialog2.scan_file(path)
                    result=result+self.msgEdit(c,t[7])
                    c=c+1
                    p = CyperHunter.predict([[t[1], t[2], t[3], t[4], t[5], t[6]]])
                    if(round(p[0])==1):
                        result = result + t[0]+"\n"
                        Scounter=Scounter+1

        result=result+"Directory scanned: \n"+path2+"\nTotal files scanned: "+str(fileCounter)+"\nPotentially Sensitive Files: "+str(Scounter)+"\nFinished scanning"
        self.resultEntry.setPlainText(result)
        if (path == ""):
            self.Popmsg("Please enter a path")
        else:
            self.Popmsg("Finished searching through the files")

    def encryptfiles(self,g):
        password = self.S_pas_Entry.text().encode()
        fff = b'{,\xc8\x81\xf5l\x1e\x0f\x9f\xa9\xe0\xae\x82\xe6[f'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=fff, iterations=100000, backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(password))

        for in_f in g:
            with open(in_f, 'rb')as f:
                data = f.read()

            os.remove(in_f)
            fernet = Fernet(key)
            encrypted = fernet.encrypt(data)

            with open(in_f, 'wb')as f:
                f.write(encrypted)
        self.Popmsg("Encryption Completed")

    def encryptf(self,g):
        try:
            print(" ")
            password = self.S_pas_Entry.text()
            password = password.encode()
            fff = b'{,\xc8\x81\xf5l\x1e\x0f\x9f\xa9\xe0\xae\x82\xe6[f'
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=fff, iterations=100000,
                             backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(password))
            for in_f in g:
                with open(in_f, 'rb')as f:
                    data = f.read()

                fernet = Fernet(key)
                encrypted = fernet.encrypt(data)

                os.remove(in_f)
                with open(in_f, 'wb')as f:
                    f.write(encrypted)

            print("\nEncryption Completed\n")
            self.Popmsg("Encryption Completed")
        except FileNotFoundError:
            print("File is not in path")

    def cho(self):
        t = self.resultEntry.toPlainText()

        if ("It's not Sensitive" in t):
            print("File not Sensitive")
            self.Popmsg("File not Sensitive if you want to encrypt go to Encryption/Decryption page")
        else:
            f = t.split("Analysing Files....\nRunning Random Forest algorithm on files....\nSensitive Files Names:\n")
            s = ""
            for y in f:
                s = s + y
            r = s.split("Directory scanned: \n")
            e = ""
            for y in r:
                e = e + y
            k = e.split("Total files scanned: ")
            w = ""
            for y in k:
                w = w + y
            q = w.split("\n")
            g = list()
            for z in q:
                z=str(z)
                if (z.endswith(".txt") | z.endswith(".TXT")):
                    g.append(z)
            if(len(g)==0):
                print("Do Nothing")
            else:
                Ui_Dialog2.encryptfiles(self, g)

    def cho2(self):

        path = self.dirEntry.text()
        if(path.endswith(".txt") | path.endswith(".TXT")):
            Ui_Dialog2.SSearch2(self)
        else:
            Ui_Dialog2.SSearch(self)

    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.setFixedSize(640, 492)
        Dialog.setStyleSheet("background-color: rgb(237, 241, 254);")
        Dialog.setWindowFlag(QtCore.Qt.WindowMinimizeButtonHint)
        Dialog.setWindowIcon(QtGui.QIcon('output-onlinepngtools.ico'))
        self.msg=QtWidgets.QMessageBox()
        self.frame_3 = QtWidgets.QFrame(Dialog)
        self.frame_3.setGeometry(QtCore.QRect(40, 0, 41, 491))
        self.frame_3.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.frame_3.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_3.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_3.setObjectName("frame_3")
        self.frame_5 = QtWidgets.QFrame(Dialog)
        self.frame_5.setGeometry(QtCore.QRect(560, 0, 41, 491))
        self.frame_5.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.frame_5.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_5.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_5.setObjectName("frame_5")
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(260, 20, 171, 71))
        self.label.setText("")
        self.label.setPixmap(QtGui.QPixmap("output-onlinepngtools.png"))
        self.label.setScaledContents(True)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(Dialog)
        self.label_2.setGeometry(QtCore.QRect(120, 110, 47, 13))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(Dialog)
        self.label_3.setGeometry(QtCore.QRect(120, 210, 61, 16))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(Dialog)
        self.label_4.setGeometry(QtCore.QRect(120, 390, 81, 16))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.resultEntry = QtWidgets.QTextEdit(Dialog)
        self.resultEntry.setGeometry(QtCore.QRect(210, 210, 281, 171))
        self.resultEntry.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.resultEntry.setReadOnly(True)
        self.resultEntry.setObjectName("resultEntry")
        self.dirEntry = QtWidgets.QLineEdit(Dialog)
        self.dirEntry.setGeometry(QtCore.QRect(210, 110, 281, 20))
        self.dirEntry.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.dirEntry.setObjectName("dirEntry")
        self.S_pas_Entry = QtWidgets.QLineEdit(Dialog)
        self.S_pas_Entry.setGeometry(QtCore.QRect(210, 390, 281, 20))
        self.S_pas_Entry.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.S_pas_Entry.setEchoMode(QtWidgets.QLineEdit.Password)
        self.S_pas_Entry.setPlaceholderText("")
        self.S_pas_Entry.setObjectName("S_pas_Entry")
        self.Search = QtWidgets.QCommandLinkButton(Dialog)
        self.Search.setGeometry(QtCore.QRect(300, 140, 101, 61))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("search.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Search.setIcon(icon)
        self.Search.setIconSize(QtCore.QSize(40, 40))
        self.Search.setObjectName("Search")
        # connect button to the method
        self.Search.clicked.connect(self.cho2)


        self.Encrypt = QtWidgets.QCommandLinkButton(Dialog)
        self.Encrypt.setGeometry(QtCore.QRect(230, 420, 111, 61))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("cyber-security.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Encrypt.setIcon(icon1)
        self.Encrypt.setIconSize(QtCore.QSize(40, 40))
        self.Encrypt.setObjectName("Encrypt")
        # connect button to the method
        self.Encrypt.clicked.connect(self.cho)

        self.Home = QtWidgets.QCommandLinkButton(Dialog)
        self.Home.setGeometry(QtCore.QRect(360, 420, 111, 61))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap("home-run.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Home.setIcon(icon2)
        self.Home.setIconSize(QtCore.QSize(40, 40))
        self.Home.setObjectName("Home")


        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)
        Dialog.setTabOrder(self.dirEntry, self.Search)
        Dialog.setTabOrder(self.Search, self.resultEntry)
        Dialog.setTabOrder(self.resultEntry, self.S_pas_Entry)
        Dialog.setTabOrder(self.S_pas_Entry, self.Encrypt)
        Dialog.setTabOrder(self.Encrypt, self.Home)

    def retranslateUi(self, SmartSearchPage_2):
        _translate = QtCore.QCoreApplication.translate
        SmartSearchPage_2.setWindowTitle(_translate("SmartSearchPage_2", "Cyber Hunter - Smart Search"))
        self.dirEntry.setPlaceholderText(_translate("SmartSearchPage_2", "Like : C:\\Program Files or C:\\abc.txt"))
        self.label_2.setText(_translate("SmartSearchPage_2", "Path :"))
        self.label_3.setText(_translate("SmartSearchPage_2", "Result :"))
        self.Encrypt.setText(_translate("SmartSearchPage_2", "Encrypt"))
        self.Search.setText(_translate("SmartSearchPage_2", "Search"))
        self.Home.setText(_translate("SmartSearchPage_2", "Home"))
        self.label_4.setText(_translate("SmartSearchPage_2", "Password :"))

    def Popmsg(self,msg):

        try:
            self.msg.setWindowIcon(QtGui.QIcon('output-onlinepngtools.ico'))
            self.msg.setWindowTitle("Cyber Hunter")
            self.msg.setText(msg)
            self.msg.setIcon(QtWidgets.QMessageBox.Information)
            self.msg.exec_()
        except:
            print("Erorr in : Popmsg Line 540")

# --------------------------------

# Encryption/Decryption page
class Ui_Dialog3(object):

    def encryptf(self):
        try:
            print(" ")
            password = self.pas_Entry.text()
            in_f = self.Filepath_Entry.text()
            in_o = self.Filepath_Entry.text()
            password = password.encode()
            fff = b'{,\xc8\x81\xf5l\x1e\x0f\x9f\xa9\xe0\xae\x82\xe6[f'
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=fff, iterations=100000,
                             backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(password))

            with open(in_f, 'rb')as f:
                data = f.read()

            fernet = Fernet(key)
            encrypted = fernet.encrypt(data)

            os.remove(in_f)
            with open(in_o, 'wb')as f:
                f.write(encrypted)

            print("\nEncryption Completed\n")
            self.Popmsg("Encryption Completed")
        except FileNotFoundError:
            self.Popmsg("File is not in path")
            print("File is not in path")

    def decrypt(self):
        try:
            print(" ")
            password = self.pas_Entry.text()
            in_f = self.Filepath_Entry.text()
            in_o = self.Filepath_Entry.text()
            password = password.encode()
            fff = b'{,\xc8\x81\xf5l\x1e\x0f\x9f\xa9\xe0\xae\x82\xe6[f'
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=fff, iterations=100000,
                             backend=default_backend())
            key = base64.urlsafe_b64encode(kdf.derive(password))
            with open(in_f, 'rb')as f:
                data = f.read()
            fernet = Fernet(key)
            encrypted = fernet.decrypt(data)
            os.remove(in_f)
            with open(in_o, 'wb')as f:
                f.write(encrypted)
            print("\nDecryption Completed\n")
            self.Popmsg("Decryption Completed")
        except FileNotFoundError:
            self.Popmsg("File is not in path")
            print("File is not in path")
        except binascii.Error:
            self.Popmsg("Wrong password !!")
            print("Wrong password")
        except InvalidToken:
            self.Popmsg("Wrong password !!")
            print("Wrong password")
        except InvalidSignature:
            self.Popmsg("Wrong password !!")
            print("Wrong password")

    def setupUi(self, Dialog3):
        Dialog3.setObjectName("Dialog")
        Dialog3.setFixedSize(640, 480)
        Dialog3.setWindowFlag(QtCore.Qt.WindowMinimizeButtonHint)
        Dialog3.setStyleSheet("background-color: rgb(237, 241, 254);")
        Dialog3.setWindowIcon(QtGui.QIcon('output-onlinepngtools.ico'))
        self.msg = QtWidgets.QMessageBox()
        self.frame_3 = QtWidgets.QFrame(Dialog3)
        self.frame_3.setGeometry(QtCore.QRect(40, 0, 41, 491))
        self.frame_3.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.frame_3.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_3.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_3.setObjectName("frame_3")
        self.frame_5 = QtWidgets.QFrame(Dialog3)
        self.frame_5.setGeometry(QtCore.QRect(560, 0, 41, 491))
        self.frame_5.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.frame_5.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_5.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_5.setObjectName("frame_5")
        self.label = QtWidgets.QLabel(Dialog3)
        self.label.setGeometry(QtCore.QRect(260, 60, 171, 71))
        self.label.setText("")
        self.label.setPixmap(QtGui.QPixmap("output-onlinepngtools.png"))
        self.label.setScaledContents(True)
        self.label.setObjectName("label")
        self.Home1 = QtWidgets.QCommandLinkButton(Dialog3)
        self.Home1.setGeometry(QtCore.QRect(280, 370, 111, 61))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("home-run.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Home1.setIcon(icon)
        self.Home1.setIconSize(QtCore.QSize(40, 40))
        self.Home1.setObjectName("Home1")
        self.Filepath_Entry = QtWidgets.QLineEdit(Dialog3)
        self.Filepath_Entry.setGeometry(QtCore.QRect(210, 190, 281, 20))
        self.Filepath_Entry.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.Filepath_Entry.setText("")
        self.Filepath_Entry.setObjectName("Filepath_Entry")
        self.pas_Entry = QtWidgets.QLineEdit(Dialog3)
        self.pas_Entry.setGeometry(QtCore.QRect(210, 220, 281, 20))
        self.pas_Entry.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.pas_Entry.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pas_Entry.setPlaceholderText("")
        self.pas_Entry.setObjectName("pas_Entry")
        self.Filepath = QtWidgets.QLabel(Dialog3)
        self.Filepath.setGeometry(QtCore.QRect(120, 190, 71, 21))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.Filepath.setFont(font)
        self.Filepath.setObjectName("Filepath")
        self.pas = QtWidgets.QLabel(Dialog3)
        self.pas.setGeometry(QtCore.QRect(120, 220, 71, 21))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.pas.setFont(font)
        self.pas.setObjectName("pas")
        self.Decrypt = QtWidgets.QCommandLinkButton(Dialog3)
        self.Decrypt.setGeometry(QtCore.QRect(230, 250, 111, 61))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("encryption.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Decrypt.setIcon(icon1)
        self.Decrypt.setIconSize(QtCore.QSize(40, 40))
        self.Decrypt.setObjectName("Decrypt")
        # connect button to the method
        self.Decrypt.clicked.connect(self.decrypt)

        self.Encrypt1 = QtWidgets.QCommandLinkButton(Dialog3)
        self.Encrypt1.setGeometry(QtCore.QRect(360, 250, 111, 61))
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap("cyber-security.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.Encrypt1.setIcon(icon2)
        self.Encrypt1.setIconSize(QtCore.QSize(40, 40))
        self.Encrypt1.setObjectName("Encrypt1")
        # connect button to the method
        self.Encrypt1.clicked.connect(self.encryptf)


        self.retranslateUi(Dialog3)
        QtCore.QMetaObject.connectSlotsByName(Dialog3)
        Dialog3.setTabOrder(self.Filepath_Entry, self.pas_Entry)
        Dialog3.setTabOrder(self.pas_Entry, self.Decrypt)
        Dialog3.setTabOrder(self.Decrypt, self.Encrypt1)
        Dialog3.setTabOrder(self.Encrypt1, self.Home1)

    def retranslateUi(self, Dialog3):
        _translate = QtCore.QCoreApplication.translate
        Dialog3.setWindowTitle(_translate("Dialog", "Cyber Hunter - Encryption / Decryption"))
        self.Home1.setText(_translate("Dialog", "Home"))
        self.Filepath_Entry.setPlaceholderText(_translate("Dialog", "Like : C:\\abc.txt"))
        self.Filepath.setText(_translate("Dialog", "File path :"))
        self.pas.setText(_translate("Dialog", "Password :"))
        self.Decrypt.setText(_translate("Dialog", "Decrypt"))
        self.Encrypt1.setText(_translate("Dialog", "Encrypt"))

    def Popmsg(self,msg):

        try:
            self.msg.setWindowIcon(QtGui.QIcon('output-onlinepngtools.ico'))
            self.msg.setWindowTitle("Cyber Hunter")
            self.msg.setText(msg)
            self.msg.setIcon(QtWidgets.QMessageBox.Information)
            self.msg.exec_()
        except:
            print("Error in : Popmsg Line 680")

# --------------------------------

# Dialog = Home page
class Dialog(QtWidgets.QDialog, Ui_Dialog1):
    def __init__(self, parent=None):
        super(Dialog, self).__init__(parent)
        self.setupUi(self)
        self.Encrypt_Decrypt.clicked.connect(self.close)
        self.SmartSearch.clicked.connect(self.close)

# Dialog2 = Smart Search page
class Dialog2(QtWidgets.QDialog, Ui_Dialog2):
    def __init__(self, parent=None):
        super(Dialog2, self).__init__(parent)
        self.setupUi(self)
        self.Home.clicked.connect(self.close)

# Dialog3 = Encryption/Decryption page
class Dialog3(QtWidgets.QDialog, Ui_Dialog3):
    def __init__(self, parent=None):
        super(Dialog3, self).__init__(parent)
        self.setupUi(self)
        self.Home1.clicked.connect(self.close)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    w1 = Dialog()
    w2 = Dialog2()
    w3 = Dialog3()
    w1.SmartSearch.clicked.connect(w2.show)
    w2.Home.clicked.connect(w1.show)
    w1.Encrypt_Decrypt.clicked.connect(w3.show)
    w3.Home1.clicked.connect(w1.show)
    w1.show()
    sys.exit(app.exec_())

