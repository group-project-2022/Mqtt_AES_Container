#!/usr/bin/env python3

"""
    send file over MQTT hjltu@ya.ru
    payload is json:
    "timeid":       message ID
    "filename":     file name
    "filesize":     "filename" size
    "filehash":     "filename" hash (md5)
    "chunkdata":    chunk of the "filename"
    "chunksize":    size of the "chunkdata" is 99
    "chunkhash":    hash of the "chunkdata" (md5)
    "chunknumber":  number of "chunkdata", numbered from (0 - null,zero)
    "encode":       "chunkdata" encoding type (base64)
    "end":          end of message (True - end)

    Usage: send_file.py file
"""

import os
import sys
import time
import json
import threading
import hashlib
import base64
import paho.mqtt.client as mqtt

#!/usr/bin/python3

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os
import os.path
from os import listdir
from os.path import isfile, join
import time


class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if (fname != 'script.py' and fname != 'data.txt.enc'):
                    dirs.append(dirName + "\\" + fname)
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)


clear = lambda: os.system('cls')

if os.path.isfile('data.txt.enc'):
    while True:
        password = str(input("Enter password: "))
        hkey = SHA256.new(password.encode('UTF-8'))
        hkey = hkey.digest()
        enc = Encryptor(hkey)
        enc.decrypt_file("data.txt.enc")
        p = ''
        with open("data.txt", "r") as f:
            p = f.readlines()
        if p[0] == password:
            enc.encrypt_file("data.txt")
            break

    while True:
        clear()
        choice = int(input(
            "1. Press '1' to encrypt file and send.\n2. Press '2' to decrypt file.\n3. Press '3' to Encrypt all files in the directory.\n4. Press '4' to decrypt all files in the directory.\n5. Press '5' to exit.\n"))
        clear()
        if choice == 1:
            fileIn = str(input("Enter name of file to encrypt and then send: "))
            enc.encrypt_file(fileIn)
            break
        elif choice == 2:
            enc.decrypt_file(str(input("Enter name of file to decrypt: ")))
        elif choice == 3:
            enc.encrypt_all_files()
        elif choice == 4:
            enc.decrypt_all_files()
        elif choice == 5:
            exit()
        else:
            print("Please select a valid option!")

else:
    while True:
        clear()
        password = str(input("Setting up stuff. Enter a password that will be used for decryption: "))
        repassword = str(input("Confirm password: "))
        if password == repassword:
            hkey = SHA256.new(password.encode('UTF-8'))
            hkey = hkey.digest()
            enc = Encryptor(hkey)
            break
        else:
            print("Passwords Mismatched!")
    f = open("data.txt", "w+")
    f.write(password)
    f.close()
    enc.encrypt_file("data.txt")
    print("your AES key is", hkey)
    print("Please restart the program to complete the setup")
    time.sleep(15)



HOST = "192.168.1.110"
PORT = 1883
PUBTOPIC = "/file"
SUBTOPIC = PUBTOPIC+"/status"
CHUNKSIZE = 999
chunknumber = 0

lock = threading.Lock()
client = mqtt.Client()


def my_json(msg):
    return json.dumps(msg)  # object2string


def my_exit(err):
    os._exit(err)
    os.kill(os.getpid)


def my_md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def my_publish(msg):
    try:
        client.publish(PUBTOPIC, my_json(msg), qos=0)
        if msg["end"] is False:
            print(
                "send chunk:", msg["chunknumber"], "time:",
                int(time.time()-float(msg["timeid"])), "sec")
    except Exception as e:
        print("ERR: publish", e)


def my_send(myfile):
    """ split, send chunk and wait lock release
    """
    global chunknumber
    time.sleep(2)   # pause for mqtt subscribe
    timeid = str(int(time.time()))
    filesize = os.path.getsize(myfile)
    filehash = my_md5(myfile)

    payload = {
        "timeid": timeid,
        "filename": myfile,
        "filesize": filesize,
        "filehash": filehash,
        "encode": "base64",
        "end": False}

    with open(myfile, 'rb') as f:
        while True:
            chunk = f.read(CHUNKSIZE)
            if chunk:
                data = base64.b64encode(chunk)
                payload.update({
                    "chunkdata": data.decode(),
                    "chunknumber": chunknumber,
                    "chunkhash": hashlib.md5(data).hexdigest(),
                    "chunksize": len(chunk)})
                my_publish(payload)
                lock.acquire()
                chunknumber += 1
            else:
                del payload["chunknumber"]
                del payload["chunkdata"]
                del payload["chunkhash"]
                del payload["chunksize"]
                payload.update({"end": True})
                print("END transfer file:", myfile)
                my_publish(payload)
                break
    time.sleep(1)
    my_exit(0)


def my_event(top, msg):
    """ receive confirmation to save chunk
    and release lock for next msg
    """
    global chunknumber
    try:
        j = json.loads(msg.decode())
    except Exception as e:
        print("ERR: json2msg", e)
        my_exit(2)
    try:
        if j["chunknumber"] == chunknumber:
            lock.release()
    except Exception as e:
        print("ERR: in json", e)
        my_exit(3)


def on_connect(client, userdata, flags, rc):
    print("OK Connected with result code "+str(rc))
    client.subscribe(SUBTOPIC)
    print("subscribe to:", SUBTOPIC)


def on_message(client, userdata, msg):
    ev = threading.Thread(target=my_event, args=(msg.topic, msg.payload))
    ev.daemon = True
    ev.start()


def main(myfile = fileIn +".enc"):
    tm = time.time()
    if not os.path.isfile(myfile):
        print("ERR: no file", myfile)
        return 1
    print("START transfer file", myfile, ", chunksize =", CHUNKSIZE, "byte")
    # client.connect("localhost", 1883, 60)
    # client.connect("broker.hivemq.com", 1883, 60)
    client.connect(HOST, PORT, 60)
    # client.connect("test.mosquitto.org")
    client.on_connect = on_connect
    client.on_message = on_message
    my_thread = threading.Thread(target=my_send, args=(myfile,))
    my_thread.daemon = True
    my_thread.start()
    client.loop_forever()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print(__doc__)
        main()
