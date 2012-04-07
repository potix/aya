#!/usr/bin/env python
# -*- coding: utf-8 -*-

## Copyright (c) 2010- Hiroyuki kakine
##
## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to deal
## in the Software without restriction, including without limitation the rights
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
##
## The above copyright notice and this permission notice shall be included in
## all copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
## THE SOFTWARE.

import os
import os.path
import sys
import getopt
import re
import smtplib
import time
import socket
import datetime
import ConfigParser
import distutils
import logging
import logging.handlers
import traceback
from email.MIMEText import MIMEText
from email.Header import Header
from email.Utils import formatdate
from distutils.dir_util import mkpath

######## setting sample ###################
# default config path /etc/mailrc
#                     /$HOME/.mailrc
###########################################
#[mail]
#tls = True
#auth = True
#smtp_host = smtp-server
#smtp_port = smtp-server-port
#hostname = hostname
#username =  username
#password = userpassword
#to = address1, adress2, address3 
#from = address
#subject = anything event mail send by $MHOST
#
#[global]
#log_file_path = /var/log/mail
#debug = True
##########################################

default_config_file_path = os.path.join(os.environ['HOME'], ".mailrc")

class Mail:
    def __init__(self, config_file_path):
        self.config_file_path = config_file_path
        self.config = None
        self.global_config = None
        self.mail_config = None
        self.config_defaults = { "debug"             : "False",
                                 "log_file_path"     : "./mail.log",
                                 "tls"               : "False", 
                                 "starttls"          : "False", 
                                 "auth"              : "False", 
                                 "smtp_host"         : "", 
                                 "smtp_port"         : "587", 
                                 "hostname"          : "", 
                                 "username"          : "", 
                                 "password"          : "", 
                                 "to"                : "",
                                 "from"              : "",
                                 "subject"           : "" }
        self.mail_config_keys = { "tls"               : "False", 
                                  "starttls"          : "False", 
                                  "auth"              : "False", 
                                  "smtp_host"         : "", 
                                  "smtp_port"         : "587", 
                                  "hostname"          : "", 
                                  "username"          : "", 
                                  "password"          : "", 
                                  "to"                : "",
                                  "from"              : "",
                                  "subject"           : "" }
        self.global_config_keys = [ "debug",
                                    "log_file_path"]
        self.required_mail_keys =       [ "smtp_host",
                                          "hostname",
                                          "to",
                                          "from" ]
        self.required_mail_auth_keys =  [ "username",
                                          "password" ]
        self.encoding = "ISO-2022-JP"
        self.mail_subject_mail_hostname_re = re.compile("\$MHOST")
        self.logger = None
    def load_config(self):
        self.config = ConfigParser.SafeConfigParser(self.config_defaults)
        self.config.read(self.config_file_path)
    def load_global_config(self):
        global_config = {}
        for key in self.global_config_keys:
            global_config[key] = self.config.get("global", key).strip()
        self.global_config = global_config
    def load_mail_config(self):
        mail_config = {}
        for key in self.mail_config_keys:
            mail_config[key] = self.config.get("mail", key).strip()
        for required_mail_key in self.required_mail_keys:
            if not mail_config[required_mail_key]:
                self.logger.error("%s option is required" % (required_mail_key))
                return False
            if mail_config["auth"].lower() == "true":
                for required_mail_auth_key in self.required_mail_auth_keys:
                    if not mail_config[required_mail_auth_key]:
                        self.logger.error("%s option is required, if use mail_auth" % (required_mail_auth_key))
                        return False
        self.mail_config = mail_config
        return True
    def create_logger(self, debug, log_file_path):
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(process)d %(thread)d %(message)s")
        handler = logging.handlers.TimedRotatingFileHandler(log_file_path, "D", 1, 10)
        handler.setFormatter(formatter)
        self.logger = logging.getLogger("")
        if debug.lower() == "true":
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)
    def create_mail_subject(self, subject):
        subject = self.mail_config["subject"]
        subject = self.mail_subject_mail_hostname_re.sub(self.mail_config["hostname"], subject)
        return subject
    def create_mail_body(self, body):
        body = time.strftime("%Y/%m/%d %H:%M:%S")  + " " + body + "\n"
        return body
    def create_message(self, subject, body):
        message = MIMEText(self.create_mail_body(body), 'plain', self.encoding)
        message['Subject'] = Header(self.create_mail_subject(subject), self.encoding)
        message['From'] = self.mail_config["from"]
        message['To'] = self.mail_config["to"]
        message['Date'] = formatdate()
        return message
    def send(self, subject, body):
        self.load_config()
        self.load_global_config()
        self.create_logger(self.global_config["debug"], self.global_config["log_file_path"])
        try:
            if not self.load_mail_config():
                self.logger.error("failed in load mail config");
                sys.exit(1)
            if subject:
               self.mail_config["subject"] = subject
            message = self.create_message(self.mail_config["subject"], body)
            if self.mail_config["tls"].lower() == "true":
                sock = smtplib.SMTP_SSL()
            else:
                sock = smtplib.SMTP()
            sock.connect(self.mail_config["smtp_host"], self.mail_config["smtp_port"])
            sock.ehlo(self.mail_config["hostname"])
            if self.mail_config["starttls"].lower() == "true":
                sock.starttls()
                sock.ehlo(self.mail_config["hostname"])
            if self.mail_config["auth"].lower() == "true":
                sock.login(self.mail_config["username"], self.mail_config["password"])
            sock.sendmail(self.mail_config["from"], self.mail_config["to"].split(","), message.as_string())
            sock.close()
            self.logger.debug("sent mail to %s" % (self.mail_config["to"]))
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            self.logger.error("failed in send of mail");
            self.logger.error("%s" % (trace));

config_file_path = default_config_file_path
subject = ""
body = ""
try:
    optlist, args = getopt.getopt(sys.argv[1:], "c:s:b:", longopts=["config=", "subject=", "body="])
except getopt.GetoptError:
    print("invalid argument")
    sys.exit(1)
for opt, args in optlist:
    if opt in ("-c", "--config"):
        config_file_path = args
    elif opt in ("-s", "--subject"):
        subject = args
    elif opt in ("-b", "--body"):
        body = args
mail = Mail(config_file_path)
mail.send(subject, body)
