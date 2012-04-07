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
import sys
import logging
import logging.handlers
import getopt
import re
import smtplib
import time
import socket
import ConfigParser
import urlparse
import urllib2
import struct
import threading
import traceback
import random
from email.MIMEText import MIMEText
from email.Header import Header
from email.Utils import formatdate

version="0.1c"
default_config_path="/etc/aya.conf"
######## setting sample ###################
#[global]
#debug = True
#log_file_path = /var/log/aya.log
#pid_file_path = /var/run/aya.pid
#
#[entry_name1]
#polling_stop = False
#polling_host = <hotname or ip address>
#polling_protocols = ICMP, TCP:53, TCP:80, TCP:443, URL:http://user@pass:www/loation
#polling_interval = 60
#polling_timeout = 3
#proxy_url = http://user:pass@proxy/
#alert_threshold = 2/2
#alert_block_time = 300
#mail = True
#mail_tls = True
#mail_starttls = True
#mail_auth = False
#mail_smtp_host = <hostname or ip address>
#mail_smtp_port = 25
#mail_hostname = <hostname>
#mail_username = <user name>
#mail_password = <password>
#mail_to = <address1, address2, address3>
#mail_from = <address>
#mail_subject = $UPDOWN alert! $PHOST - $PPROTO from $MHOST
##########################################

# URL処理クラス
class URL:
    def __init__(self, http_url, proxy_url, timeout):
        self.http_url = http_url
        self.proxy_url = proxy_url
        self.timeout = int(timeout)
        self.logger = logging.getLogger("")
        self.default_proxy_port = ""
        self.default_http_port = ""
    def open(self):
        # URL接続処理
        try:
            handlers = []
            if self.proxy_url:
                proxy = urlparse.urlsplit(self.proxy_url)
                proxy_scheme = proxy.scheme
                proxy_username = proxy.username
                proxy_password = proxy.password
                proxy_hostname = proxy.hostname
                proxy_port = proxy.port
                if not proxy_port:
                    proxy_port = self.default_proxy_port
                else:
                    proxy_port = ":" + str(proxy_port)
                proxy_handler = urllib2.ProxyHandler({proxy_scheme:proxy_scheme + "://" + proxy_hostname + proxy_port})
                handlers.append(proxy_handler)
                if proxy_hostname and proxy_username and proxy_password:
                    proxy_auth_pwmgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
                    proxy_auth_pwmgr.add_password(None, proxy_hostname, proxy_username, proxy_password)
                    proxy_basic_auth_handler = urllib2.ProxyBasicAuthHandler(proxy_auth_pwmgr)
                    proxy_digest_auth_handler = urllib2.ProxyDigestAuthHandler(proxy_auth_pwmgr)
                    handlers.append(proxy_basic_auth_handler)
                    handlers.append(proxy_digest_auth_handler)
            http = urlparse.urlsplit(self.http_url)
            http_scheme = http.scheme
            http_username = http.username
            http_password = http.password
            http_hostname = http.hostname
            http_port = http.port
            if not http_port:
                http_port = self.default_http_port
            else:
                http_port = ":" + str(http_port)
            if http_hostname and http_username and http_password:
                http_auth_pwmgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
                http_auth_pwmgr.add_password(None, http_hostname, http_username, http_password)
                http_basic_auth_handler = urllib2.HTTPBasicAuthHandler(http_auth_pwmgr)
                http_digest_auth_handler = urllib2.HTTPDigestAuthHandler(http_auth_pwmgr)
                handlers.append(http_basic_auth_handler)
                handlers.append(http_digest_auth_handler)
            opener = urllib2.build_opener()
            for handler in handlers:
               opener.add_handler(handler)
            urllib2.install_opener(opener)
            fh = urllib2.urlopen(http_scheme + "://" + http_hostname + http_port + http.path + http.query + http.fragment, timeout=self.timeout)
            data = fh.read()
            self.logger.debug("url open %s - %s, data size = %d" % (self.proxy_url, self.http_url, len(data))) 
            # 問題がなければ OK を返す
            return "OK"
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            self.logger.info("failed in open url");
            self.logger.info("%s" % (trace));
            # 問題があれば OK 以外を返す。問題が分かりやすいのでスタックトレース返しておく。
            return " ".join(trace)

# ICMP処理クラス
class ICMP:
    ECHO_REPLY = 0
    ECHO_REQUEST = 8
    def __init__(self, host, timeout):
        self.host = host
        self.timeout = int(timeout)
        self.id = (int(time.time() * 1000) + os.getpid() + random.randint(0, 0xffff)) & 0xffff
        self.seq = 1
        self.logger = logging.getLogger("")
    def get_checksum(self, source):
        sum = 0
        max_count = len(source)
        count = 0
        while max_count - count > 1:
            val = (ord(source[count + 1]) << 8) | ord(source[count])
            sum = sum + val 
            count += 2
        if max_count - count == 1:
            sum += ord(source[count])
        sum = sum & 0xffffffff
        sum = (sum & 0xffff) + (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16)
        sum = ~sum & 0xffff
        sum = socket.htons(sum)
        return sum
    def send(self):
        try:
            # ICMP送信
            host = socket.gethostbyname(self.host)
            icmp = socket.getprotobyname("icmp")
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            sock.settimeout(self.timeout)
            send_header = struct.pack("!bbHHH", ICMP.ECHO_REQUEST, 0, 0, self.id, self.seq)
            double_size = struct.calcsize("d")
            send_data = struct.pack("d", time.time()) + "Are you alive?"
            checksum = self.get_checksum(send_header + send_data)
            send_header = struct.pack("!bbHHH", ICMP.ECHO_REQUEST, 0, checksum, self.id, self.seq)
            send_packet = send_header + send_data
            sock.sendto(send_packet, (host, icmp))
            while True:
                recv_packet, from_host = sock.recvfrom(1024)
                recv_header = recv_packet[20:28]
                recv_type, recv_code, recv_chksum, recv_id, recv_seq = struct.unpack("!bbHHH", recv_header)
                if ICMP.ECHO_REPLY == recv_type and self.id == recv_id and self.seq == recv_seq:
                    break;
            sock.close()
            sent_time = struct.unpack("d", recv_packet[28:28 + double_size])[0]
            self.logger.debug("icmp sent %s. id = %d, ttl = %lf" % (self.host, self.id, time.time() - sent_time)) 
            # 問題がなければ OK を返す
            return "OK"
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            self.logger.info("failed in send of icmp");
            self.logger.info("%s" % (trace));
            # 問題があれば OK 以外を返す。問題が分かりやすいのでスタックトレース返しておく。
            return " ".join(trace)

# TCP処理クラス
class TCP:
    def __init__(self, host, port, timeout):
        self.host = host
        self.port = int(port.strip())
        self.timeout = int(timeout)
        self.logger = logging.getLogger("")
    def connect(self):
        try:
            # TCP接続
            host = socket.gethostbyname(self.host)
            try:
                port = int(self.port)
            except ValueError:
                port = socket.getservbyname(self.port)
            sock = socket.socket()
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            sock.close()
            self.logger.debug("tcp connected to %s:%s" % (self.host, self.port)) 
            # 問題がなければ OK を返す
            return "OK"
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            self.logger.info("failed in connect of tcp");
            self.logger.info("%s" % (trace));
            # 問題があれば OK 以外を返す。問題が分かりやすいのでスタックトレース返しておく。
            return " ".join(trace)

# メール処理クラス
class Mail:
    def __init__(self, smtp_host, smtp_port, hostname,    \
                 username, password, to_addrs, from_addr, \
                 subject, body, tls, starttls, auth):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.hostname = hostname
        self.username = username
        self.password = password
        self.to_addrs = to_addrs
        self.from_addr = from_addr
        self.subject = subject
        self.body = body
        self.starttls = starttls
        self.tls = tls
        self.auth = auth
        self.encoding = "ISO-2022-JP"
        self.logger = logging.getLogger("")
    def create_message(self):
        # メールの送信メッセージ生成
        message = MIMEText(self.body, 'plain', self.encoding)
        message['Subject'] = Header(self.subject, self.encoding)
        message['From'] = self.from_addr
        message['To'] = self.to_addrs
        message['Date'] = formatdate()
        return message 
    def send(self):
        # メールの送信処理
        try:
            message = self.create_message()
            if self.tls.lower() == "true":
                sock = smtplib.SMTP_SSL()
            else:
                sock = smtplib.SMTP()
            sock.connect(self.smtp_host, self.smtp_port)
            sock.ehlo(self.hostname)
            if self.starttls.lower() == "true":
                sock.starttls()
                sock.ehlo(self.hostname)
            if self.auth.lower() == "true":
                sock.login(self.username, self.password)
            sock.sendmail(self.from_addr, self.to_addrs.split(","), message.as_string())
            sock.close()
            self.logger.debug("sent mail to %s" % (self.to_addrs))
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            self.logger.error("failed in send of mail");
            self.logger.error("%s" % (trace));

# Alert管理クラス
class AlertManager:
    STATE_UP       = 0
    STATE_DOWN     = 1
    STATE_UP_READY = 2
    STATE_TRANS_SELF          = 0
    STATE_TRANS_DOWN_ALERT    = 1
    STATE_TRANS_UP_READY      = 2
    STATE_TRANS_UP_ALERT      = 3
    STATE_TRANS_DOWN_NO_ALERT = 4
    NO_ALERT   = 0
    UP_ALERT   = 1
    DOWN_ALERT = 2
    def __init__(self): 
        self.blocking_end_time = {}
        self.state = {}
        self.result_pool = {}
        self.alert_threshold = None
        self.check_window = None
        self.alert_block_time = None
        self.state_trans_table = [ [ [ AlertManager.STATE_TRANS_SELF,          AlertManager.STATE_TRANS_SELF ],
                                     [ AlertManager.STATE_TRANS_DOWN_ALERT,    AlertManager.STATE_TRANS_DOWN_ALERT ] ],       
                                   [ [ AlertManager.STATE_TRANS_UP_READY,      AlertManager.STATE_TRANS_SELF ],
                                     [ AlertManager.STATE_TRANS_UP_READY,      AlertManager.STATE_TRANS_SELF ] ],
                                   [ [ AlertManager.STATE_TRANS_UP_ALERT,      AlertManager.STATE_TRANS_UP_ALERT ],
                                     [ AlertManager.STATE_TRANS_DOWN_NO_ALERT, AlertManager.STATE_TRANS_DOWN_NO_ALERT ] ] ]
        self.logger = logging.getLogger("")
    def set_params(self, alert_threshold, check_window, alert_block_time):
        # パラメータをセットする
        self.alert_threshold = int(alert_threshold)
        self.check_window = int(check_window)
        self.alert_block_time = int(alert_block_time)
    def get_results(self, id):
        # 貯めてあったポーリング結果を取り出す
        if len(self.result_pool[id]) >= self.check_window:
            return self.result_pool[id][0:self.check_window]
        else:
            return self.result_pool[id]
    def put_result(self, result, id):
        # ポーリング結果をポールに貯める
        result_info = { "time":time.time() }
        result_info["result"] = result
        if not id in self.result_pool:
            self.blocking_end_time[id] = 0
            self.result_pool[id] = []
            self.state[id] = AlertManager.STATE_UP
        if len(self.result_pool[id]) >= self.check_window:
            self.result_pool[id].pop()
            self.result_pool[id].insert(0, result_info)
        else:
            self.result_pool[id].insert(0, result_info)
    def get_alert(self, id):
        updown = 0    # up = 0, down = 1
        blocking = 0   # non blocking = 0, blocking = 1
        ng_count = 0
        # しきい値をこえていれば、downとする
        results = self.get_results(id)
        for result_info in results:
            if result_info["result"].lower() != "ok":
                ng_count += 1
        # ng回数がアラートのしきい値を超えていればダウンとみなす
        if ng_count >= self.alert_threshold:
            updown = 1
        # ただし、ng回数がアラートのしきい値を超えていなくても
        # ステートがUP_READYの時には最新の結果がOKでなければUPしたとみなさい
        elif self.state[id] == AlertManager.STATE_UP_READY and results[0]["result"].lower() != "ok":
            updown = 1
        # blocking終了時間を超えていなければブロッキングとする
        if time.time() <= self.blocking_end_time[id]:
            blocking = 1
        # 状態遷移テーブルから、遷移情報を取得
        action = self.state_trans_table[self.state[id]][updown][blocking]
        self.logger.debug("action %d, sate %d, updown %d, blocking %d" % (action, self.state[id], updown, blocking))
        if action == AlertManager.STATE_TRANS_SELF:
            return AlertManager.NO_ALERT
        elif action == AlertManager.STATE_TRANS_DOWN_ALERT:
            self.state[id] = AlertManager.STATE_DOWN
            self.blocking_end_time[id] = time.time() + int(self.alert_block_time)
            return AlertManager.DOWN_ALERT
        elif action == AlertManager.STATE_TRANS_UP_READY:
            self.state[id] = AlertManager.STATE_UP_READY
            return AlertManager.NO_ALERT
        elif action == AlertManager.STATE_TRANS_UP_ALERT:
            self.state[id] = AlertManager.STATE_UP
            return AlertManager.UP_ALERT
        elif action == AlertManager.STATE_TRANS_DOWN_NO_ALERT:
            self.state[id] = AlertManager.STATE_DOWN
            return AlertManager.NO_ALERT
        else:
            self.logger.error("unknown state transration. internal error");
            return AlertManager.NO_ALERT
    def result_to_string(self, result_info):
        return "%s %s" % (time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(result_info["time"])), result_info["result"])

# entryスレッドクラス
class EntryThread(threading.Thread):
    def __init__(self, config_path, section): 
        threading.Thread.__init__(self)
        self.config_path = config_path
        self.section = section
        self.config = None
        self.entry_config = {}
        self.end_flag = False
        self.polling_items = []
        self.alert_threshold = 3
        self.check_window = 3
        self.mail_subject_alert_updown_re = re.compile("\$UPDOWN")
        self.mail_subject_polling_host_re = re.compile("\$PHOST")
        self.mail_subject_polling_protocol_re = re.compile("\$PPROTO")
        self.mail_subject_mail_hostname_re = re.compile("\$MHOST")
        self.config_defaults = { "polling_stop"      : "False",
                                 "polling_host"      : "",
                                 "polling_protocols" : "", 
                                 "polling_interval"  : "60", 
                                 "polling_timeout"   : "3", 
                                 "proxy_url"         : "", 
                                 "alert_threshold"   : "3/3", 
                                 "alert_block_time"  : "0", 
                                 "mail"              : "False", 
                                 "mail_tls"          : "False", 
                                 "mail_starttls"     : "False", 
                                 "mail_auth"         : "False", 
                                 "mail_smtp_host"    : "", 
                                 "mail_smtp_port"    : "587", 
                                 "mail_hostname"     : "", 
                                 "mail_username"     : "", 
                                 "mail_password"     : "", 
                                 "mail_to"           : "", 
                                 "mail_from"         : "", 
                                 "mail_subject"      : "AYA Alert! $PHOST - $PPROTO from $MHOST" }
        self.entry_config_keys =  [ "polling_stop",
                                    "polling_host",
                                    "polling_protocols", 
                                    "polling_interval", 
                                    "polling_timeout",
                                    "proxy_url", 
                                    "alert_threshold", 
                                    "alert_block_time", 
                                    "mail", 
                                    "mail_tls", 
                                    "mail_starttls", 
                                    "mail_auth", 
                                    "mail_smtp_host", 
                                    "mail_smtp_port", 
                                    "mail_hostname", 
                                    "mail_username", 
                                    "mail_password", 
                                    "mail_to", 
                                    "mail_from", 
                                    "mail_subject" ]
        self.required_keys =            [ "polling_host",
                                          "polling_protocols" ]
        self.required_mail_keys =       [ "mail_smtp_host", 
                                          "mail_hostname", 
                                          "mail_to", 
                                          "mail_from" ]
        self.required_mail_auth_keys =  [ "mail_username", 
                                          "mail_password" ]
        self.logger = logging.getLogger("")
        self.alert_manager = AlertManager()
    def stop(self):
        self.end_flag = True
    def load_config(self):
        # コンフィグの読み込み
        self.config = ConfigParser.SafeConfigParser(self.config_defaults)
        self.config.read(config_path)
    def load_entry_config(self):
        # エントリーセクションのコンフィグの取得
        entry_config = {}
        for key in self.entry_config_keys:
            entry_config[key] = self.config.get(self.section, key).strip()
        for required_key in self.required_keys:
            if not entry_config[required_key]:
                self.logger.error("%s option is required" % (required_key))
                return False
        if entry_config["mail"].lower() == "true":
            for required_mail_key in self.required_mail_keys:
                if not entry_config[required_mail_key]:
                    self.logger.error("%s option is required, if use mail" % (required_mail_key))
                    return False
            if entry_config["mail_auth"].lower() == "true":
                for required_mail_auth_key in self.required_mail_auth_keys:
                    if not entry_config[required_mail_auth_key]:
                        self.logger.error("%s option is required, if use mail_auth" % (required_mail_auth_key))
                        return False
        self.entry_config = entry_config
        # protocolsオプションの値をパース
        self.polling_items = self.entry_config["polling_protocols"].split(",")
        # thresholdオプションの値をパース
        elems = self.entry_config["alert_threshold"].split("/")
        if len(elems) == 2:
            self.alert_threshold = elems[0].strip()
            self.check_window = elems[1].strip()
        else:
            self.logger.error("Invalid threshold, use default 3/3");
        return True
    def icmp_polling(self):
        # ICMPの送信処理
        icmp = ICMP(self.entry_config["polling_host"], self.entry_config["polling_timeout"])
        result = icmp.send()
        return result
    def tcp_polling(self, protocol):
        # TCPの接続処理
        port = protocol[4:].strip() # "TCP:"部分を取り除く
        tcp = TCP(self.entry_config["polling_host"], port, self.entry_config["polling_timeout"])
        result = tcp.connect()
        return result
    def url_polling(self, protocol):
        # URLの接続処理
        http_url = protocol[4:].strip() # "URL:"部分を取り除く
        url = URL(http_url, self.entry_config["proxy_url"], self.entry_config["polling_timeout"])
        result = url.open()
        return result
    def create_mail_subject(self, updown,  protocol):
        # 送信メールのsubjectを生成
        subject = self.entry_config["mail_subject"]
        subject = self.mail_subject_alert_updown_re.sub(updown, subject)
        subject = self.mail_subject_polling_host_re.sub(self.entry_config["polling_host"], subject)
        subject = self.mail_subject_polling_protocol_re.sub(protocol, subject)
        subject = self.mail_subject_mail_hostname_re.sub(self.entry_config["mail_hostname"], subject)
        return subject
    def create_mail_body(self, protocol):
        # 送信メールのbodyメッセージを生成
        body = "---\n"
        for result in self.alert_manager.get_results(protocol):
            body += "%s\n" % (self.alert_manager.result_to_string(result))
        return body
    def send_mail(self, updown, protocol):
        # メール送信処理
        subject = self.create_mail_subject(updown, protocol)
        body = self.create_mail_body(protocol)
        mail = Mail(self.entry_config["mail_smtp_host"], self.entry_config["mail_smtp_port"],
                    self.entry_config["mail_hostname"], self.entry_config["mail_username"],
                    self.entry_config["mail_password"], self.entry_config["mail_to"],
                    self.entry_config["mail_from"], subject, body,
                    self.entry_config["mail_tls"], self.entry_config["mail_starttls"],
                    self.entry_config["mail_auth"])
        mail.send()
    def run(self):
        # スレッドメインループ
        while not self.end_flag:
            # コンフィグを読み込み
            self.logger.debug("loading config in %s thread" % (self.section))
            self.load_config()
            if not self.load_entry_config():
                # エントリーコンフィグの読込に失敗
                self.logger.error("failed in load entry config")
                time.sleep(int(self.entry_config["polling_interval"]))
                continue
            # polling stopが指定されている場合はなにもしない
            if self.entry_config["polling_stop"].lower() == "true":
                # 次のポーリング時間までsleep
                self.logger.debug("skip polling")
                time.sleep(int(self.entry_config["polling_interval"]))
                continue
            # アラートマネージャーのパラメータを更新
            self.alert_manager.set_params(self.alert_threshold, self.check_window, self.entry_config["alert_block_time"])
            # プロトコルごとのポーリング処理
            for protocol in self.polling_items:
                # ポーリング処理をして結果をプールに貯める
                protocol = protocol.strip()
                result = None
                if protocol == "ICMP":
                    result = self.icmp_polling()
                elif re.match("TCP:", protocol): 
                    result = self.tcp_polling(protocol)
                elif re.match("URL:", protocol): 
                    result = self.url_polling(protocol)
                else:
                    self.logger.error("%s is unsupport protocol" % (protocol))
                    continue
                # 結果をアラートマネージャーに渡す
                self.alert_manager.put_result(result, protocol)
                # アラートマネージャーからアラート情報を取り出す
                alert = self.alert_manager.get_alert(protocol)
                if alert == AlertManager.NO_ALERT:
                    self.logger.debug("no alert %s - %s" % (self.entry_config["polling_host"], protocol))
                    continue
                # アラート発生
                updown = None
                if alert == AlertManager.UP_ALERT:
                    updown = "UP"
                    self.logger.info("%s alert %s - %s" % (updown, self.entry_config["polling_host"], protocol))
                elif alert == AlertManager.DOWN_ALERT:
                    updown = "DOWN"
                    self.logger.info("%s alert %s - %s" % (updown, self.entry_config["polling_host"], protocol))
                else:
                    self.logger.error("unknown alert. internal error")
                    continue
                # メールの送信処理 
                if self.entry_config["mail"].lower() == "true":
                    self.send_mail(updown, protocol)
            # 次のポーリング時間までsleep
            time.sleep(int(self.entry_config["polling_interval"]))

# Aya メインクラス　
class Aya:
    def __init__(self, config_path):
        self.config_path = config_path
        self.config = None
        self.global_config = None
        self.config_defaults = { "debug"             : "False",
                                 "log_file_path"     : "/var/log/aya.log",
                                 "pid_file_path"     : "/var/run/aya.pid" }
        self.global_config_keys = [ "debug",
                                    "log_file_path",
                                    "pid_file_path" ]
        self.logger = None
    def load_config(self):
        # コンフィグの読み込み
        self.config = ConfigParser.SafeConfigParser(self.config_defaults)
        self.config.read(self.config_path)
    def load_global_config(self):
        # グローバルセクションのコンフィグの取得
        global_config = {}
        for key in self.global_config_keys:
            global_config[key] = self.config.get("global", key).strip()
        self.global_config = global_config
    def create_logger(self, debug, log_file_path):
        # ロガー生成
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(process)d %(thread)d %(message)s")
        handler = logging.handlers.TimedRotatingFileHandler(log_file_path, "D", 1, 10)
        handler.setFormatter(formatter)
        logger = logging.getLogger("")
        if debug.lower() == "true":
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        return logger
    def init_global(self):
        self.load_global_config()
        # ロガー生成
        self.logger = self.create_logger(self.global_config["debug"], self.global_config["log_file_path"])
        # デーモン化
        self.logger.info("-- aya start --")
        try:
            pid = os.fork()
            if pid > 0:
                # 親
                return False
            os.setsid()
            pid = os.fork()
            if pid > 0:
                # 親
                return False
            os.chdir('/')
            os.umask(0)
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            self.logger.error("failed in daemonize");
            self.logger.error("%s" % (trace));
            sys.exit(1)
        # 入力、出力の変更
        try:
            sys.stdin = open("/dev/null", "r")
            sys.stdout = open(self.global_config["log_file_path"] + "error", "w")
            sys.stderr = open(self.global_config["log_file_path"] + "error", "w")
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            self.logger.error("failed in open log file");
            self.logger.error("%s" % (trace));
            sys.exit(1)
        # process id ファイル生成
        try:
            f = open(self.global_config["pid_file_path"], "w")
            f.write("%lu" % os.getpid())
            f.close()
        except:
            trace = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
            self.logger.error("failed in make pid file");
            self.logger.error("%s" % (trace));
            sys.exit(1)
        return True
    def start(self):
        # 初回のコンフィグ読み込み
        self.load_config()
        self.load_global_config()
        if not self.init_global():
            return
        threads = []
        remove_threads = []
        while True:
            # 定期的にコンフィグを読み込む
            self.logger.debug("loading config in main thread")
            self.load_config()
            sections = self.config.sections()
            # 存在していたセクションが無くなっていればスレッド停止
            for thread in threads:
                exist = False
                for section in sections:
                    if thread.getName() == section:
                        exist = True
                        break;
                if not exist:
                    self.logger.debug("stopping %s thread" % (thread.getName()))
                    thread.stop() 
                    remove_threads.append(thread)
            # エントリーセクション毎にスレッドを作る
            for section in self.config.sections():
                # globalは読み飛ばす
                if section == "global":
                    continue;
                # 既にスレッドが存在していればスキップ
                exist = False
                for thread in threads:
                    if thread.getName() == section:
                        exist = True
                        break;
                if exist:
                    continue
                # スレッドが存在しないセクションがあればスレッド追加
                # globalセクションの情報を渡す。
                self.logger.debug("starting %s thread" % (section))
                entry_thread = EntryThread(self.config_path, section)
                threads.append(entry_thread)
                entry_thread.setDaemon(True)
                entry_thread.setName(section)
                entry_thread.start()
            # 削除スレッドがいる場合はここでjoin
            for remove_thread in remove_threads:
                if not remove_thread.isAlive():
                    # スレッドの回収
                    self.logger.debug("thread join %s" % (remove_thread.getName()))
                    for thread in threads:
                        if thread.getName() == remove_thread.getName():
                            threads.remove(thread)
                            break;
                    remove_threads.remove(remove_thread)
                    remove_thread.join()
            # 30秒待つ
            time.sleep(30)
        for thread in threads:
            thread.join()
        self.logger.info("-- aya stop --")
        
def usage():
    print("%s [-h] [-v] [-c <config file path>]" % (sys.argv[0]))
    sys.exit(0)

# コマンドライン引数の処理
config_path = default_config_path
try:
    optlist, args = getopt.getopt(sys.argv[1:], "c:vh", longopts=["config=", "version", "help"])
except getopt.GetoptError:
    usage()
for opt, args in optlist:
    if opt in ("-c", "--config"):
        config_path = args
    if opt in ("-v", "--version"):
        print("version %s" % (version))
        sys.exit(0)
    if opt in ("-h", "--help"):
        usage()

# スタート処理
aya = Aya(config_path)
aya.start()

