import datetime
import errno
import hashlib
import os
import json
import re
from enum import Enum
import time
import itertools
import shutil
import sys
from sklearn.metrics import f1_score

import random

import numpy as np
import torch
def getmask(idx,num_node):
    mask = torch.zeros(num_node, dtype=torch.bool)
    mask[idx] = 1
    return mask

def my_obj_pairs_hook(lst):
    """
    obj pairs hook deal same key items in dict. push them into key: list. not overwrite key value.
    """
    result = {}
    count = {}
    for key, val in lst:
        if key in count:
            count[key] = count[key] + 1
        else:
            count[key] = 1
        if key in result:
            if count[key] > 2:
                result[key].append(val)
            else:
                result[key] = [result[key], val]
        else:
            result[key] = val
    return result


class HandshakeType(Enum):
    HelloRequest = 0
    ClientHello = 1
    ServerHello = 2
    sslSessionTicket = 4
    Certificate = 11
    ServerKeyExchange = 12
    CertificateRequest = 13
    ServerHelloDone = 14
    CertificateVerify = 15
    ClientKeyExchange = 16
    Finished = 20
    EncryptedHandshakeMessage = 22


class ContentType(Enum):
    ChangeCipherSpec = 20
    Alert = 21
    Handshake = 22
    ApplicationData = 23
    heartbeat = 24
    tls12_cid = 25
    ACK = 26


class Feature:
    """
    Feature:

    """

    def __init__(self, stream: dict):
        self.__stream = stream
        self.__feature = {}

        self.__add_item()

    def get_feature(self):
        """get feature instance
            Args:

            Returns:
                list: self.__features [{feature}[,{feature}]}
        """
        return self.__feature

    def __add_item_pac(self, pac, key):
        """Add item from single pac.
            Args:
                pac (dict): source pac
                key (str): key value
        """
        # check key is exist.
        if pac.has_key(key):
            self.__feature[key] = pac[key]

    def __add_tcp_item(self, pac_tcp: dict):
        """Add tcp related features
        """
        self.__feature.setdefault("tcp_srcport", pac_tcp.get("tcp.srcport"))  # 源端口
        self.__feature.setdefault("tcp_dstport", pac_tcp.get("tcp.dstport"))  # 目的端口

    def __add_ssl_item(self, pac: dict, pac_ssl: dict):
        """Add ssl related features
        """

        if isinstance(pac_ssl, str):
            return

        if pac_ssl.get("ssl.record") is not None:
            pac_record_raw = pac_ssl.get("ssl.record_raw")
            pac_record = pac_ssl.get("ssl.record")
            # hand multi pac_records in one tls
            if pac_record.__class__.__name__ == "dict":
                pac_records = [pac_record]
                pac_records_raw = [pac_record_raw]
            else:
                pac_records = pac_record
                pac_records_raw = pac_record_raw

            for index, pac_record in enumerate(pac_records):
                record_content_type = pac_record.get("ssl.record.content_type")
                if record_content_type is not None:
                    self.__feature["content_type"][ContentType(int(record_content_type)).name] += 1
                elif pac_record.get("ssl.record.opaque_type") == "23":
                    self.__feature["content_type"]["ApplicationData"] += 1
                    if pac["_source"]["layers"]["ssl"]["ssl.srcport"] == "443":
                        self.__feature["recordLayer_size"].append(int(pac_record.get("ssl.record.length")))
                    else:
                        self.__feature["recordLayer_size"].append(-int(pac_record.get("ssl.record.length")))
                if pac_record.get("ssl.handshake") is not None:
                    raw_bytes = pac_records_raw[index][0]
                    raw_bytes_len = len(raw_bytes)
                    if raw_bytes_len % 2 != 0:
                        raw_bytes = raw_bytes + '0'
                    for i in range(0, raw_bytes_len, 2):
                        self.__feature["raw_bytes"].append(int(raw_bytes[i:i + 2], 16))
                    pac_handshake = pac_record.get("ssl.handshake")
                    if pac_handshake.__class__.__name__ == "dict":
                        self.__deal_ssl_handshake(pac_handshake)
                    #                         self.__deal_handshake_extension(pac_handshake)
                    elif pac_handshake.__class__.__name__ == "list":
                        for hs in pac_handshake:
                            self.__deal_ssl_handshake(hs)
                #                             self.__deal_handshake_extension(hs)
                elif pac_record.get("ssl.handshake.type") is not None:
                    raw_bytes = pac_records_raw[index][0]
                    raw_bytes_len = len(raw_bytes)
                    if raw_bytes_len % 2 != 0:
                        raw_bytes = raw_bytes + '0'
                    for i in range(0, raw_bytes_len, 2):
                        self.__feature["raw_bytes"].append(int(raw_bytes[i:i + 2], 16))
                    pac_handshake = pac_record
                    self.__deal_ssl_handshake(pac_handshake)
                else:
                    if record_content_type is None or ContentType(int(record_content_type)).name == "ApplicationData":
                        self.__application_flag = 1

    def __add_tls_item(self, pac: dict, pac_tls: dict):
        """Add ssl related features
        """

        if isinstance(pac_tls, str):
            return
        if pac_tls.get("tls.record") is not None:
            pac_record_raw = pac_tls.get("tls.record_raw")
            pac_record = pac_tls.get("tls.record")
            # hand multi pac_records in one tls
            if pac_record.__class__.__name__ == "dict":
                pac_records = [pac_record]
                pac_records_raw = [pac_record_raw]
            else:
                pac_records = pac_record
                pac_records_raw = pac_record_raw

            for index, pac_record in enumerate(pac_records):
                record_content_type = pac_record.get("tls.record.content_type")
                if record_content_type is not None:
                    self.__feature["content_type"][ContentType(int(record_content_type)).name] += 1
                elif pac_record.get("tls.record.opaque_type") == "23":
                    self.__feature["content_type"]["ApplicationData"] += 1
                    if pac["_source"]["layers"]["tcp"]["tcp.srcport"] == "443":
                        self.__feature["recordLayer_size"].append(int(pac_record.get("tls.record.length")))
                    else:
                        self.__feature["recordLayer_size"].append(-int(pac_record.get("tls.record.length")))
                if pac_record.get("tls.handshake") is not None:
                    raw_bytes = pac_records_raw[index][0]
                    raw_bytes_len = len(raw_bytes)
                    if raw_bytes_len % 2 != 0:
                        raw_bytes = raw_bytes + '0'
                    for i in range(0, raw_bytes_len, 2):
                        self.__feature["raw_bytes"].append(int(raw_bytes[i:i + 2], 16))

                    pac_handshake = pac_record.get("tls.handshake")
                    if pac_handshake.__class__.__name__ == "dict":
                        self.__deal_tls_handshake(pac_handshake)
                    #                         self.__deal_handshake_extension(pac_handshake)
                    elif pac_handshake.__class__.__name__ == "list":
                        for hs in pac_handshake:
                            self.__deal_tls_handshake(hs)
                #                             self.__deal_handshake_extension(hs)
                elif pac_record.get("tls.handshake.type") is not None:
                    raw_bytes = pac_records_raw[index][0]
                    raw_bytes_len = len(raw_bytes)
                    if raw_bytes_len % 2 != 0:
                        raw_bytes = raw_bytes + '0'
                    for i in range(0, raw_bytes_len, 2):
                        self.__feature["raw_bytes"].append(int(raw_bytes[i:i + 2], 16))
                    pac_handshake = pac_record
                    self.__deal_tls_handshake(pac_handshake)
                else:
                    if record_content_type is None or ContentType(
                            int(record_content_type)).name == "ApplicationData":
                        self.__application_flag = 1

    def __deal_ssl_handshake(self, pac_handshake: dict):
        """Deal ssl handshake info based on handshake type
        """
        #         print("this is handshake...")

        # print(self.__feature)
        self.__feature["content_type"]["Handshake"] += 1

        handshake_type = int(pac_handshake.get("ssl.handshake.type"))
        # print(pac_handshake)
        self.__feature["handshake_type"][HandshakeType(int(handshake_type)).name] += 1

        func_dic = {
            "ClientHello": self.__deal_handshake_ssl_client_hello,
            "ServerHello": self.__deal_handshake_ssl_server_hello,
            "Certificate": self.__deal_handshake_ssl_certificate,
            # "ServerKeyExchange": self.__deal_handshake_serverkey_exchange,
            # "CertificateRequest": self.__deal_handshake_certificate_request,
            # "ServerHelloDone": self.__deal_handshake_server_hello_done,
            # "CertificateVerify": self.__deal_handshake_certificate_verify,
            "ClientKeyExchange": self.__deal_handshake_ssl_client_key_exchange,
            # "Finished": self.__deal_handshake_finished,
            # "EncryptedHandshakeMessage": self.__deal_handshake_encrypted_handshake_message,
        }
        # print(pac_handshake)
        #         print(f"{HandshakeType(handshake_type).name}: {handshake_type}")
        if func_dic.get(HandshakeType(handshake_type).name) is not None:
            func_dic.get(HandshakeType(handshake_type).name)(pac_handshake)

    def __deal_tls_handshake(self, pac_handshake: dict):
        """Deal ssl handshake info based on handshake type
        """
        #         print("this is handshake...")

        # print(self.__feature)
        self.__feature["content_type"]["Handshake"] += 1

        handshake_type = int(pac_handshake.get("tls.handshake.type"))
        # print(pac_handshake)
        self.__feature["handshake_type"][HandshakeType(int(handshake_type)).name] += 1

        func_dic = {
            "ClientHello": self.__deal_handshake_tls_client_hello,
            "ServerHello": self.__deal_handshake_tls_server_hello,
            "Certificate": self.__deal_handshake_tls_certificate,
            # "ServerKeyExchange": self.__deal_handshake_serverkey_exchange,
            # "CertificateRequest": self.__deal_handshake_certificate_request,
            # "ServerHelloDone": self.__deal_handshake_server_hello_done,
            # "CertificateVerify": self.__deal_handshake_certificate_verify,
            "ClientKeyExchange": self.__deal_handshake_tls_client_key_exchange,
            # "Finished": self.__deal_handshake_finished,
            # "EncryptedHandshakeMessage": self.__deal_handshake_encrypted_handshake_message,
        }
        # print(pac_handshake)
        #         print(f"{HandshakeType(handshake_type).name}: {handshake_type}")
        if func_dic.get(HandshakeType(handshake_type).name) is not None:
            func_dic.get(HandshakeType(handshake_type).name)(pac_handshake)

    def __deal_handshake_ssl_client_hello(self, handshake_msg: dict):
        """Deal ssl client hello
        """

        for key in handshake_msg.keys():
            matchObj = re.match(r'Extension: (.*) \(len=([0-9]*)\)', key, re.M)
            if matchObj:
                self.__feature["extensions"].append(matchObj.group(1))
        self.__feature["version"] = handshake_msg["ssl.handshake.version"]

        if handshake_msg["ssl.handshake.ciphersuites"].get("ssl.handshake.ciphersuite") is not None:
            cs = handshake_msg["ssl.handshake.ciphersuites"]["ssl.handshake.ciphersuite"]
        else:
            cs = handshake_msg["ssl.handshake.ciphersuites"]["ssl.handshake.cipherspec"]
        self.__feature["cs"] = cs

    def __deal_handshake_tls_client_hello(self, handshake_msg: dict):
        """Deal tls client hello
        """
        for key in handshake_msg.keys():
            matchObj = re.match(r'Extension: (.*) \(len=([0-9]*)\)', key, re.M)
            if matchObj:
                self.__feature["extensions"].append(matchObj.group(1))
            self.__feature["version"] = handshake_msg["tls.handshake.version"]

        if handshake_msg["tls.handshake.ciphersuites"].get("tls.handshake.ciphersuite") is not None:
            cs = handshake_msg["tls.handshake.ciphersuites"]["tls.handshake.ciphersuite"]
        else:
            cs = handshake_msg["tls.handshake.ciphersuites"]["tls.handshake.cipherspec"]
        self.__feature["cs"] = cs


    def __deal_handshake_ssl_server_hello(self, handshake_msg: dict):
        """Deal ssl server hello
        """
        #         print("server hello")
        if handshake_msg.get("ssl.handshake.ciphersuite") is not None:
            scs = handshake_msg["ssl.handshake.ciphersuite"]
        else:
            scs = handshake_msg['ssl.handshake.cipherspec']
        self.__feature["scs"].append(scs)

    def __deal_handshake_tls_server_hello(self, handshake_msg: dict):
        """Deal tls server hello
        """
        #         print("server hello")

        if handshake_msg.get("tls.handshake.ciphersuite") is not None:
            scs = handshake_msg["tls.handshake.ciphersuite"]
        else:
            scs = handshake_msg['tls.handshake.cipherspec']
        self.__feature["scs"].append(scs)

    def __deal_handshake_ssl_certificate(self, handshake_msg: dict):
        """Deal ssl certificate
        """
        #         print("certificate")
        if self.__feature["handshake_type"]["Certificate"] > 1:
            return
        string_type = ["x509sat.printableString", "x509sat.printableString", "x509sat.uTF8String", "x509sat.IA5String",
                       "x509sat.teletexString"]

        if handshake_msg["ssl.handshake.certificates_length"] == "0":
            return
        c_trees = handshake_msg["ssl.handshake.certificates"]["ssl.handshake.certificate_tree"]
        if isinstance(c_trees, dict):
            c_num = 1
            c_tree = c_trees
        else:
            c_num = len(c_trees)
            c_tree = c_trees[0]
        valid_tree = c_tree["x509af.signedCertificate_element"]["x509af.validity_element"]
        # print(valid_tree)
        notBefore = valid_tree["x509af.notBefore_tree"]["x509af.utcTime"]
        try:
            notAfter = valid_tree["x509af.notAfter_tree"]["x509af.utcTime"]
        except:
            notAfter = valid_tree["x509af.notAfter_tree"]["x509af.generalizedTime"]
        try:
            notBefore = time.mktime(time.strptime(notBefore, "%y-%m-%d %H:%M:%S (UTC)"))
        except:
            notBefore = time.mktime(time.strptime(notBefore, "%Y-%m-%d %H:%M:%S (UTC)"))
        try:
            notAfter = time.mktime(time.strptime(notAfter, "%y-%m-%d %H:%M:%S (UTC)"))
        except:
            notAfter = time.mktime(time.strptime(notAfter, "%Y-%m-%d %H:%M:%S (UTC)"))
        self.__feature["certificate_validity"] = notAfter - notBefore

        self.__feature["certificate_num"] = c_num
        if c_tree["x509af.signedCertificate_element"]["x509af.issuer_tree"]["x509if.rdnSequence"] == "0":
            return
        # print(c_tree["x509af.signedCertificate_element"]["x509af.issuer_tree"])
        issuer_tree = c_tree["x509af.signedCertificate_element"]["x509af.issuer_tree"]["x509if.rdnSequence_tree"][
            "x509if.RDNSequence_item_tree"]
        if isinstance(issuer_tree, dict):
            issuer_relative = issuer_tree["x509if.RelativeDistinguishedName_item_element"]
        else:
            if issuer_tree[-1]["x509if.RelativeDistinguishedName_item_element"].get(
                    "x509sat.DirectoryString_tree") is not None:
                issuer_relative = issuer_tree[-1]["x509if.RelativeDistinguishedName_item_element"]
            elif list(issuer_tree[-1]["x509if.RelativeDistinguishedName_item_element"].keys())[-1] in string_type:
                issuer_relative = issuer_tree[-1]["x509if.RelativeDistinguishedName_item_element"]
            else:
                issuer_relative = issuer_tree[0]["x509if.RelativeDistinguishedName_item_element"]
        if issuer_relative.get("x509sat.DirectoryString_tree") is not None:
            issuer_directory = issuer_relative["x509sat.DirectoryString_tree"]
        else:
            issuer_directory = issuer_relative
        # print(issuer_tree)
        # print(issuer_relative)
        for st in string_type:
            if st in issuer_directory.keys():
                issuer = issuer_directory[st]
        self.__feature["issuer"] = issuer

        subject_tree = c_tree["x509af.signedCertificate_element"]["x509af.subject_tree"]["x509af.rdnSequence_tree"][
            "x509if.RDNSequence_item_tree"]
        # print(subject_tree)
        if isinstance(subject_tree, dict):
            subject_relative = subject_tree["x509if.RelativeDistinguishedName_item_element"]
        else:
            if subject_tree[-1]["x509if.RelativeDistinguishedName_item_element"].get(
                    "x509sat.DirectoryString_tree") is not None:
                subject_relative = subject_tree[-1]["x509if.RelativeDistinguishedName_item_element"]
            elif list(subject_tree[-1]["x509if.RelativeDistinguishedName_item_element"].keys())[-1] in string_type:
                subject_relative = subject_tree[-1]["x509if.RelativeDistinguishedName_item_element"]
            else:
                subject_relative = subject_tree[0]["x509if.RelativeDistinguishedName_item_element"]

        if subject_relative.get("x509sat.DirectoryString_tree") is not None:
            subject_directory = subject_relative["x509sat.DirectoryString_tree"]
        else:
            subject_directory = subject_relative

        subject = ''
        for st in string_type:
            if st in subject_directory.keys():
                subject = subject_directory[st]
        # print(subject_directory)
        self.__feature["subject"] = subject

        if issuer == subject:
            self.__feature["self_signed_certificate"] = 1
        else:
            self.__feature["self_signed_certificate"] = 0

    def __deal_handshake_tls_certificate(self, handshake_msg: dict):
        """Deal tls certificate
        """
        #         print("certificate")
        if self.__feature["handshake_type"]["Certificate"] > 1:
            return
        string_type = ["x509sat.printableString", "x509sat.printableString", "x509sat.uTF8String",
                       "x509sat.IA5String", "x509sat.teletexString"]

        if handshake_msg["tls.handshake.certificates_length"] == "0":
            return
        c_trees = handshake_msg["tls.handshake.certificates"]["tls.handshake.certificate_tree"]
        if isinstance(c_trees, dict):
            c_num = 1
            c_tree = c_trees
        else:
            c_num = len(c_trees)
            c_tree = c_trees[0]
        valid_tree = c_tree["x509af.signedCertificate_element"]["x509af.validity_element"]
        # print(valid_tree)
        notBefore = valid_tree["x509af.notBefore_tree"]["x509af.utcTime"]
        try:
            notAfter = valid_tree["x509af.notAfter_tree"]["x509af.utcTime"]
        except:
            notAfter = valid_tree["x509af.notAfter_tree"]["x509af.generalizedTime"]
        try:
            notBefore = time.mktime(time.strptime(notBefore, "%y-%m-%d %H:%M:%S (UTC)"))
        except:
            notBefore = time.mktime(time.strptime(notBefore, "%Y-%m-%d %H:%M:%S (UTC)"))
        try:
            notAfter = time.mktime(time.strptime(notAfter, "%y-%m-%d %H:%M:%S (UTC)"))
        except:
            notAfter = time.mktime(time.strptime(notAfter, "%Y-%m-%d %H:%M:%S (UTC)"))
        self.__feature["certificate_validity"] = notAfter - notBefore

        self.__feature["certificate_num"] = c_num
        if c_tree["x509af.signedCertificate_element"]["x509af.issuer_tree"]["x509if.rdnSequence"] == "0":
            return
        # print(c_tree["x509af.signedCertificate_element"]["x509af.issuer_tree"])
        issuer_tree = c_tree["x509af.signedCertificate_element"]["x509af.issuer_tree"]["x509if.rdnSequence_tree"][
            "x509if.RDNSequence_item_tree"]
        if isinstance(issuer_tree, dict):
            issuer_relative = issuer_tree["x509if.RelativeDistinguishedName_item_element"]
        else:
            if issuer_tree[-1]["x509if.RelativeDistinguishedName_item_element"].get(
                    "x509sat.DirectoryString_tree") is not None:
                issuer_relative = issuer_tree[-1]["x509if.RelativeDistinguishedName_item_element"]
            elif list(issuer_tree[-1]["x509if.RelativeDistinguishedName_item_element"].keys())[-1] in string_type:
                issuer_relative = issuer_tree[-1]["x509if.RelativeDistinguishedName_item_element"]
            else:
                issuer_relative = issuer_tree[0]["x509if.RelativeDistinguishedName_item_element"]
        if issuer_relative.get("x509sat.DirectoryString_tree") is not None:
            issuer_directory = issuer_relative["x509sat.DirectoryString_tree"]
        else:
            issuer_directory = issuer_relative
        # print(issuer_tree)
        # print(issuer_relative)
        for st in string_type:
            if st in issuer_directory.keys():
                issuer = issuer_directory[st]
        self.__feature["issuer"] = issuer

        subject_tree = c_tree["x509af.signedCertificate_element"]["x509af.subject_tree"]["x509af.rdnSequence_tree"][
            "x509if.RDNSequence_item_tree"]
        # print(subject_tree)
        if isinstance(subject_tree, dict):
            subject_relative = subject_tree["x509if.RelativeDistinguishedName_item_element"]
        else:
            if subject_tree[-1]["x509if.RelativeDistinguishedName_item_element"].get(
                    "x509sat.DirectoryString_tree") is not None:
                subject_relative = subject_tree[-1]["x509if.RelativeDistinguishedName_item_element"]
            elif list(subject_tree[-1]["x509if.RelativeDistinguishedName_item_element"].keys())[-1] in string_type:
                subject_relative = subject_tree[-1]["x509if.RelativeDistinguishedName_item_element"]
            else:
                subject_relative = subject_tree[0]["x509if.RelativeDistinguishedName_item_element"]

        if subject_relative.get("x509sat.DirectoryString_tree") is not None:
            subject_directory = subject_relative["x509sat.DirectoryString_tree"]
        else:
            subject_directory = subject_relative

        subject = ''
        for st in string_type:
            if st in subject_directory.keys():
                subject = subject_directory[st]
        # print(subject_directory)
        self.__feature["subject"] = subject

        if issuer == subject:
            self.__feature["self_signed_certificate"] = 1
        else:
            self.__feature["self_signed_certificate"] = 0

    def __deal_handshake_ssl_client_key_exchange(self, handshake_msg: dict):
        """Deal ssl client key exchange
        """
        #         print("client key exchange")
        key_length = int(handshake_msg["ssl.handshake.length"]) * 8
        self.__feature["client_key_length"] = key_length

    def __deal_handshake_tls_client_key_exchange(self, handshake_msg: dict):
        """Deal tls client key exchange
        """
        #         print("client key exchange")
        key_length = int(handshake_msg["tls.handshake.length"]) * 8
        self.__feature["client_key_length"] = key_length

    def __add_ip_item(self, pac_ip: dict):
        """Add ip related features
        """
        if pac_ip.get("ip.src") is not None:
            self.__feature.setdefault("ip_src", pac_ip.get("ip.src"))  # 源ip
        elif pac_ip.get("ipv6.src") is not None:
            self.__feature.setdefault("ip_src", pac_ip.get("ipv6.src"))  # 源ip
        if pac_ip.get("ip.dst") is not None:
            self.__feature.setdefault("ip_dst", pac_ip.get("ip.dst"))  # 目的ip
        elif pac_ip.get("ipv6.dst") is not None:
            self.__feature.setdefault("ip_dst", pac_ip.get("ipv6.dst"))  # 目的ip

    def __add_ssl_stream_metadata(self, packet: dict):
        payload = packet["_source"]["layers"]["tcp"].get("tcp.payload")
        if payload is not None:
            payload = payload.split(":")
            length = len(payload)
            if packet["_source"]["layers"]["tcp"]["tcp.srcport"] == "443":
                self.__feature["packet_length"].append(length)
                self.__feature["inbound_count"] += 1
                self.__feature["inbound_bytes"] += length
                if self.__application_flag == 0:
                    self.__raw_data.extend(payload)
            else:
                self.__feature["packet_length"].append(-length)
                self.__feature["outbound_count"] += 1
                self.__feature["outbound_bytes"] += length
                if self.__application_flag == 0:
                    self.__raw_data.extend(payload)

    def __add_tls_stream_metadata(self, packet: dict):
        payload = packet["_source"]["layers"]["tcp"].get("tcp.payload")
        if payload is not None:
            payload = payload.split(":")
            length = len(payload)
            if packet["_source"]["layers"]["tcp"]["tcp.srcport"] == "443":
                self.__feature["packet_length"].append(length)
                self.__feature["inbound_count"] += 1
                self.__feature["inbound_bytes"] += length
                if self.__application_flag == 0:
                    self.__raw_data.extend(payload)
            else:
                self.__feature["packet_length"].append(-length)
                self.__feature["outbound_count"] += 1
                self.__feature["outbound_bytes"] += length
                if self.__application_flag == 0:
                    self.__raw_data.extend(payload)

    def __add_byte_distribution(self):
        for i in itertools.product('0123456789abcdef', repeat=2):
            self.__feature["bytes_distribution"].append(self.__raw_data.count(''.join(i)))

    def __add_time_interval(self, packet: dict):
        self.__time_relative.append(1000 * float(packet["_source"]["layers"]["frame"]["frame.time_relative"]))

    def __add_item(self):
        """Add item in self.__feature.
            Add new item. format:
                self.__feature[key]=value
                self.__feature[key]=function(value)
        """
        self.__application_flag = 0
        self.__raw_data = []
        self.__time_relative = []
        self.__feature["version"] = ''
        self.__feature["packet_length"] = []
        self.__feature["inbound_bytes"] = 0
        self.__feature["outbound_bytes"] = 0
        self.__feature["inbound_count"] = 0
        self.__feature["outbound_count"] = 0
        self.__feature["content_type"] = {
            "ChangeCipherSpec": 0,
            "Alert": 0,
            "Handshake": 0,
            "ApplicationData": 0,
            'heartbeat': 0,
            'tls12_cid': 0,
            'ACK': 0
        }
        self.__feature["extensions"] = []
        self.__feature["handshake_type"] = {
            "HelloRequest": 0,
            "ClientHello": 0,
            "ServerHello": 0,
            "sslSessionTicket": 0,
            "Certificate": 0,
            "ServerKeyExchange": 0,
            "CertificateRequest": 0,
            "ServerHelloDone": 0,
            "CertificateVerify": 0,
            "ClientKeyExchange": 0,
            "Finished": 0,
            "EncryptedHandshakeMessage": 0,
        }
        self.__feature["bytes_distribution"] = []
        self.__feature["packet_interval_time"] = []
        self.__feature["certificate_validity"] = 0

        self.__feature["cs"] = []
        self.__feature["scs"] = []
        self.__feature["certificate_num"] = 0
        self.__feature["issuer"] = ''
        self.__feature["subject"] = ''
        self.__feature["self_signed_certificate"] = 0
        self.__feature["client_key_length"] = 0
        self.__feature['raw_bytes'] = []
        self.__feature['recordLayer_size'] = []

        for pac in self.__stream:
            layers = pac["_source"]["layers"]
            #             print(layers.keys())
            if layers.get("ip") is not None:
                self.__add_ip_item(layers.get("ip"))
            elif layers.get("ipv6") is not None:
                self.__add_ip_item(layers.get("ipv6"))
            if layers.get("tcp") is not None:
                self.__add_tcp_item(layers.get("tcp"))
            # Here alter ssl to ssl
            if layers.get("ssl") is not None:

                if layers.get("ssl").__class__.__name__ == "dict":
                    self.__application_flag = 0
                    self.__add_ssl_item(pac, layers.get("ssl"))
                else:
                    for ssl in layers.get("ssl"):
                        self.__application_flag = 0
                        self.__add_ssl_item(pac, ssl)
                self.__add_ssl_stream_metadata(pac)
                self.__add_time_interval(pac)
            if layers.get("tls") is not None:

                if layers.get("tls").__class__.__name__ == "dict":
                    self.__application_flag = 0
                    self.__add_tls_item(pac, layers.get("tls"))
                else:
                    for tls in layers.get("tls"):
                        self.__application_flag = 0
                        self.__add_tls_item(pac, tls)
                self.__add_tls_stream_metadata(pac)
                self.__add_time_interval(pac)

        self.__add_byte_distribution()
        self.__feature["packet_interval_time"] = self.__time_relative


def stream_reorganization(streams):
    streams_feature = []
    stream_ids = list()
    stream_ro_dict = dict()
    for pac in streams:
        if pac["_source"]["layers"].get("tcp") is None:
            continue
        stream_ids.append(int(pac["_source"]["layers"]["tcp"]["tcp.stream"]))

    stream_ids_set = set(stream_ids)
    #     print(stream_ids_set)
    for stream_id in stream_ids_set:
        stream_ro_dict[stream_id] = []
    for pac in streams:
        if pac["_source"]["layers"].get("tcp") is None:
            continue
        id = int(pac["_source"]["layers"]["tcp"]["tcp.stream"])
        stream_ro_dict[id].append(pac)
    print(stream_ro_dict.keys())
    for key in stream_ro_dict.keys():
        feature = Feature(stream_ro_dict[key])
        streams_feature.append(feature.get_feature())
    return streams_feature

def parse_pcap_json(outdir, pcap, streams):
    pcap = pcap.replace(".pcap", "")
    streams_feature = stream_reorganization(streams)
    for i in range(len(streams_feature)):
        if os.path.exists(outdir + pcap) == False:
            os.makedirs(outdir + pcap)
        if streams_feature[i]['raw_bytes'] != []:
            with open(outdir + pcap + '/' + pcap + '_' + str(i) + '.json', "w") as fp:
                json.dump(streams_feature[i], fp, indent=4)

def setup(args):
    set_random_seed(args['seed'])
    # args['dataset'] = 'ACMRaw' if args['hetero'] else 'ACM'
    args['device'] = 'cuda:0' if torch.cuda.is_available() else 'cpu'
    # args['device'] = 'cpu'
    print('Using the {}'.format(args['device']))
    args['log_dir'] = setup_log_dir(args)
    return args

def setup_log_dir(args, sampling=False):
    """Name and create directory for logging.
    Parameters
    ----------
    args : dict
        Configuration
    Returns
    -------
    log_dir : str
        Path for logging directory
    sampling : bool
        Whether we are using sampling based training
    """
    date_postfix = get_date_postfix()
    log_dir = os.path.join(
        args['log_dir'],
        '{}_{}'.format(args['dataset'][args['dataset'].rfind('/')+1:], date_postfix))

    if sampling:
        log_dir = log_dir + '_sampling'

    mkdir_p(log_dir)
    return log_dir

def get_date_postfix():
    """Get a date based postfix for directory name.
    Returns
    -------
    post_fix : str
    """
    dt = datetime.datetime.now()
    post_fix = '{}_{:02d}-{:02d}-{:02d}'.format(
        dt.date(), dt.hour, dt.minute, dt.second)

    return post_fix

def mkdir_p(path, log=True):
    """Create a directory for the specified path.
    Parameters
    ----------
    path : str
        Path name
    log : bool
        Whether to print result for directory creation
    """
    try:
        os.makedirs(path)
        if log:
            print('Created directory {}'.format(path))
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path) and log:
            print('Directory {} already exists.'.format(path))
        else:
            raise

def set_random_seed(seed=0):
    """Set random seed.
    Parameters
    ----------
    seed : int
        Random seed to use
    """
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)

class EarlyStopping(object):
    def __init__(self, patience=10):
        dt = datetime.datetime.now()
        self.filename = 'early_stop_{}_{:02d}-{:02d}-{:02d}.pth'.format(
            dt.date(), dt.hour, dt.minute, dt.second)
        self.patience = patience
        self.counter = 0
        self.best_acc = None
        self.best_loss = None
        self.early_stop = False

    def step(self, loss, acc, model, args):
        if self.best_loss is None:
            self.best_acc = acc
            self.best_loss = loss
            self.save_checkpoint(model, args)
        elif (loss > self.best_loss) and (acc < self.best_acc):
            self.counter += 1
            print(f'EarlyStopping counter: {self.counter} out of {self.patience}')
            if self.counter >= self.patience:
                self.early_stop = True
        else:
            if (loss <= self.best_loss) and (acc >= self.best_acc):
                self.save_checkpoint(model, args)
            self.best_loss = np.min((loss, self.best_loss))
            self.best_acc = np.max((acc, self.best_acc))
            self.counter = 0
        return self.early_stop

    def save_checkpoint(self, model, args):
        """Saves model when validation loss decreases."""
        torch.save(model.state_dict(), os.path.join(args['log_dir'], self.filename))

    def load_checkpoint(self, model, args):
        """Load the latest checkpoint."""
        # model.load_state_dict(torch.load(os.path.join(args['log_dir'], self.filename)))
        model.load_state_dict(torch.load(os.path.join(args['log_dir'], self.filename)))

def score(logits, labels):
    _, indices = torch.max(logits, dim=1)
    prediction = indices.long().cpu().numpy()
    labels = labels.cpu().numpy()

    accuracy = (prediction == labels).sum() / len(prediction)
    FPR = np.where(prediction==1, np.where(labels==0, True,False),False).sum()/np.where(prediction==1, True,False).sum()
    FNR = np.where(prediction==0, np.where(labels==1, True,False),False).sum()/np.where(prediction==0, True,False).sum()
    micro_f1 = f1_score(labels, prediction, average='micro')
    macro_f1 = f1_score(labels, prediction, average='macro')

    return accuracy, micro_f1, macro_f1, FPR, FNR

def evaluate(model, g, features, labels, mask, loss_func):
    model.eval()
    with torch.no_grad():
        logits = model(g, features)
    loss = loss_func(logits[mask], labels[mask])
    accuracy, micro_f1, macro_f1, FPR, FNR = score(logits[mask], labels[mask])

    return loss, accuracy, micro_f1, macro_f1, FPR, FNR
