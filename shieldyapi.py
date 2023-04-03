import hashlib
import os
import ctypes
import base64

import cryptography.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature


class ShieldyAPI:
    _dllFilePath = "lib/native.dll"
    _dllFilePathUpdate = "lib/native.update"
    _appSalt = ""
    _dll = None
    _initialized = False

    def __SC_FreeMemory(self, buf):
        self._dll.SC_FreeMemory.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
        self._dll.SC_FreeMemory.restype = ctypes.c_bool
        c_buf = ctypes.c_char_p(buf.value)
        result = self._dll.SC_FreeMemory(ctypes.byref(c_buf))
        buf.value = None
        return result

    def __SC_Initialize(self, app_guid, app_version):
        self._dll.SC_Initialize.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self._dll.SC_Initialize.restype = ctypes.c_bool
        return self._dll.SC_Initialize(bytes(app_guid, 'utf-8'), bytes(app_version, 'utf-8'))

    def __SC_GetVariable(self, variable_name):
        self._dll.SC_GetVariable.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.POINTER(ctypes.c_int)]
        self._dll.SC_GetVariable.restype = ctypes.c_bool
        buf = ctypes.c_void_p()
        size = ctypes.c_int()
        success = self._dll.SC_GetVariable(bytes(variable_name, 'utf-8'), ctypes.byref(buf), ctypes.byref(size))
        if success:
            result = ctypes.string_at(buf, size.value)
            if not self.__SC_FreeMemory(buf):
                print("Failed to free memory in SC_GetVariable")
            return result
        else:
            return None

    def __SC_GetUserProperty(self, secret):
        self._dll.SC_GetUserProperty.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p),
                                                 ctypes.POINTER(ctypes.c_int)]
        self._dll.SC_GetUserProperty.restype = ctypes.c_bool
        buf = ctypes.c_void_p()
        size = ctypes.c_int()
        success = self._dll.SC_GetUserProperty(bytes(secret, 'utf-8'), ctypes.byref(buf), ctypes.byref(size))
        if success:
            result = ctypes.string_at(buf, size.value)
            if not self.__SC_FreeMemory(buf):
                print("Failed to free memory in SC_GetUserProperty")
            return result
        else:
            return None

    def __SC_DownloadFile(self, file_name):
        self._dll.SC_DownloadFile.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p),
                                              ctypes.POINTER(ctypes.c_int)]
        self._dll.SC_DownloadFile.restype = ctypes.c_bool
        buf = ctypes.c_void_p()
        size = ctypes.c_int()
        success = self._dll.SC_DownloadFile(bytes(file_name, 'utf-8'), ctypes.byref(buf), ctypes.byref(size))
        if success:
            result = bytes(ctypes.string_at(buf, size.value))
            if not self.__SC_FreeMemory(buf):
                print("Failed to free memory in SC_DownloadFile")
            return result
        else:
            return None

    def __SC_DeobfString(self, obfuscated_base64_string, rounds):
        self._dll.SC_DeobfString.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.POINTER(ctypes.c_int)]
        self._dll.SC_DeobfString.restype = ctypes.c_bool
        buf = ctypes.c_void_p()
        size = ctypes.c_int()
        success = self._dll.SC_DeobfString(bytes(obfuscated_base64_string, 'utf-8'), rounds, ctypes.byref(buf),
                                           ctypes.byref(size))
        if success:
            result = ctypes.string_at(buf, size.value)
            if not self.__SC_FreeMemory(buf):
                print("Failed to free memory in SC_DeobfString")
            return result
        else:
            return None

    def __SC_Log(self, text):
        self._dll.SC_Log.argtypes = [ctypes.c_char_p]
        self._dll.SC_Log.restype = ctypes.c_bool
        return self._dll.SC_Log(bytes(text, 'utf-8'))

    def __SC_LoginLicenseKey(self, license_key):
        self._dll.SC_LoginLicenseKey.argtypes = [ctypes.c_char_p]
        self._dll.SC_LoginLicenseKey.restype = ctypes.c_bool
        return self._dll.SC_LoginLicenseKey(bytes(license_key, 'utf-8'))

    def __SC_LoginUserPass(self, username, password):
        self._dll.SC_LoginUserPass.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self._dll.SC_LoginUserPass.restype = ctypes.c_bool
        return self._dll.SC_LoginUserPass(bytes(username, 'utf-8'), bytes(password, 'utf-8'))

    def __SC_GetLastError(self):
        self._dll.SC_GetLastError.argtypes = []
        self._dll.SC_GetLastError.restype = ctypes.c_int
        return self._dll.SC_GetLastError()

    def xor_to_str(self, val: bytes, key: str) -> str:
        result = bytearray()
        for i in range(len(val)):
            # wartość bajtu dla danego indeksu w kluczu
            key_byte = ord(key[i % len(key)])
            # wykonanie operacji XOR
            xor_byte = val[i] ^ key_byte
            # dodanie wynikowego bajtu do tablicy wynikowej
            result.append(xor_byte)
        # konwersja tablicy wynikowej na string
        return result.decode()

    def xor_to_bytes(self, val: bytes, key: str) -> bytes:
        result = bytearray()
        for i in range(len(val)):
            # wartość bajtu dla danego indeksu w kluczu
            key_byte = ord(key[i % len(key)])
            # wykonanie operacji XOR
            xor_byte = val[i] ^ key_byte
            # dodanie wynikowego bajtu do tablicy wynikowej
            result.append(xor_byte)
        # konwersja tablicy wynikowej na bytes
        return bytes(result)

    def __perform_update(self):
        if os.path.exists(self._dllFilePathUpdate):
            os.remove(self._dllFilePath)
            os.rename(self._dllFilePathUpdate, self._dllFilePath)

    @staticmethod
    def __get_rsa_public_key():
        public_key_der = base64.b64decode(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgb7m2HrJ7M6aiC9VzIOizWZ/XlB0eXSC56W6/ql5pUUjd0rEst6NgN1WuNlgjIjgqaRCIT2cJsX8yekjNSxwCogGcGTKm50i9ueh8SdwXtqIRMe4MHBuGbhimLlzDXhFGCfl8HIl2KpnyzBuIDqmuwNqJFdADXprHLiv066M6P9WKp8S4oIb0Y0s8k7aif7B/4bxHNe6ukI2uvVmAM0hEfq5g1pm2jvvAU9xytv2yWuYQ6u+0SzWkRAlP0MDKV9WsE/AKo9wID+Iod0u9U8tEj6HkiUhQ0V/q0BKjSWGOEUyujVoacVgswLOQU6nVdnntJEoZ9Jf8mOnbyLc6xTDTwIDAQAB")
        return load_der_public_key(public_key_der)

    def __verify_native_binary(self):
        self.__perform_update()

        if not os.path.exists(self._dllFilePath):
            return False

        with open(self._dllFilePath, "rb") as f:
            dll = f.read()

        if len(dll) < 32:
            print("Failed to read DLL on path " + self._dllFilePath)
            return False

        # read last 256 bytes
        rsa_signature = dll[-256:]

        # read all bytes except last 256
        dll_without_signature = dll[:-256]

        # do md5 of dll without signature
        dll_hash = hashlib.md5(dll_without_signature).digest()

        print("DLL hash size: " + str(len(dll_hash)))

        rsa_pub_key = self.__get_rsa_public_key()

        try:
            if rsa_pub_key is None:
                print("Failed to get RSA public key")
                return False
            rsa_pub_key.verify(
                signature=rsa_signature,
                data=dll_hash,
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256()
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            print("Verification failed")
            return False

    # string appGuid, string version, string appSalt
    def init(self, app_guid, version, app_salt):
        self._appSalt = app_salt

        if not self.__verify_native_binary():
            print("Verification failed")
            return False

        self._dll = ctypes.WinDLL(self._dllFilePath)
        self._initialized = self.initialize(app_guid, version)
        print("Initialized: " + str(self._initialized))
        return self._initialized

    def initialize(self, app_guid, version):
        return self.__SC_Initialize(app_guid, version)

    def login(self, username, password):
        if not self._initialized:
            return False

        return self.__SC_LoginUserPass(username, password)

    def login_license_key(self, license_key):
        if not self._initialized:
            return False

        return self.__SC_LoginLicenseKey(license_key)

    def get_last_error(self):
        return self.__SC_GetLastError()

    def get_variable(self, name):
        if not self._initialized:
            return None

        xored = self.__SC_GetVariable(name)
        if xored is None:
            return None

        return self.xor_to_str(xored, self._appSalt)

    def download_file(self, file_name):
        if not self._initialized:
            return None

        xored = self.__SC_DownloadFile(file_name)
        if xored is None:
            return None

        return self.xor_to_bytes(xored, self._appSalt)

    def get_user_property(self, name):
        if not self._initialized:
            return None

        xored = self.__SC_GetUserProperty(name)
        if xored is None:
            return None

        return self.xor_to_str(xored, self._appSalt)

    def deobfuscate_string(self, string_base64, rounds):
        if not self._initialized:
            return None

        xored = self.__SC_DeobfString(string_base64, rounds)
        if xored is None:
            return None

        return self.xor_to_str(xored, self._appSalt)