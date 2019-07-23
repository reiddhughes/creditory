#!/usr/bin/env python2.7

import base64
import binascii
import collections
import cryptography.hazmat.primitives.ciphers.aead as aead
import datetime
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib
import hmac
import json
import os
import requests
import socket


import credible.backend as credible_backend


_BITS_PER_HEX_CHARACTER = 16
_BITS_PER_BYTE = 8


class Undefined(object):
    pass


class OnePasswordException(Exception):
    pass


class OnePasswordBackendException(
    OnePasswordException,
    credible_backend.BackendError
):

    pass


class ByteString(str):
    _HEX_FORMAT_SPEC = 'x'
    _PADDING = "===="

    @classmethod
    def from_integer(cls, integer):
        as_hex = format(integer, cls._HEX_FORMAT_SPEC)

        try:
            unhexlified = binascii.unhexlify(as_hex)
        except TypeError:
            unhexlified = binascii.unhexlify("0" + as_hex)

        byte_string = cls(unhexlified)

        return byte_string

    @classmethod
    def from_hexlified_string(cls, hexlified_string):
        try:
            unhexlified = binascii.unhexlify(hexlified_string)
        except TypeError:
            unhexlified = binascii.unhexlify("0" + hexlified_string)
        byte_string = cls(unhexlified)

        return byte_string

    @classmethod
    def from_unpadded_urlsafe_base64_encoded_string(cls, encoded_string):
        str_encoded_string = str(encoded_string)
        padded = str_encoded_string + cls._PADDING
        decoded = base64.urlsafe_b64decode(padded)
        byte_string = cls(decoded)

        return byte_string

    def hexlify(self):
        as_hex = binascii.hexlify(self)

        return as_hex

    def to_integer(self):
        as_hex = self.hexlify()
        as_integer = int(as_hex, _BITS_PER_HEX_CHARACTER)

        return as_integer

    def pad(self):
        padded = self + self._PADDING

        return padded

    def pad_and_urlsafe_base64_decode(self):
        padded = self.pad()
        decoded = base64.urlsafe_b64decode(padded)

        return decoded

    def urlsafe_base64_encode(self):
        encoded = base64.urlsafe_b64encode(self)

        return encoded

    def urlsafe_base64_encode_and_unpad(self):
        encoded = base64.urlsafe_b64encode(self)
        unpadded = encoded.replace("=", "")

        return unpadded

    def base32_encode_and_unpad_and_lower(self):
        encoded = base64.b32encode(self)
        unpadded = encoded.replace("=", "")
        lowered = unpadded.lower()

        return lowered

    def __xor__(self, other):
        resulting_characters = []

        for self_char, other_char in zip(self, other):
            self_ord = ord(self_char)
            other_ord = ord(other_char)
            xored_int = self_ord ^ other_ord
            resulting_chr = chr(xored_int)

            resulting_characters.append(resulting_chr)

        xored_result = "".join(resulting_characters)
        byte_string = self.__class__(xored_result)

        return byte_string

    def __int__(self):
        as_int = self.to_integer()

        return as_int

    def __getslice__(self, start, stop):
        super_result = super(ByteString, self).__getslice__(start, stop)
        byte_string = self.__class__(super_result)

        return byte_string


class Unlockable(object):

    def unlock(self, keychain):
        raise NotImplementedError

    @property
    def encrypted_by(self):
        raise NotImplementedError


class UnlockableKey(Unlockable):

    @property
    def uuid(self):
        raise NotImplementedError

    def unlock(self, keychain):
        raise NotImplementedError

    @property
    def encrypted_by(self):
        raise NotImplementedError


class UnlockableAesGcmKey(UnlockableKey):

    @property
    def uuid(self):
        raise NotImplementedError

    def unlock(self, keychain):
        raise NotImplementedError

    @property
    def encrypted_by(self):
        raise NotImplementedError

    def decrypt(self, initialization_vector, data):
        raise NotImplementedError


class LockedAesGcmKey(UnlockableKey):

    def __init__(
            self,
            locked_data,
            encrypted_by,
            uuid
    ):

        self._locked_data = locked_data
        self._encrypted_by = encrypted_by
        self._uuid = uuid
        self._internal_key = Undefined

    @property
    def uuid(self):
        key_uuid = self._uuid

        return key_uuid

    @property
    def encrypted_by(self):
        other_uuid = self._encrypted_by

        return other_uuid

    def decrypt(self, initialization_vector, data):
        plaintext = self._internal_key.decrypt(
            initialization_vector,
            data,
            None
        )

        return plaintext

    def unlock(self, keychain):
        if self._internal_key is Undefined:
            self._unlock_and_save_internal_key(keychain=keychain)

        else:
            pass

    def _unlock_and_save_internal_key(self, keychain):
        plaintext = keychain.decrypt_rsa_value(
            uuid=self.encrypted_by,
            ciphertext=self._locked_data
        )

        key_data = json.loads(plaintext)
        key = ByteString.from_unpadded_urlsafe_base64_encoded_string(key_data['k'])
        internal_key = aead.AESGCM(key=key)

        self._internal_key = internal_key

    def unlock_and_decrypt(self, keychain, initialization_vector, data):
        self.unlock(keychain=keychain)
        plaintext = self.decrypt(
            initialization_vector=initialization_vector,
            data=data
        )

        return plaintext


class UnlockedAesGcmKey(UnlockableKey):

    def __init__(
            self,
            raw_key,
            uuid
    ):

        self._uuid = uuid
        self._internal_key = aead.AESGCM(key=raw_key)

    @property
    def uuid(self):
        key_uuid = self._uuid

        return key_uuid

    @property
    def encrypted_by(self):
        raise NotImplementedError

    def decrypt(self, initialization_vector, data):
        plaintext = self._internal_key.decrypt(
            initialization_vector,
            data,
            None
        )

        return plaintext

    def unlock(self, keychain):
        pass

    def unlock_and_decrypt(self, keychain, initialization_vector, data):
        self.unlock(keychain=keychain)

        plaintext = self.decrypt(
            initialization_vector=initialization_vector,
            data=data
        )

        return plaintext

    def encrypt(self, initialization_vector, data):
        ciphertext = self._internal_key.encrypt(
            initialization_vector,
            data,
            None
        )

        return ciphertext


class LockedRsaPrivateKey(UnlockableKey):
    _MODULUS_KEY = 'n'
    _PUBLIC_EXPONENT_KEY = 'e'
    _PRIVATE_EXPONENT_KEY = 'd'
    _FIRST_PRIME_FACTOR_KEY = 'p'
    _SECOND_PRIME_FACTOR_KEY = 'q'
    _CRT_COEFFICIENT_KEY = 'u'
    _CRT_COEFFICIENT_JWK_KEY = 'qi'

    def __init__(self, initialization_vector, locked_data, encrypted_by, uuid):
        self._initialization_vector = initialization_vector
        self._locked_data = locked_data
        self._encrypted_by = encrypted_by
        self._uuid = uuid
        self._internal_key = Undefined

    @property
    def uuid(self):
        key_uuid = self._uuid

        return key_uuid

    @property
    def encrypted_by(self):
        return self._encrypted_by

    @staticmethod
    def _type_raw_parameters(raw_parameters):
        typed_parameters = (
            ByteString.from_unpadded_urlsafe_base64_encoded_string(
                single_parameter
            ).to_integer()
            for single_parameter
            in raw_parameters
        )

        return typed_parameters

    def _extract_rsa_parameters(self, unlocked_data):
        raw_parameters = (
            unlocked_data[self._MODULUS_KEY],
            unlocked_data[self._PUBLIC_EXPONENT_KEY],
            unlocked_data[self._PRIVATE_EXPONENT_KEY],
            unlocked_data[self._FIRST_PRIME_FACTOR_KEY],
            unlocked_data[self._SECOND_PRIME_FACTOR_KEY]
        )

        typed_parameters = self._type_raw_parameters(
            raw_parameters=raw_parameters
        )

        return typed_parameters

    def _create_internal_key(self, plaintext):
        unlocked_data = json.loads(plaintext)
        extracted_parameters = self._extract_rsa_parameters(
            unlocked_data=unlocked_data
        )

        # noinspection PyArgumentList
        rsa_key = RSA.construct(extracted_parameters)
        rsa_cipher = PKCS1_OAEP.new(key=rsa_key)

        return rsa_cipher

    def unlock(self, keychain):
        if self._internal_key is Undefined:
            plaintext = keychain.decrypt_aes_gcm_value(
                uuid=self.encrypted_by,
                initialization_vector=self._initialization_vector,
                data=self._locked_data
            )

            internal_key = self._create_internal_key(plaintext=plaintext)
            self._internal_key = internal_key

        else:
            pass

    def decrypt(self, ciphertext):
        plaintext = self._internal_key.decrypt(ciphertext)

        return plaintext

    def unlock_and_decrypt(self, keychain, ciphertext):
        self.unlock(keychain=keychain)
        plaintext = self.decrypt(ciphertext=ciphertext)

        return plaintext


def _hash_to_byte_string(value):
    hashed_value = hashlib.sha256(value)
    digest = hashed_value.digest()
    byte_string = ByteString(digest)

    return byte_string


class RandomGenerator(credible_backend.ValueSource):

    def __init__(
            self,
            entropy_source=os.urandom,
            hostname_strategy=socket.gethostname
    ):

        self._entropy_source = entropy_source
        self._hostname_strategy = hostname_strategy

    def create_client_secret_value(self):
        bytes_to_generate = 256 / _BITS_PER_BYTE
        generated_bytes = self._entropy_source(bytes_to_generate)
        byte_string = ByteString(generated_bytes)

        return byte_string

    def create_initialization_vector(self):
        generated_bytes = self._entropy_source(12)
        byte_string = ByteString(generated_bytes)

        return byte_string

    def create_device_uuid(self):
        bytes_for_uuid = 128 / _BITS_PER_BYTE
        hostname = self._hostname_strategy()
        filled_hostname = hostname.zfill(bytes_for_uuid)
        limited_hostname = filled_hostname[:bytes_for_uuid]
        encoded = base64.b32encode(limited_hostname)
        unpadded = encoded.replace("=", "")
        lowered = unpadded.lower()

        return lowered

    def create_uuid(self):
        bytes_for_uuid = 128 / _BITS_PER_BYTE
        generated_bytes = self._entropy_source(bytes_for_uuid)
        encoded = base64.b32encode(generated_bytes)
        unpadded = encoded.replace("=", "")
        lowered = unpadded.lower()

        return lowered

    def __getitem__(self, item):
        item_to_method = {
            "client_secret_value": self.create_client_secret_value,
            "initialization_vector": self.create_initialization_vector,
            "device_uuid": self.create_device_uuid
        }

        lower_item = str(item).lower()
        method = item_to_method[lower_item]
        value = method()

        return value

    def get(self, k, default=None):
        try:
            value = self[k]
        except KeyError:
            value = default

        return value

    def __setitem__(self, key, value):
        raise OnePasswordBackendException


class TwoSecretKey(object):

    def __init__(
            self,
            email,
            client_secret_value,
            master_password,
            secret_key,
            secret_key_uuid,
            secret_key_format
    ):

        self._email = email
        self._client_secret_value = client_secret_value
        self._master_password = master_password
        self._secret_key = secret_key
        self._secret_key_uuid = secret_key_uuid
        self._secret_key_format = secret_key_format

    @property
    def email(self):
        address = self._email

        return address

    @property
    def secret_key_uuid(self):
        uuid = self._secret_key_uuid

        return uuid

    @property
    def secret_key_format(self):
        key_format = self._secret_key_format

        return key_format

    @property
    def client_secret_value(self):
        secret_value = self._client_secret_value

        return secret_value

    def derive_client_public_value(self, public_root_modulo, public_prime):
        integer_public_root_modulo = int(public_root_modulo)
        integer_public_prime = int(public_prime)
        integer_client_secret_value = int(self._client_secret_value)

        public_value = pow(
            integer_public_root_modulo,
            integer_client_secret_value,
            integer_public_prime
        )

        byte_string = ByteString.from_integer(public_value)

        return byte_string

    def create_client_verify_hash(self, session_id):
        """

        :param ByteString session_id:
        :return:
        """

        account_key_hash = _hash_to_byte_string(self._secret_key_uuid)
        session_id_hash = _hash_to_byte_string(session_id)

        combined_hashes = account_key_hash + session_id_hash
        hash_of_combined_hashes = _hash_to_byte_string(combined_hashes)
        encoded_hash_of_hashes = (
            hash_of_combined_hashes.urlsafe_base64_encode_and_unpad()
        )

        return encoded_hash_of_hashes

    @property
    def _secret_key_hmac(self):
        secret_key_hmac = self._derive_key_using_hmac(
            first_string=self._secret_key,
            second_string=self._secret_key_format,
            third_string=self._secret_key_uuid
        )

        return secret_key_hmac

    def derive_two_secret_key(self, salt_information):
        salt_email_hmac = self._derive_key_using_hmac(
            first_string=salt_information.salt,
            second_string=salt_information.method,
            third_string=self._email
        )

        password_based_key = hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=self._master_password,
            salt=salt_email_hmac,
            iterations=salt_information.iterations
        )

        password_based_key_byte_string = ByteString(password_based_key)
        xored_result = password_based_key_byte_string ^ self._secret_key_hmac

        return xored_result

    @staticmethod
    def _derive_key_using_hmac(first_string, second_string, third_string):
        first_hmac = hmac.new(
            third_string,
            msg=first_string,
            digestmod=hashlib.sha256
        )

        second_hmac = hmac.new(
            first_hmac.digest(),
            msg=second_string + chr(1),
            digestmod=hashlib.sha256
        )

        digested_key = second_hmac.digest()
        byte_string = ByteString(digested_key)

        return byte_string


class KeyExchange(object):

    def __init__(self, two_secret_key, public_root_modulo, public_prime):
        """

        :param TwoSecretKey two_secret_key:
        :param int public_root_modulo:
        :param int public_prime:
        """

        self._two_secret_key = two_secret_key
        self._public_root_modulo = public_root_modulo
        self._public_prime = public_prime

    @property
    def client_public_value(self):
        public_value = self._two_secret_key.derive_client_public_value(
            public_root_modulo=self._public_root_modulo,
            public_prime=self._public_prime
        )

        return public_value

    def derive_raw_transport_key(
            self,
            session_id,
            server_public_value,
            secure_remote_password_key
    ):

        hexlified_client_public_value = self.client_public_value.hexlify()
        hexlified_server_public_value = server_public_value.hexlify()
        concatenated_hexlified_public_values = (
                hexlified_client_public_value
                + hexlified_server_public_value
        )

        hashed_concatenated_public_values = _hash_to_byte_string(
            concatenated_hexlified_public_values
        )

        public_values_as_integer = (
            hashed_concatenated_public_values.to_integer()
        )

        secure_remote_password_key_as_integer = (
            secure_remote_password_key.to_integer()
        )

        public_values_crossed_with_remote_key = (
                public_values_as_integer
                * secure_remote_password_key_as_integer
        )

        crossed_values_added_to_secret = (
                self._two_secret_key.client_secret_value.to_integer()
                + public_values_crossed_with_remote_key
        )

        server_public_value_as_integer = server_public_value.to_integer()

        public_secure_remote_password_value = pow(
            self._public_root_modulo,
            secure_remote_password_key_as_integer,
            self._public_prime
        )

        session_id_as_integer = session_id.to_integer()
        public_remote_value_crossed_with_session_id = (
                public_secure_remote_password_value
                * session_id_as_integer
        )

        server_public_value_minus_public_remote_cross = (
                server_public_value_as_integer
                - public_remote_value_crossed_with_session_id
        )

        derived_key_as_integer = pow(
            server_public_value_minus_public_remote_cross,
            crossed_values_added_to_secret,
            self._public_prime
        )

        derive_key_byte_string = ByteString.from_integer(derived_key_as_integer)
        hexlified_derived_key = derive_key_byte_string.hexlify()
        hashed_derived_key = _hash_to_byte_string(hexlified_derived_key)

        return hashed_derived_key


class Keychain(object):
    _RSA_ALGORITHM = 'RSA-OAEP'
    _AES_GCM_ALGORITHM = 'A256GCM'

    def __init__(self):
        self._rsa_keys = {}
        self._aes_gcm_keys = {}

    def register_rsa_key(self, key):
        self._rsa_keys[key.uuid] = key

    def register_aes_gcm_key(self, key):
        self._aes_gcm_keys[key.uuid] = key

    def retrieve_rsa_key(self, uuid):
        key = self._rsa_keys[uuid]

        return key

    def retrieve_aes_gcm_key(self, uuid):
        key = self._aes_gcm_keys[uuid]

        return key

    def decrypt_rsa_value(self, uuid, ciphertext):
        key = self.retrieve_rsa_key(uuid=uuid)
        plaintext = key.unlock_and_decrypt(keychain=self, ciphertext=ciphertext)
        byte_string = ByteString(plaintext)

        return byte_string

    def decrypt_aes_gcm_value(self, uuid, initialization_vector, data):
        key = self.retrieve_aes_gcm_key(uuid=uuid)
        plaintext = key.unlock_and_decrypt(
            keychain=self,
            initialization_vector=initialization_vector,
            data=data
        )

        byte_string = ByteString(plaintext)

        return byte_string

    def add_locked_symmetric_key(self, uuid, data, encrypted_by):
        symmetric_key = LockedAesGcmKey(
            locked_data=data,
            encrypted_by=encrypted_by,
            uuid=uuid
        )

        self.register_aes_gcm_key(key=symmetric_key)

    def add_locked_private_key(self, uuid, initialization_vector, data, encrypted_by):
        private_key = LockedRsaPrivateKey(
            initialization_vector=initialization_vector,
            locked_data=data,
            encrypted_by=encrypted_by,
            uuid=uuid
        )

        self.register_rsa_key(key=private_key)

    def encrypt_with_aes_gcm(self, uuid, initialization_vector, data):
        key = self.retrieve_aes_gcm_key(uuid=uuid)
        ciphertext = key.encrypt(
            initialization_vector=initialization_vector,
            data=data
        )

        byte_string = ByteString(ciphertext)

        return byte_string


class OnePasswordDeviceClient(object):
    _BASE_URL = 'https://my.1password.com'
    _V1_API_FRAGMENT = 'api/v1'
    _V2_AUTH_API_FRAGMENT = 'api/v2/auth'
    _SESSION_ID_KEY = 'sessionID'
    _STATUS_KEY = 'status'
    _DEVICE_NOT_REGISTERED_STATUS = "device-not-registered"
    _USER_AUTH_KEY = 'userAuth'
    _SALT_KEY = 'salt'
    _CLIENT_VERSION = 577
    PUBLIC_PRIME = 1044388881413152506679602719846529545831269060992135009022588756444338172022322690710444046669809783930111585737890362691860127079270495454517218673016928427459146001866885779762982229321192368303346235204368051010309155674155697460347176946394076535157284994895284821633700921811716738972451834979455897010306333468590751358365138782250372269117968985194322444535687415522007151638638141456178420621277822674995027990278673458629544391736919766299005511505446177668154446234882665961680796576903199116089347634947187778906528008004756692571666922964122566174582776707332452371001272163776841229318324903125740713574141005124561965913888899753461735347970011693256316751660678950830027510255804846105583465055446615090444309583050775808509297040039680057435342253926566240898195863631588888936364129920059308455669454034010391478238784189888594672336242763795138176353222845524644040094258962433613354036104643881925238489224010194193088911666165584229424668165441688927790460608264864204237717002054744337988941974661214699689706521543006262604535890998125752275942608772174376107314217749233048217904944409836238235772306749874396760463376480215133461333478395682746608242585133953883882226786118030184028136755970045385534758453247
    PUBLIC_ROOT_MODULO = 5

    def __init__(self, device_uuid, request_factory=requests):
        self._device_uuid = device_uuid
        self._request_factory = request_factory

    @property
    def device_uuid(self):
        uuid = self._device_uuid

        return uuid

    @staticmethod
    def _create_header_mac(
            method,
            url,
            version,
            session_id,
            request_id,
            session_hmac
    ):

        hmac_inner_message = "|".join(
            [session_id, method, url, version, str(request_id)]
        )

        mac_header_piece = hmac.new(
            key=session_hmac,
            msg=hmac_inner_message,
            digestmod=hashlib.sha256
        ).digest()

        byte_string = ByteString(mac_header_piece)
        mac_part = byte_string[0:12]
        encoded_mac_message_part = mac_part.urlsafe_base64_encode_and_unpad()

        assembled_header = "|".join(
            ["v1", str(request_id), encoded_mac_message_part]
        )

        return assembled_header

    def _create_base_headers(self):
        headers = {
            'accept-encoding': 'gzip, deflate, br',
            'x-agilebits-client': '1Password for Web/577',
            'accept-language': 'en-US',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
            'accept': 'application/json; q=1.0, text/*; q=0.8, */*; q=0.1',
            'cache-control': 'no-cache',
            'authority': 'my.1password.com',
            'x-requested-with': 'XMLHttpRequest',
        }

        return headers

    def _create_session_headers(self, session_id):
        headers = {
            'origin': 'https://my.1password.com',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
            'x-agilebits-session-id': session_id,
            'content-type': 'application/json',
            'accept': 'application/json; q=1.0, text/*; q=0.8, */*; q=0.1',
            'cache-control': 'no-cache',
            'authority': 'my.1password.com',
            'x-requested-with': 'XMLHttpRequest',
        }

        return headers

    def _create_session_and_mac_headers(self, session_id, header_mac):
        headers = self._create_session_headers(session_id=session_id)
        headers['x-agilebits-mac'] = header_mac

        return headers

    def register_device(self, session_id):
        headers = self._create_session_headers(session_id=session_id)
        register_data_object = {
            "uuid": self._device_uuid,
            "clientName":"1Password for Web",
            "clientVersion":"577",
            "name":"Chrome",
            "model":"70.0.3538.77",
            "osName":"MacOSX",
            "osVersion":"10.13.6",
            "userAgent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
        }

        register_data = json.dumps(register_data_object)

        response = self._request_factory.post(
            'https://my.1password.com/api/v1/device',
            headers=headers,
            data=register_data
        )

        return response

    def create_session(
            self,
            email,
            secret_key_format,
            secret_key_uuid
    ):

        headers = self._create_base_headers()

        url = "/".join(
            [
                self._BASE_URL,
                self._V2_AUTH_API_FRAGMENT,
                email,
                secret_key_format,
                secret_key_uuid,
                self._device_uuid
            ]
        )

        initial_response = self._request_factory.get(url, headers=headers)
        initial_response_json = initial_response.json()

        return initial_response_json

    def exchange_public_values(self, session_id, client_public_value):
        headers = self._create_session_headers(session_id=session_id)

        auth_data_object = {
            'sessionID': str(session_id),
            'userA': str(client_public_value)
        }

        auth_data = json.dumps(auth_data_object)
        response = self._request_factory.post(
            'https://my.1password.com/api/v1/auth',
            headers=headers,
            data=auth_data
        )

        response_json = response.json()

        return response_json

    def verify(self, session_id, session_hmac, request_id, initialization_vector, data):
        header_mac = self._create_header_mac(
            method='POST',
            url="my.1password.com/api/v2/auth/verify?",
            version='v1',
            session_id=session_id,
            request_id=request_id,
            session_hmac=session_hmac
        )

        # headers = self._create_session_and_mac_headers(
        #     session_id=session_id,
        #     header_mac=header_mac
        # )

        headers = {
            'origin': 'https://my.1password.com',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
            'x-agilebits-session-id': session_id,
            'content-type': 'application/json',
            'accept': 'application/json; q=1.0, text/*; q=0.8, */*; q=0.1',
            'cache-control': 'no-cache',
            'x-agilebits-mac': header_mac,
            'authority': 'my.1password.com',
            'x-requested-with': 'XMLHttpRequest',
        }

        verify_data_object = {
            'kid': session_id,
            "enc": "A256GCM",
            "cty": "b5+jwk+json",
            "iv": initialization_vector,
            "data":data
        }

        verify_data = json.dumps(verify_data_object)

        response = self._request_factory.post(
            'https://my.1password.com/api/v2/auth/verify',
            headers=headers,
            data=verify_data
        )

        response_json = response.json()

        return response_json

    def retrieve_keysets(self, session_id, session_hmac, request_id):
        header_mac = self._create_header_mac(
            method='GET',
            url="my.1password.com/api/v1/account/keysets?",
            version='v1',
            session_id=session_id,
            request_id=request_id,
            session_hmac=session_hmac
        )

        headers = self._create_session_and_mac_headers(
            session_id=session_id,
            header_mac=header_mac
        )

        response = self._request_factory.get(
            'https://my.1password.com/api/v1/account/keysets',
            headers=headers
        )

        keyset_response_json = response.json()

        return keyset_response_json

    def retrieve_vaults(self, session_id, session_hmac, request_id):
        header_mac = self._create_header_mac(
            method='GET',
            url="my.1password.com/api/v1/vaults?",
            version='v1',
            session_id=session_id,
            request_id=request_id,
            session_hmac=session_hmac
        )

        headers = self._create_session_and_mac_headers(
            session_id=session_id,
            header_mac=header_mac
        )

        headers['cookie'] = '_ab=a'
        response = self._request_factory.get(
            'https://my.1password.com/api/v1/vaults',
            headers=headers
        )

        vaults_response_json = response.json()

        return vaults_response_json

    def retrieve_vault_overview(self, session_id, session_hmac, vault_uuid, request_id):
        vault_overview_url = 'my.1password.com/api/v1/vault/{vault_uuid}/items/overviews?'.format(vault_uuid=vault_uuid)

        header_mac = self._create_header_mac(
            method='GET',
            url=vault_overview_url,
            version='v1',
            session_id=session_id,
            request_id=request_id,
            session_hmac=session_hmac
        )

        headers = self._create_session_and_mac_headers(
            session_id=session_id,
            header_mac=header_mac
        )

        url = 'https://my.1password.com/api/v1/vault/{vault_uuid}/items/overviews'.format(vault_uuid=vault_uuid)
        response = self._request_factory.get(url, headers=headers)

        response_json = response.json()

        return response_json

    def retrieve_item(self, session_id, session_hmac, vault_uuid, item_uuid, request_id):
        item_url = 'my.1password.com/api/v1/vault/{vault_uuid}/item/{item_uuid}?'.format(
            vault_uuid=vault_uuid,
            item_uuid=item_uuid
        )

        header_mac = self._create_header_mac(
            method='GET',
            url=item_url,
            version='v1',
            session_id=session_id,
            request_id=request_id,
            session_hmac=session_hmac
        )

        headers = self._create_session_and_mac_headers(
            session_id=session_id,
            header_mac=header_mac
        )

        url = 'https://my.1password.com/api/v1/vault/{vault_uuid}/item/{item_uuid}'.format(
            vault_uuid=vault_uuid,
            item_uuid=item_uuid
        )

        response = self._request_factory.get(url, headers=headers)
        response_json = response.json()

        return response_json

    def add_item(self, session_id, session_hmac, vault_uuid, content_version, data, request_id, initialization_vector):
        item_url = 'my.1password.com/api/v2/vault/{vault_uuid}/{content_version}/items?'.format(vault_uuid=vault_uuid, content_version=content_version)
        header_mac = self._create_header_mac(method='PATCH', url=item_url, version='v1', session_id=session_id, request_id=request_id, session_hmac=session_hmac)
        headers = self._create_session_and_mac_headers(
            session_id=session_id,
            header_mac=header_mac
        )

        url = 'https://my.1password.com/api/v2/vault/{vault_uuid}/{content_version}/items'.format(vault_uuid=vault_uuid, content_version=content_version)
        item_data_object = {
            'kid': session_id,
            "enc": "A256GCM",
            "cty": "b5+jwk+json",
            "iv": initialization_vector,
            "data":data
        }

        item_data = json.dumps(item_data_object)

        response = self._request_factory.patch(url, headers=headers, data=item_data)
        response_json = response.json()

        return response_json


class SaltInformation(object):

    def __init__(self, salt, method, iterations):
        """

        :param ByteString salt:
        :param ByteString method:
        :param int iterations:
        """
        self.salt = salt
        self.method = method
        self.iterations = iterations


class Vault(credible_backend.ValueSource):

    def __init__(self, name, session):
        """

        :param str name:
        :param Session session:
        """

        self._name = name
        self._session = session

    def __getitem__(self, item):
        item_contents = self._session.retrieve_item_contents_by_name(
            vault_name=self._name,
            item_name=item
        )

        return item_contents

    def get(self, k, default=None):
        value = self[k]

        return value

    def __setitem__(self, key, value):
        raise NotImplementedError


class Session(object):

    def __init__(self, keychain, client, two_secret_key, key_exchange, random_generator):
        """

        :param Keychain keychain:
        :param OnePasswordDeviceClient client:
        :param TwoSecretKey two_secret_key:
        :param KeyExchange key_exchange:
        :param RandomGenerator random_generator:
        :param OnePasswordCredentials credentials:
        """

        initial_session_response = client.create_session(
            email=two_secret_key.email,
            secret_key_format=two_secret_key.secret_key_format,
            secret_key_uuid=two_secret_key.secret_key_uuid
        )

        initial_status = initial_session_response['status']
        session_id_from_response = initial_session_response['sessionID']
        session_id = ByteString(session_id_from_response)

        if initial_status == "device-not-registered":
            client.register_device(session_id=session_id)
            registered_auth_response = client.create_session(
                email=two_secret_key.email,
                secret_key_format=two_secret_key.secret_key_format,
                secret_key_uuid=two_secret_key.secret_key_uuid
            )

        else:

            registered_auth_response = initial_session_response

        user_auth_data = registered_auth_response['userAuth']
        salt = ByteString.from_unpadded_urlsafe_base64_encoded_string(user_auth_data['salt'])
        method = ByteString(user_auth_data['method'])
        iterations = int(user_auth_data['iterations'])
        salt_information = SaltInformation(
            salt=salt,
            method=method,
            iterations=iterations
        )

        public_values_response = client.exchange_public_values(
            session_id=session_id,
            client_public_value=key_exchange.client_public_value.hexlify()
        )

        server_public_value = ByteString.from_hexlified_string(
            public_values_response['userB']
        )

        secure_remote_password_key = two_secret_key.derive_two_secret_key(
            salt_information=salt_information
        )

        raw_transport_key = key_exchange.derive_raw_transport_key(
            session_id=session_id,
            server_public_value=server_public_value,
            secure_remote_password_key=secure_remote_password_key
        )

        transport_key = UnlockedAesGcmKey(
            raw_key=raw_transport_key,
            uuid=session_id
        )

        keychain.register_aes_gcm_key(transport_key)

        self._two_secret_key = two_secret_key
        self._session_id = session_id
        self._keychain = keychain
        self._client = client
        self._random_generator = random_generator
        self._request_id = 1
        self._session_hmac = self._create_session_hmac(
            raw_transport_key=raw_transport_key
        )

        self._client_verify_hash = two_secret_key.create_client_verify_hash(
            session_id=session_id
        )

        self._vault_item_names = collections.defaultdict(dict)
        self._vault_names = collections.defaultdict(list)

        self.verify()

    @staticmethod
    def _create_session_hmac(raw_transport_key):
        msg = "He never wears a Mac, in the pouring rain. Very strange."

        new_hmac = hmac.new(
            key=raw_transport_key,
            msg=msg,
            digestmod=hashlib.sha256
        )

        digested = new_hmac.digest()
        byte_string = ByteString(digested)

        return byte_string

    @staticmethod
    def _assemble_verify_data(
            device_uuid,
            session_id,
            client_verify_hash
    ):

        device = collections.OrderedDict()
        device["uuid"] = str(device_uuid)
        device["clientName"] = "1Password for Web"
        device["clientVersion"] = "577"
        device["name"] = "Chrome"
        device["model"] = "70.0.3538.77"
        device["osName"] = "MacOSX"
        device["osVersion"] = "10.13.6"
        device[
            "userAgent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"

        payload = collections.OrderedDict()
        payload["sessionID"] = str(session_id)
        payload["clientVerifyHash"] = str(client_verify_hash)
        payload["client"] = "1Password for Web/577"
        payload["device"] = device

        payload_as_json = json.dumps(payload, separators=(",", ":"))

        return payload_as_json

    def _create_verify_data(self, initialization_vector):
        payload_as_json = self._assemble_verify_data(
            device_uuid=self._client.device_uuid,
            session_id=self._session_id,
            client_verify_hash=self._client_verify_hash
        )

        ciphertext = self._keychain.encrypt_with_aes_gcm(
            uuid=self._session_id,
            initialization_vector=initialization_vector,
            data=payload_as_json
        )

        byte_string = ByteString(ciphertext)
        encoded_data = byte_string.urlsafe_base64_encode_and_unpad()

        return encoded_data

    def verify(self):
        initialization_vector = (
            self._random_generator.create_initialization_vector()
        )

        encoded_data = self._create_verify_data(
            initialization_vector=initialization_vector
        )

        response = self._client.verify(
            session_id=self._session_id,
            initialization_vector=initialization_vector.urlsafe_base64_encode_and_unpad(),
            data=encoded_data,
            session_hmac=self._session_hmac,
            request_id=self._request_id
        )

        self._decrypt_response(response=response)
        self._request_id += 1

    def _decrypt_response(self, response):
        try:
            algorithm = str(response['enc'])
        except KeyError:
            message = "Could not decrypt.  Response: " + str(response)

            raise OnePasswordException(message)

        if algorithm == 'A256GCM':

            data = ByteString.from_unpadded_urlsafe_base64_encoded_string(
                response['data']
            )

            initialization_vector = (
                ByteString.from_unpadded_urlsafe_base64_encoded_string(
                    response['iv']
                )
            )

            key_id = ByteString(response['kid'])
            plaintext = self._keychain.decrypt_aes_gcm_value(
                uuid=key_id,
                initialization_vector=initialization_vector,
                data=data
            )

        else:
            raise OnePasswordException('Non-A256GCM algorithm detected.')

        return plaintext

    def process_keysets(self, keysets_json):
        for single_keyset in keysets_json['keysets']:
            uuid = str(single_keyset['uuid'])
            symmetric_key_data = single_keyset['encSymKey']
            private_key_data = single_keyset['encPriKey']

            symmetric_key_id = symmetric_key_data['kid']

            if symmetric_key_id == 'mp':
                salt = ByteString.from_unpadded_urlsafe_base64_encoded_string(symmetric_key_data['p2s'])
                iterations = int(symmetric_key_data['p2c'])
                method = ByteString(symmetric_key_data['alg'])
                salt_information = SaltInformation(
                    salt=salt,
                    method=method,
                    iterations=iterations
                )

                raw_master_unlock_key = (
                    self._two_secret_key.derive_two_secret_key(
                        salt_information=salt_information
                    )
                )

                master_unlock_key = UnlockedAesGcmKey(
                    raw_key=raw_master_unlock_key,
                    uuid='mp'
                )

                self._keychain.register_aes_gcm_key(key=master_unlock_key)

                symmetric_encrypted_data = ByteString.from_unpadded_urlsafe_base64_encoded_string(
                    symmetric_key_data['data']
                )
                symmetric_iv = ByteString.from_unpadded_urlsafe_base64_encoded_string(
                    symmetric_key_data['iv']
                )

                symmetric_key_plaintext = master_unlock_key.decrypt(
                    initialization_vector=symmetric_iv,
                    data=symmetric_encrypted_data
                )

                unlocked_symmetric_key_data = json.loads(
                    symmetric_key_plaintext
                )

                symmetric_raw_key = ByteString.from_unpadded_urlsafe_base64_encoded_string(
                    unlocked_symmetric_key_data['k']
                )

                symmetric_key = UnlockedAesGcmKey(
                    raw_key=symmetric_raw_key,
                    uuid=uuid
                )

                self._keychain.register_aes_gcm_key(key=symmetric_key)

            else:
                symmetric_key_encrypted_data = ByteString.from_unpadded_urlsafe_base64_encoded_string(
                    symmetric_key_data['data']
                )

                self._keychain.add_locked_symmetric_key(
                    uuid=uuid,
                    data=symmetric_key_encrypted_data,
                    encrypted_by=symmetric_key_id
                )

            private_key_encrypted_data = ByteString.from_unpadded_urlsafe_base64_encoded_string(
                private_key_data['data']
            )

            private_key_encrypted_by = ByteString(private_key_data['kid'])

            priv_key_iv = ByteString.from_unpadded_urlsafe_base64_encoded_string(
                private_key_data['iv']
            )

            self._keychain.add_locked_private_key(
                uuid=uuid,
                initialization_vector=priv_key_iv,
                data=private_key_encrypted_data,
                encrypted_by=private_key_encrypted_by
            )

    def retrieve_keysets(self):
        response = self._client.retrieve_keysets(
            session_id=self._session_id,
            session_hmac=self._session_hmac,
            request_id=self._request_id
        )

        self._request_id += 1

        decrypted_response = self._decrypt_response(response=response)
        decrypted_response_json = json.loads(decrypted_response)

        self.process_keysets(keysets_json=decrypted_response_json)

    def _process_vaults(self, vaults_json):
        for single_vault in vaults_json:
            access_data = single_vault['access']

            for single_accessor in access_data:
                encrypted_vault_key = single_accessor['encVaultKey']
                encrypted_by = ByteString(encrypted_vault_key['kid'])
                
                encrypted_data = ByteString.from_unpadded_urlsafe_base64_encoded_string(encrypted_vault_key['data'])
                
                accessor_data = self._keychain.decrypt_rsa_value(
                    uuid=encrypted_by,
                    ciphertext=encrypted_data
                )

                accessor_data_json = json.loads(accessor_data)
                accessor_algorithm = accessor_data_json['alg']
                uuid = ByteString(accessor_data_json['kid'])

                if accessor_algorithm == 'A256GCM':
                    raw_key = ByteString.from_unpadded_urlsafe_base64_encoded_string(accessor_data_json['k'])
                    aes_key = UnlockedAesGcmKey(raw_key=raw_key, uuid=uuid)
                    self._keychain.register_aes_gcm_key(key=aes_key)

                else:
                    raise OnePasswordException("Non-AES key found.")
                
        for single_vault_again in vaults_json:
            encrypted_attributes = single_vault_again['encAttrs']
            encrypted_attributes_iv = ByteString.from_unpadded_urlsafe_base64_encoded_string(encrypted_attributes['iv'])
            encrypted_attributes_data = ByteString.from_unpadded_urlsafe_base64_encoded_string(encrypted_attributes['data'])
            encrypted_attributes_kid = ByteString(encrypted_attributes['kid'])
            decrypted_attributes = self._keychain.decrypt_aes_gcm_value(
                uuid=encrypted_attributes_kid,
                initialization_vector=encrypted_attributes_iv,
                data=encrypted_attributes_data
            )
            decrypted_attributes_json = json.loads(decrypted_attributes)
            vault_uuid = ByteString(decrypted_attributes_json['uuid'])
            vault_name = ByteString(decrypted_attributes_json['name'])
            self._vault_names[vault_name].append(vault_uuid)

    def retrieve_vaults(self):
        response = self._client.retrieve_vaults(
            session_id=self._session_id,
            session_hmac=self._session_hmac,
            request_id=self._request_id
        )

        self._request_id += 1

        decrypted_response = self._decrypt_response(response=response)
        decrypted_response_json = json.loads(decrypted_response)

        self._process_vaults(vaults_json=decrypted_response_json)

        return decrypted_response_json
    
    def process_items(self, items_json, vault_uuid):
        for single_item in items_json['items']:
            encrypted_overview = single_item['encOverview']
            encrypted_data = ByteString.from_unpadded_urlsafe_base64_encoded_string(encrypted_overview['data'])
            encrypted_iv = ByteString.from_unpadded_urlsafe_base64_encoded_string(encrypted_overview['iv'])
            encrypted_kid = ByteString(encrypted_overview['kid'])

            decrypted_overview = self._keychain.decrypt_aes_gcm_value(
                uuid=encrypted_kid,
                initialization_vector=encrypted_iv,
                data=encrypted_data
            )

            item_uuid = single_item['uuid']
            decrypted_overview_json = json.loads(decrypted_overview)
            item_name = decrypted_overview_json['title']

            if item_name not in self._vault_item_names[vault_uuid]:
                self._vault_item_names[vault_uuid][item_name] = item_uuid

    def retrieve_vault_contents(self, vault_uuid):
        response = self._client.retrieve_vault_overview(
            session_id=self._session_id,
            session_hmac=self._session_hmac,
            request_id=self._request_id,
            vault_uuid=vault_uuid
        )

        self._request_id += 1

        decrypted_response = self._decrypt_response(response=response)
        decrypted_response_json = json.loads(decrypted_response)

        self.process_items(
            items_json=decrypted_response_json,
            vault_uuid=vault_uuid
        )

        return decrypted_response_json

    def retrieve_vault_contents_by_name(self, vault_name):
        vault_uuid = self._vault_names[vault_name][0]
        return self.retrieve_vault_contents(vault_uuid=vault_uuid)

    def process_item_contents(self, contents_json):
        item_contents = contents_json['item']
        encrypted_details = item_contents['encDetails']
        details_data = ByteString.from_unpadded_urlsafe_base64_encoded_string(encrypted_details['data'])
        details_iv = ByteString.from_unpadded_urlsafe_base64_encoded_string(encrypted_details['iv'])
        details_kid = ByteString(encrypted_details['kid'])

        encrypted_overview = item_contents['encOverview']
        overview_data = ByteString.from_unpadded_urlsafe_base64_encoded_string(encrypted_overview['data'])
        overview_iv = ByteString.from_unpadded_urlsafe_base64_encoded_string(encrypted_overview['iv'])
        overview_kid = ByteString(encrypted_overview['kid'])

        decrypted_overview = self._keychain.decrypt_aes_gcm_value(
            uuid=overview_kid,
            initialization_vector=overview_iv,
            data=overview_data
        )
        decrypted_overview_json = json.loads(decrypted_overview)

        decrypted_details = self._keychain.decrypt_aes_gcm_value(
            uuid=details_kid,
            initialization_vector=details_iv,
            data=details_data
        )

        decrypted_details_json = json.loads(decrypted_details)

        item_contents['overview'] = decrypted_overview_json
        item_contents['details'] = decrypted_details_json

        return item_contents

    def retrieve_item_contents(self, vault_uuid, item_uuid):
        response = self._client.retrieve_item(
            session_hmac=self._session_hmac,
            session_id=self._session_id,
            vault_uuid=vault_uuid,
            item_uuid=item_uuid,
            request_id=self._request_id
        )

        self._request_id += 1

        decrypted_response = self._decrypt_response(response=response)
        decrypted_response_json = json.loads(decrypted_response)

        item_contents = self.process_item_contents(decrypted_response_json)

        return item_contents

    def retrieve_item_contents_by_name(self, vault_name, item_name):
        vault_uuid = self._vault_names[vault_name][0]
        self.retrieve_vault_contents(vault_uuid=vault_uuid)

        try:
            item_uuid = self._vault_item_names[vault_uuid][item_name]

        except KeyError:
            raise OnePasswordException('Could not find {item_name} in {vault_name}'.format(item_name=item_name, vault_name=vault_name))

        item_contents = self.retrieve_item_contents(
            vault_uuid=vault_uuid,
            item_uuid=item_uuid
        )

        return item_contents
    
    def retrieve_login_by_name(self, vault_name, item_name):
        item_contents = self.retrieve_item_contents_by_name(vault_name=vault_name, item_name=item_name)
        item_details = item_contents['details']
        item_fields = item_details['fields']
        item_fields_map = {single_field['name']: single_field['value'] for single_field in item_fields if 'name' in single_field}
        login = {'username': item_fields_map['username'], 'password': item_fields_map['password']}
        
        return login

    def retrieve_multi_factor_authentication_site_by_name(
            self,
            vault_name,
            site_name
    ):

        item_contents = self.retrieve_item_contents_by_name(
            vault_name=vault_name,
            item_name=site_name
        )

        item_object = {
            "title": item_contents['overview']['title']
        }

        details = item_contents['details']

        if "fields" in details:
            for single_field in details['fields']:
                if "designation" in single_field:
                    item_object[single_field['designation']] = single_field['value']

        if 'sections' in details:
            for single_section in details['sections']:
                if "fields" in single_section:
                    for single_field in single_section['fields']:
                        if str(single_field['n']).startswith("TOTP"):
                            item_object['totp_secret'] = single_field['v']

        return item_object

    def retrieve_password_by_name(self, vault_name, password_name):
        item_contents = self.retrieve_item_contents_by_name(
            vault_name=vault_name,
            item_name=password_name
        )

        if item_contents['trashed'] == 'Y':
            raise OnePasswordException('Item Has Been Trashed')

        password = item_contents['details']['password']

        return password

    def add_mfa_site_to_vault(
            self,
            vault_name,
            site_name,
            url,
            username,
            password,
            totp_secret
    ):

        vault = self.retrieve_vault_contents_by_name(vault_name=vault_name)
        vault_version = int(vault['contentVersion'])
        vaults = self.retrieve_vaults()
        vault_uuid = self._vault_names[vault_name][0]
        vault_info = [single_vault for single_vault in vaults if single_vault['uuid'] == vault_uuid][0]
        encryption_key_uuid = vault_info['encAttrs']['kid']
        now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + "Z"

        overview = collections.OrderedDict()
        overview["title"] = site_name
        overview["url"] = url
        overview["ainfo"] = username
        overview["ps"] = 0
        overview["pbe"] = 0
        overview["pgrng"] = False
        overview["URLs"] = [
            {
                "l": "website",
                "u": url
            }
        ]
        overview["tags"] = []

        details = collections.OrderedDict()
        section_uuid = self._random_generator.create_uuid()
        section_name = "Section_" + section_uuid
        totp_uuid = self._random_generator.create_uuid()
        totp_name = "TOTP_" + totp_uuid
        details["sections"] = [
            {
                "name": section_name,
                "title": "",
                "fields": [
                    {
                        "t": "one-time password",
                        "v": totp_secret,
                        "k": "concealed",
                        "n": totp_name
                    }
                ]
            }
        ]
        details["fields"] = [
            {
                "name": "username",
                "value": username,
                "type": "T",
                "designation": "username"
            },
            {
                "name": "password",
                "value": password,
                "type": "P",
                "designation": "password"
            }
        ]
        details["notesPlain"] = ""

        overview_iv = self._random_generator.create_initialization_vector()
        details_iv = self._random_generator.create_initialization_vector()

        encrypted_overview_data = self._keychain.encrypt_with_aes_gcm(
            uuid=encryption_key_uuid,
            initialization_vector=overview_iv,
            data=json.dumps(overview, separators=(",", ":"))
        )

        encrypted_details_data = self._keychain.encrypt_with_aes_gcm(
            uuid=encryption_key_uuid,
            initialization_vector=details_iv,
            data=json.dumps(details, separators=(",", ":"))
        )

        item_uuid = self._random_generator.create_uuid()

        enc_overview = collections.OrderedDict()
        enc_overview["kid"] = encryption_key_uuid
        enc_overview["enc"] = "A256GCM"
        enc_overview["cty"] = "b5+jwk+json"
        enc_overview["iv"] = overview_iv.urlsafe_base64_encode_and_unpad()
        enc_overview["data"] = encrypted_overview_data.urlsafe_base64_encode_and_unpad()

        enc_details = collections.OrderedDict()
        enc_details["kid"] = encryption_key_uuid
        enc_details["enc"] = "A256GCM"
        enc_details["cty"] = "b5+jwk+json"
        enc_details["iv"] = details_iv.urlsafe_base64_encode_and_unpad()
        enc_details["data"] = encrypted_details_data.urlsafe_base64_encode_and_unpad()

        data = collections.OrderedDict()
        data["uuid"] = item_uuid
        data["templateUuid"] = "001"
        data["itemVersion"] = 0
        data["vaultVersion"] = vault_version
        data["encryptedBy"] = encryption_key_uuid
        data["encOverview"] = enc_overview
        data["encDetails"] = enc_details
        data["trashed"] = "N"
        data["updatedAt"] = now
        data["createdAt"] = now
        data["fileReferences"] = []

        payload_as_json = json.dumps([data], separators=(",", ":"))

        initialization_vector = (
            self._random_generator.create_initialization_vector()
        )

        ciphertext = self._keychain.encrypt_with_aes_gcm(
            uuid=self._session_id,
            initialization_vector=initialization_vector,
            data=payload_as_json
        )

        byte_string = ByteString(ciphertext)
        encoded_data = byte_string.urlsafe_base64_encode_and_unpad()

        response = self._client.add_item(
            session_id=self._session_id,
            initialization_vector=initialization_vector.urlsafe_base64_encode_and_unpad(),
            data=encoded_data,
            session_hmac=self._session_hmac,
            request_id=self._request_id,
            content_version=vault_version,
            vault_uuid=vault_uuid
        )

        self._request_id += 1
        decrypted_response = self._decrypt_response(response=response)
        decrypted_response_json = json.loads(decrypted_response)

        return decrypted_response_json

    def add_password_to_vault(self, vault_name, item_name, password):
        vault = self.retrieve_vault_contents_by_name(vault_name=vault_name)
        vault_version = int(vault['contentVersion'])
        vaults = self.retrieve_vaults()
        vault_uuid = self._vault_names[vault_name][0]
        vault_info = [single_vault for single_vault in vaults if single_vault['uuid'] == vault_uuid][0]
        encryption_key_uuid = vault_info['encAttrs']['kid']
        now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + "Z"
        ainfo_time = datetime.datetime.utcnow().strftime('%B %-d, %Y %-I:%M %p')

        overview = collections.OrderedDict()
        overview["title"] = item_name
        overview["url"] = ""
        overview["ainfo"] = ainfo_time
        overview["ps"] = 0
        overview["pbe"] = 0
        overview["pgrng"] = False
        overview["URLs"] = []
        overview["tags"] = []

        details = collections.OrderedDict()
        details["sections"] = []
        details["fields"] = []
        details["password"] = password
        details["notesPlain"] = ""

        overview_iv = self._random_generator.create_initialization_vector()
        details_iv = self._random_generator.create_initialization_vector()

        encrypted_overview_data = self._keychain.encrypt_with_aes_gcm(
            uuid=encryption_key_uuid,
            initialization_vector=overview_iv,
            data=json.dumps(overview, separators=(",", ":"))
        )

        encrypted_details_data = self._keychain.encrypt_with_aes_gcm(
            uuid=encryption_key_uuid,
            initialization_vector=details_iv,
            data=json.dumps(details, separators=(",", ":"))
        )

        try:
            item_contents = self.retrieve_item_contents_by_name(
                vault_name=vault_name,
                item_name=item_name
            )
            item_uuid = item_contents['uuid']
            item_version = item_contents['itemVersion']

        except OnePasswordException:
            item_uuid = self._random_generator.create_uuid()
            item_version = 0

        enc_overview = collections.OrderedDict()
        enc_overview["kid"] = encryption_key_uuid
        enc_overview["enc"] = "A256GCM"
        enc_overview["cty"] = "b5+jwk+json"
        enc_overview["iv"] = overview_iv.urlsafe_base64_encode_and_unpad()
        enc_overview["data"] = encrypted_overview_data.urlsafe_base64_encode_and_unpad()

        enc_details = collections.OrderedDict()
        enc_details["kid"] = encryption_key_uuid
        enc_details["enc"] = "A256GCM"
        enc_details["cty"] = "b5+jwk+json"
        enc_details["iv"] = details_iv.urlsafe_base64_encode_and_unpad()
        enc_details["data"] = encrypted_details_data.urlsafe_base64_encode_and_unpad()

        data = collections.OrderedDict()
        data["uuid"] = item_uuid
        data["templateUuid"] = "005"
        data["itemVersion"] = item_version
        data["vaultVersion"] = vault_version
        data["encryptedBy"] = encryption_key_uuid
        data["encOverview"] = enc_overview
        data["encDetails"] = enc_details
        data["trashed"] = "N"
        data["updatedAt"] = now
        data["createdAt"] = now
        data["fileReferences"] = []

        payload_as_json = json.dumps([data], separators=(",", ":"))

        initialization_vector = (
            self._random_generator.create_initialization_vector()
        )

        ciphertext = self._keychain.encrypt_with_aes_gcm(
            uuid=self._session_id,
            initialization_vector=initialization_vector,
            data=payload_as_json
        )

        byte_string = ByteString(ciphertext)
        encoded_data = byte_string.urlsafe_base64_encode_and_unpad()

        response = self._client.add_item(
            session_id=self._session_id,
            initialization_vector=initialization_vector.urlsafe_base64_encode_and_unpad(),
            data=encoded_data,
            session_hmac=self._session_hmac,
            request_id=self._request_id,
            content_version=vault_version,
            vault_uuid=vault_uuid
        )

        self._request_id += 1
        decrypted_response = self._decrypt_response(response=response)
        decrypted_response_json = json.loads(decrypted_response)

        return decrypted_response_json


class OnePasswordCredentials(object):
    
    def __init__(self, sources, sinks):
        self._email_secret_value = credible_backend.SecretValue(
            value_name='ONE_PASSWORD_EMAIL',
            sources=sources,
            sinks=sinks
        )
        
        self._master_password_secret_value = credible_backend.SecretValue(
            value_name='ONE_PASSWORD_MASTER_PASSWORD',
            sources=sources,
            sinks=sinks
        )
        
        self._secret_key_secret_value = credible_backend.SecretValue(
            value_name='ONE_PASSWORD_SECRET_KEY',
            sources=sources,
            sinks=sinks
        )

    @property
    def email(self):
        email_value = self._email_secret_value.retrieve_value()
        
        return email_value
    
    @email.setter
    def email(self, value):
        self._email_secret_value.persist_value(value=value)

    @property
    def master_password(self):
        master_password_value = (
            self._master_password_secret_value.retrieve_value()
        )
        
        return master_password_value

    @master_password.setter
    def master_password(self, value):
        self._master_password_secret_value.persist_value(value=value)

    @property
    def secret_key(self):
        secret_key_value = self._secret_key_secret_value.retrieve_value()

        return secret_key_value

    @secret_key.setter
    def secret_key(self, value):
        self._secret_key_secret_value.persist_value(value=value)

    # noinspection PyAttributeOutsideInit
    def persist(self):
        self.email = self.email
        self.master_password = self.master_password
        self.secret_key = self.secret_key


class OnePasswordConfigurationFile(credible_backend.JsonConfigurationFile):

    def __init__(self, operating_system=os):
        super(OnePasswordConfigurationFile, self).__init__(
            path_environment_variable='ONE_PASSWORD_CONFIGURATION_FILE_PATH',
            default_path=operating_system.path.expanduser(
                "~/one_password_configuration.json"
            )
        )


def create_session(email, master_password, secret_key, device_uuid=Undefined):
    random_generator = RandomGenerator()

    secret_key_parts = secret_key.split("-")
    secret_key_format = secret_key_parts[0]
    secret_key_uuid = secret_key_parts[1]
    secret_key = "".join(secret_key_parts[2:])
    client_secret_value = random_generator.create_client_secret_value()

    two_secret_key = TwoSecretKey(
        email=email,
        client_secret_value=client_secret_value,
        master_password=master_password,
        secret_key=secret_key,
        secret_key_uuid=secret_key_uuid,
        secret_key_format=secret_key_format
    )

    if device_uuid is Undefined:
        device_uuid = random_generator.create_device_uuid()

    client = OnePasswordDeviceClient(device_uuid=device_uuid)
    keychain = Keychain()
    key_exchange = KeyExchange(
        two_secret_key=two_secret_key,
        public_root_modulo=client.PUBLIC_ROOT_MODULO,
        public_prime=client.PUBLIC_PRIME
    )

    session = Session(
        keychain=keychain,
        client=client,
        two_secret_key=two_secret_key,
        key_exchange=key_exchange,
        random_generator=random_generator
    )
    session.retrieve_keysets()
    session.retrieve_vaults()

    return session


def create_session_from_credentials():
    configuration_file = OnePasswordConfigurationFile()
    keychain = credible_backend.Keychain()
    sources = [configuration_file, keychain]
    sinks = [keychain]
    credentials = OnePasswordCredentials(sources=sources, sinks=sinks)

    email = str(credentials.email)
    master_password = str(credentials.master_password)
    combined_secret_key = str(credentials.secret_key)

    session = create_session(
        email=email,
        master_password=master_password,
        secret_key=combined_secret_key
    )

    return session

