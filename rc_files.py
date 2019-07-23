import os
import re


class RcFileException(Exception):
    pass


class NetRcMachineEntry(object):

    @classmethod
    def create_from_text(cls, text):
        tokenized = re.split(r'\s', text)

        kwargs = {}

        for pair_index in xrange(0, len(tokenized), 2):
            keyword = tokenized[pair_index]
            value = tokenized[pair_index + 1]
            kwargs[keyword] = value

        new_machine = cls(**kwargs)

        return new_machine

    def __init__(self, machine, login=None, account=None, password=None):
        self._validate_safe(machine)
        self._validate_safe_or_none(login)
        self._validate_safe_or_none(account)
        self._validate_safe_or_none(password)

        self._machine = machine
        self._login = login
        self._account = account
        self._password = password

    @staticmethod
    def _validate_safe(s):
        result = re.compile(r'\s').search(s)

        if result:
            message = '.netrc file entries cannot have whitespace in them.'

            raise RcFileException(message)

    def _validate_safe_or_none(self, s):
        if s is not None:
            self._validate_safe(s)

    def add_to_map(self, mapping):
        mapping[self._machine] = self

    def update_login(self, login):
        self._login = login

    def serialize(self):
        lines = []

        machine_line = "machine {machine}".format(machine=self._machine)
        lines.append(machine_line)

        if self._login:
            login_line = "login {login}".format(login=self._login)
            lines.append(login_line)

        if self._account:
            account_line = "account {account}".format(account=self._account)
            lines.append(account_line)

        if self._password:
            password_line = "password {password}".format(
                password=self._password
            )

            lines.append(password_line)

        joined_lines = "\n".join(lines)

        return joined_lines


class NetRcEntries(object):

    @classmethod
    def create_from_text(cls, text):
        split_by_double_newline = text.split(os.linesep + os.linesep)
        entries_by_machine = {}

        for single_double_line_group in split_by_double_newline:
            machine_blobs = []
            current_blob_lines = []

            for single_line in single_double_line_group.splitlines():
                if single_line.startswith("machine"):

                    if current_blob_lines:
                        new_machine_blob = "\n".join(current_blob_lines)
                        machine_blobs.append(new_machine_blob)

                    current_blob_lines = [single_line]

                else:
                    current_blob_lines.append(single_line)

            if current_blob_lines:
                new_machine_blob = "\n".join(current_blob_lines)
                machine_blobs.append(new_machine_blob)

            for single_blob in machine_blobs:
                new_entry = NetRcMachineEntry.create_from_text(text=single_blob)
                new_entry.add_to_map(mapping=entries_by_machine)

        new_entries = cls(entries_by_machine=entries_by_machine)

        return new_entries

    @classmethod
    def load_from_file(cls, fp):
        file_text = fp.read()
        entries = cls.create_from_text(text=file_text)

        return entries

    def __init__(self, entries_by_machine):
        self._entries_by_machine = entries_by_machine

    def set_or_add_machine_login(self, machine, login):
        if machine in self._entries_by_machine:
            entry = self._entries_by_machine[machine]
            entry.update_login(login=login)
        else:
            new_entry = NetRcMachineEntry(machine=machine, login=login)
            new_entry.add_to_map(mapping=self._entries_by_machine)

    def add_machine_entry(self, machine_entry):
        machine_entry.add_to_map(self._entries_by_machine)

    def serialize(self):
        machine_lines = []

        for single_machine_entry in self._entries_by_machine.itervalues():
            serialized_machine = single_machine_entry.serialize()
            stripped_machine = serialized_machine.strip()
            machine_lines.append(stripped_machine)

        sorted_lines = sorted(machine_lines)
        joined_lines = "\n\n".join(sorted_lines)

        return joined_lines

    def dump(self, fp):
        serialized_entries = self.serialize()
        fp.write(serialized_entries)
