import getpass
import os
import subprocess


class BackendError(Exception):
    pass


class BackendKeyError(BackendError, KeyError):
    pass


class Undefined(object):
    pass


class ValueSource(object):

    def __getitem__(self, item):
        raise NotImplementedError

    def __setitem__(self, key, value):
        raise NotImplementedError

    def get(self, k, default=None):
        raise NotImplementedError


class SecretPrompter(ValueSource):

    def __init__(self, prompt_strategy=getpass.getpass):
        self._prompt_strategy = prompt_strategy

    def __getitem__(self, item):
        value_is_same = False
        value = None

        while not value_is_same:
            value = self._prompt_strategy("Enter {item}: ".format(item=item))
            second_value = self._prompt_strategy(
                "Confirm {item}: ".format(item=item)
            )

            value_is_same = value == second_value

            if not value_is_same:
                print "Values do not match.  Try again."

        return value

    def __setitem__(self, key, value):
        raise BackendError("Cannot set value.")

    def get(self, k, default=None):
        value = self[k]

        return value


class Keychain(ValueSource):
    _SECURITY_COMMAND = 'security'
    _ACCOUNT_OPTION = '-a'
    _SERVICE_OPTION = '-s'
    _PASSWORD_OPTION = '-w'

    def __init__(self, process_factory=subprocess, default_account=Undefined):
        self._process_factory = process_factory

        if default_account is Undefined:
            self._default_account = getpass.getuser()
        else:
            self._default_account = default_account

    def __setitem__(self, key, value):
        process_arguments = [
            self._SECURITY_COMMAND,
            'add-generic-password',
            self._ACCOUNT_OPTION,
            self._default_account,
            self._SERVICE_OPTION,
            key,
            self._PASSWORD_OPTION,
            value,
            "-U"
        ]
        try:
            self._process_factory.check_call(process_arguments)
        except self._process_factory.CalledProcessError:
            message = "Generic password could not be created."

            raise BackendError(message)

    def __getitem__(self, item):
        process_arguments = [
            self._SECURITY_COMMAND,
            'find-generic-password',
            self._ACCOUNT_OPTION,
            self._default_account,
            self._SERVICE_OPTION,
            item,
            self._PASSWORD_OPTION
        ]

        try:
            process_output = self._process_factory.check_output(
                process_arguments,
                stderr=self._process_factory.STDOUT
            )

            password = process_output.rstrip()
        except self._process_factory.CalledProcessError:
            raise BackendKeyError(item)

        return password

    def get(self, k, default=None):
        try:
            value = self[k]
        except BackendError:
            value = default

        return value


class JsonConfigurationFile(ValueSource):

    def __init__(
            self,
            path_environment_variable,
            default_path,
            operating_system=os,
            open_strategy=open
    ):
        """

        :param str path_environment_variable:
        :param str default_path:
        :param os operating_system:
        :param open open_strategy:
        """
        self._path_environment_variable = str(path_environment_variable).upper()
        self._default_path = str(default_path)
        self._operating_system = operating_system
        self._open_strategy = open_strategy

    @property
    def _path(self):
        path_from_environment = self._operating_system.environ.get(
            self._path_environment_variable,
            None
        )

        if path_from_environment:
            path = path_from_environment
        else:
            path = self._default_path

        return path

    def get(self, k, default=None):
        try:
            value = self[k]
        except BackendKeyError:
            value = default

        return value

    def __setitem__(self, key, value):
        with self._open_strategy(self._path, 'w') as configuration_file:
            configuration = json.load(configuration_file)
            configuration[key] = value
            json.dump(
                configuration,
                configuration_file,
                sort_keys=True,
                indent=4
            )

    def __getitem__(self, item):
        try:
            with self._open_strategy(self._path, 'r') as configuration_file:
                configuration = json.load(configuration_file)
                value = configuration[item]

        except IOError:
            raise BackendKeyError(item)
        except KeyError:
            raise BackendKeyError(item)

        return value


class Arguments(ValueSource):

    def __init__(self, arguments):
        self._arguments = arguments

    def __getitem__(self, item):
        value = None

        if hasattr(self._arguments, item):
            value = getattr(self._arguments, item)

        if not value:
            raise BackendKeyError(item)

        return value

    def __setitem__(self, key, value):
        raise BackendError('Cannot set value.')

    def get(self, k, default=None):
        try:
            value = self[k]
        except BackendKeyError:
            value = default

        return value


class SecretValue(object):

    def __init__(self, value_name, sources, sinks):

        """

        :param str value_name:
        :param list[ValueSource] sources:
        :param list[ValueSource] sinks:
        """

        self._value_name = str(value_name).upper()
        self._sources = sources
        self._sinks = sinks

    def retrieve_value(self):
        value = Undefined

        for single_source in self._sources:
            value = single_source.get(self._value_name, Undefined)

            if value is not Undefined:
                break

        if value is Undefined:
            message = "No sources have value: {value}.".format(value=value)

            raise BackendError(message )

        return value

    def persist_value(self, value):
        persisted = False

        for single_sink in self._sinks:
            try:
                single_sink[self._value_name] = value
                persisted = True

                break

            except BackendError:
                pass

        if not persisted:
            message = "Could not persist value: {value}.".format(value=value)

            raise BackendError(message)
