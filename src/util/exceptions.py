# -*- coding: utf-8 -*-
# Copyright (c) 2022 THL A29 Limited
#
# This source code file is made available under LGPL License
# See LICENSE for details
# ==============================================================================


# ==============================================================================
# SonarQube
# ==============================================================================


class ClientError(Exception):
    pass


class ServerError(Exception):
    pass


class AuthError(ClientError):
    pass


class ValidationError(ClientError):
    pass


# ==============================================================================
# Task
# ==============================================================================


class CompileTaskError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return f"Error: {self.msg}"


class AnalyzeTaskError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return f"Error: {self.msg}"


class ConfigError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return f"Error: {self.msg}"
