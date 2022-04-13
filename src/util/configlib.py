# -*- coding: utf-8 -*-
# Copyright (c) 2022 THL A29 Limited
#
# This source code file is made available under LGPL License
# See LICENSE for details
# ==============================================================================


import configparser


class ConfigReader(object):

    def __init__(self, cfg_string=None, cfg_file=None, interpolation=None, encoding="utf-8-sig"):
        self._cfg = configparser.ConfigParser(interpolation=interpolation)
        self._cfg.optionxform = str
        self._cfg_string = cfg_string
        self._cfg_file = cfg_file
        if self._cfg_string:
            self._cfg.read_string(self._cfg_string)
        else:
            self._cfg.read(self._cfg_file, encoding=encoding)

    def read(self, section_name):
        rule_params_dict = {}
        for key, value in self._cfg.items(section_name):
            rule_params_dict[key] = value
        return rule_params_dict

    def get_section_names(self):
        return self._cfg.sections()
