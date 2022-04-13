#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (c) 2022 THL A29 Limited
#
# This source code file is made available under LGPL License
# See LICENSE for details
# ==============================================================================

"""
SonarQube for C#
"""

import os
import json

from util.sq import SonarQube


class SonarQubeCs(object):
    def __init__(self):
        self.source_dir = os.environ.get("SOURCE_DIR", None)
        print("[debug] source_dir: %s" % self.source_dir)
        self.task_params = self.__get_task_params()

    def __get_task_params(self):
        task_request_file = os.environ.get("TASK_REQUEST")
        print("[debug] task_request_file: %s" % task_request_file)
        with open(task_request_file, "r") as rf:
            task_request = json.load(rf)
        task_params = task_request["task_params"]
        return task_params

    def run(self):
        """
        :return:
        """
        build_cmd = self.task_params["build_cmd"]
        build_cwd = os.environ.get("BUILD_CWD", None)
        build_cwd = os.path.join(self.source_dir, build_cwd) if build_cwd else self.source_dir

        sonar_scanner = SonarQube(self.task_params)
        sonar_scanner.pre_cmd(build_cwd)
        issues = sonar_scanner.scan_proj(
            sonar_scanner.scan_cs_proj, languages="cs", build_cmd=build_cmd, build_cwd=build_cwd
        )

        with open("result.json", "w") as fp:
            json.dump(issues, fp, indent=2)


tool = SonarQubeCs


if __name__ == "__main__":
    print("-- start run tool ...")
    tool().run()
    print("-- end ...")
