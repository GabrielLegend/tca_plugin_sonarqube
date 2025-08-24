#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (c) 2022 THL A29 Limited
#
# This source code file is made available under LGPL License
# See LICENSE for details
# ==============================================================================


import os
import re
import sys
import json
import shlex
import getpass
import psutil
import platform
import stat
from shutil import copyfile
from time import sleep, time
from subprocess import Popen as p, PIPE as pi, STDOUT as sout
from threading import Thread as t

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

import settings
from util.configlib import ConfigReader
from util.api import SQAPIHandler
from util.exceptions import CompileTaskError, AnalyzeTaskError, ConfigError, ValidationError, ClientError


SQ_LOCAL_USER = getattr(settings, "SQ_LOCAL_USER", None)
SQ_COMMON_USER = getattr(settings, "SQ_COMMON_USER", None)


SONAR_DEVCOST = 30
SONAR_DEBT_RATINGGRID = "0.05,0.1,0.2,0.5"


LOCAL_MODEL = "LOCAL"
COMMON_MODEL = "COMMON"

COMMON_SONAR_LANGS = [
    "cs",
    "java",
    "jsp",
    "vbnet",
    "css",
    "flex",
    "go",
    "js",
    "kotlin",
    "php",
    "py",
    "ruby",
    "scala",
    "ts",
    "web",
    "xml",
]


class SonarQube(object):
    def __init__(self, params):
        # admin
        self.base_url = SQ_LOCAL_USER["url"]
        self.port = SQ_LOCAL_USER["port"]
        self.base_path = SQ_LOCAL_USER["base_path"]
        self.user = SQ_LOCAL_USER["username"]
        self.password = SQ_LOCAL_USER["password"]
        self.projectKey = SQ_LOCAL_USER["projectKey"]
        self.model = LOCAL_MODEL
        if self.password:
            self.sonar_handle = SQAPIHandler(
                host=self.base_url, port=self.port, base_path=self.base_path, user=self.user, password=self.password
            )
        else:
            self.sonar_handle = SQAPIHandler(
                host=self.base_url, port=self.port, base_path=self.base_path, token=self.user
            )
        self.sleep_second = 5
        self.timeout = 300
        self.com_cmd = list()

        self.init_env()

        self.params = params
        self.work_dir = os.path.join(self.params["task_dir"], "workdir")
        if not os.path.exists(self.work_dir):
            os.mkdir(self.work_dir)
        self.scannerwork = os.path.join(self.work_dir, "scannerwork")

        self.is_local_up = False if settings.PLATFORMS[sys.platform] != "windows" else True

    def pre_cmd(self, build_cwd):
        pre_cmd = self.params.get("pre_cmd", None)
        if not pre_cmd:
            return
        print("[warning] do pre_cmd.")
        if isinstance(pre_cmd, str):
            pre_cmd = shlex.split(pre_cmd)
        print("[warning] run pre cmd: %s" % " ".join(pre_cmd))
        SonarQube.Process(
            pre_cmd,
            build_cwd,
            print,
        ).wait()

    def scan_proj(self, scan_fun, languages, **fun_args):
        source_dir = os.environ.get("SOURCE_DIR", None)
        pos = len(source_dir) + 1
        work_dir = self.work_dir
        rules = self.params["rules"]
        envs = os.environ
        java_home = envs.get("SQ_JDK_HOME")
        build_cwd = envs.get("BUILD_CWD", None)
        build_cwd = os.path.join(source_dir, build_cwd) if build_cwd else source_dir
        sonarqube_home = envs.get("SONARQUBE_HOME")
        property_path = os.path.join(sonarqube_home, "conf", "sonar.properties")
        property_temp = os.path.join(sonarqube_home, "conf", "sonar.properties.temp")
        is_quality = "SONAR_QUALITYPROFILE" in envs or "SONAR_QUALITYPROFILE_TYPE" in envs

        if "SONAR_TIMEOUT" in envs:
            self.timeout = int(envs.get("SONAR_TIMEOUT", self.timeout))

        print("[info] User is %s" % str(getpass.getuser()))

        if "SQ_TYPE" in envs and envs.get("SQ_TYPE") == COMMON_MODEL and SQ_COMMON_USER:
            print("[warning] Link common...")
            self._use_common_sonarqube()
        elif sys.platform in ("linux", "linux2") and getpass.getuser() == "root":
            self._root_start_local_sonarqube()
        else:
            self._start_local_sonarqube(
                shlex.split(
                    self.generate_shell_file(
                        f"export PATH={java_home}/bin:$PATH\n./bin/run.sh"
                        if sys.platform != "win32"
                        else f"set PATH={java_home}/bin;%PATH%\nbin\\windows-x86-64\\StartSonar.bat"
                    )
                )
            )

        if self.model == LOCAL_MODEL:
            no_proxy = envs.get("no_proxy", None)
            if no_proxy:
                no_proxy_list = no_proxy.split(",")
            else:
                no_proxy_list = list()
            if "localhost" not in no_proxy_list:
                no_proxy_list.append("localhost")
                envs["no_proxy"] = ",".join(no_proxy_list)

        self._wait_until_sonarqube_on()

        self.com_cmd = self._get_common_cmds()
        self._add_sonar_filter_path()

        self._wait_until_project_create()

        if envs.get("SONAR_DEVCOST", None):
            self.sonar_handle.set_settings(
                key="sonar.technicalDebt.developmentCost", value=int(envs.get("SONAR_DEVCOST", SONAR_DEVCOST))
            )
        # default: 0.05,0.1,0.2,0.5
        if envs.get("SONAR_DEBT_RATINGGRID", None):
            self.sonar_handle.set_settings(
                key="sonar.technicalDebt.ratingGrid", value=envs.get("SONAR_DEBT_RATINGGRID", SONAR_DEBT_RATINGGRID)
            )

        self._set_qualityprofiles(self.sonar_handle, self.projectKey, languages)

        sonar_report = scan_fun(**fun_args)
        if envs.get("SONAR_REPORT", None):
            sonar_report = os.path.join(source_dir, envs.get("SONAR_REPORT"))
        if not sonar_report or not os.path.exists(sonar_report):
            print(f"{sonar_report}结果文件不存在，开始遍历查找SQ分析结果文件...")
            sonar_report_list = self.get_dir_files(source_dir, "report-task.txt".lower())
            if self.scannerwork and os.path.exists(self.scannerwork):
                sonar_report_list.extend(self.get_dir_files(self.scannerwork, "report-task.txt".lower()))
            if sonar_report_list:
                sonar_report = sonar_report_list[0]
                print(f"查找到分析文件{sonar_report}")
        print("[info] 结果文件是：%s" % sonar_report)

        self._wait_until_task_succeed(self.sonar_handle, sonar_report)

        self._dump_measures(self.sonar_handle, self.projectKey, os.path.join(work_dir, "sonar_result.json"))

        issues = []
        try:
            for issue in self.sonar_handle.get_issues(
                languages=languages, componentKeys=self.projectKey, rules=None if is_quality else ",".join(rules)
            ):
                rule = issue["rule"]
                if not is_quality and rules and rule not in rules:
                    continue
                path = issue["component"].split(":")[-1]
                path = os.path.join(build_cwd, path)[pos:]
                msg = issue["message"]
                text_range = issue.get("textRange", None)
                if text_range:
                    line = int(text_range["startLine"])
                    column = int(text_range["startOffset"])
                else:
                    line = 0
                    column = 0

                if rule.endswith("DuplicatedBlocks"):
                    dupl_blocks = self.sonar_handle.duplications_show(issue["component"])
                    for dupl in dupl_blocks.get("duplications", list()):
                        refs = list()
                        for block in dupl["blocks"]:
                            refs.append(
                                {
                                    "line": block["from"],
                                    "column": 0,
                                    "msg": "重复块(%d行-%d行)" % (block["from"], block["from"] + block["size"] - 1),
                                    "tag": None,
                                    "path": dupl_blocks["files"][block["_ref"]]["name"],
                                }
                            )
                        issues.append(
                            {"path": path, "rule": rule, "msg": msg, "line": line, "column": column, "refs": refs}
                        )
                else:
                    refs = list()
                    for flow in issue.get("flows", []):
                        for location in flow.get("locations", []):
                            refs.append(
                                {
                                    "line": location["textRange"]["startLine"],
                                    "column": location["textRange"]["startOffset"],
                                    "msg": location.get("msg", ""),
                                    "tag": None,
                                    "path": location["component"].split(":")[-1],
                                }
                            )
                    issues.append(
                        {"path": path, "rule": rule, "msg": msg, "line": line, "column": column, "refs": refs}
                    )
        except ValidationError as e:
            print("[info] exception: %s" % str(e))

        incr_scan = self.params["incr_scan"]
        if not incr_scan:
            cogn_complex_cnt = 0
            cogn_complex_sum = 0
            cogn_complex_over = 0
            for issue in issues:
                if not issue["rule"].endswith(":S3776"):
                    continue
                msg = issue["msg"]
                info = [token for token in msg.split() if token.isdigit()]
                if len(info) < 2:
                    continue
                cogn_complex_cnt += 1
                cogn_complex_sum += int(info[0])
                cogn_complex_over += int(info[0]) - int(info[1])
            if "summary" not in self.params:
                self.params["summary"] = dict()
            self.params["summary"]["cogncomplexity"] = {
                "over_cognc_func_count": cogn_complex_cnt,
                "over_cognc_func_average": cogn_complex_sum / cogn_complex_cnt if cogn_complex_cnt != 0 else 0,
                "over_cognc_sum": cogn_complex_over,
            }

        if envs.get("SONAR_DEVCOST", None):
            self.sonar_handle.set_settings(key="sonar.technicalDebt.developmentCost", value=SONAR_DEVCOST)
        if envs.get("SONAR_DEBT_RATINGGRID", None):
            self.sonar_handle.set_settings(key="sonar.technicalDebt.ratingGrid", value=SONAR_DEBT_RATINGGRID)

        print("[warning] Operation after ")
        if self.model == LOCAL_MODEL:
            self._kill_sonar()

            if "SONAR_SERVER_PARAMS" in envs:
                os.remove(property_path)
                os.rename(property_temp, property_path)

        return issues

    @staticmethod
    def init_env():
        tool_dir = settings.TOOL_DIR
        os.environ["SONAR_SCANNER_HOME"] = os.path.join(
            tool_dir, settings.PLATFORMS[sys.platform], "sonar-scanner-4.2.0.1873"
        )
        os.environ["SQ_JDK_HOME"] = os.path.join(os.environ["SONAR_SCANNER_HOME"], "jre")
        os.environ["SONARQUBE_HOME"] = os.path.join(tool_dir, "common", "sonarqube-8.9.8.54436")
        os.environ["PATH"] = os.pathsep.join(
            [
                os.path.join(os.environ["SQ_JDK_HOME"], "bin"),
                os.path.join(os.environ["SONAR_SCANNER_HOME"], "bin"),
                os.environ["PATH"],
            ]
        )

    def kill_proc_famliy(self, pid):
        try:
            task_proc = psutil.Process(pid)
            children = task_proc.children(recursive=True)
            print("[info] kill process: %s" % task_proc)
            task_proc.terminate()
            print("[info] kill children processes: %s" % children)
            for child in children:
                try:
                    child.kill()
                except Exception as err:
                    print("[error] kill child proc failed: %s" % err)
            gone, still_alive = psutil.wait_procs(children, timeout=5)
            for child in still_alive:
                try:
                    child.kill()
                except Exception as err:
                    print("[error] kill child proc failed: %s" % err)
        except psutil.NoSuchProcess as err:
            print("[warning] process is already terminated: %s" % err)
        except Exception as err:
            print("[error] kill task failed: %s" % err)

    def _raise_error(self, msg, err_type=None):
        if self.model == LOCAL_MODEL:
            self._kill_sonar()
        if err_type == "compile":
            raise CompileTaskError(msg)
        elif err_type == "config":
            raise ConfigError(msg)
        else:
            raise AnalyzeTaskError(msg)

    @staticmethod
    def check_usable():
        __class__.init_env()
        check_cmd_args = ["java", "-version"]
        result = True
        try:

            p = SonarQube.Process(check_cmd_args)
            p.wait()
            out = SonarQube.decode(p.p.stdout.read())
            if out.find('version "11.') == -1:
                result = False
        except Exception as err:
            print("tool is not usable: %s" % str(err))
            result = False
        return result

    def get_dir_files(self, root_dir, want_suffix=""):
        files = set()
        for dirpath, _, filenames in os.walk(root_dir):
            for f in filenames:
                if f.lower().endswith(want_suffix):
                    fullpath = os.path.join(dirpath, f)
                    files.add(fullpath)
        files = list(files)
        return files

    @staticmethod
    def generate_shell_file(cmd, shell_name="build"):
        work_dir = os.getcwd()
        if platform.system() == "Windows":
            file_name = f"{shell_name}.bat"
        else:
            file_name = f"{shell_name}.sh"
        shell_filepath = os.path.join(work_dir, file_name)
        shell_filepath = os.path.abspath(shell_filepath.strip()).replace("\\", "/").rstrip("/")
        with open(shell_filepath, "w") as wf:
            wf.write(cmd)
        os.chmod(shell_filepath, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

        print("[info] Cmd:\n%s" % cmd)
        print("[info] Generated shell file: %s" % shell_filepath)

        if platform.system() == "Windows":
            return shell_filepath
        else:
            return "bash %s" % shell_filepath

    @staticmethod
    def decode(line):
        try:
            # UTF-8
            line = line.decode()
        except UnicodeDecodeError:
            line = line.decode(encoding="gbk")
        return line

    class Process(object):
        def __init__(self, command, cwd=None, out=None, err=None, shell=False):
            # print(" ".join(command))
            if shell : command = " ".join(command)
            self.p = None
            out_t = None
            err_t = None
            try:
                self.p = p(command, cwd=cwd, stdout=pi, stderr=pi, shell=shell)
                if out:
                    out_t = t(target=self.do, args=(self.p.stdout, out))
                    out_t.start()
                if err:
                    err_t = t(target=self.do, args=(self.p.stderr, err))
                    err_t.start()
            except Exception as e:
                import traceback
                traceback.print_exc()
                if self.p: self.p.close()
                if out_t: out_t.close()
                if err_t: err_t.close()

        def wait(self):
            if self.p: self.p.wait()

        def do(self, pipe, callback=None):
            while self.p.poll() is None:
                out = pipe.readline()
                out = bytes.decode(out)
                if out:
                    callback(out)
            out = pipe.read()
            if out:
                callback(out)

    def _use_common_sonarqube(self):
        sq_user = SQ_COMMON_USER
        self.model = COMMON_MODEL
        self.base_url = sq_user["url"]
        self.port = sq_user["port"]
        self.base_path = sq_user["base_path"]
        self.user = sq_user["username"]
        self.password = sq_user["password"]
        self.projectKey = "%s_%s" % (sq_user["projectKey"], str(self.params.get("project_id", "")))
        self.sonar_handle = SQAPIHandler(host=self.base_url, port=self.port, base_path=self.base_path, token=self.user)

        self.is_local_up = True

    def _chmod_ancestor_dir(self, path, mode):
        father_dir = os.path.abspath(path)
        while father_dir != "/":
            os.chmod(father_dir, mode)
            father_dir = os.path.dirname(father_dir)

    def _root_start_local_sonarqube(self):
        envs = os.environ
        sonarqube_home = envs.get("SONARQUBE_HOME")
        java_home = envs.get("SQ_JDK_HOME")
        user = None
        if "SONARQUBE_USER" in envs:
            user = envs.get("SONARQUBE_USER")
        else:
            user = "sonarqube"
            SonarQube.Process(
                ["useradd", user],
                cwd=sonarqube_home,
            ).wait()
        SonarQube.Process(
            ["chmod", "-R", "777", sonarqube_home],
            cwd=sonarqube_home,
        ).wait()
        SonarQube.Process(
            ["chmod", "-R", "777", java_home],
            cwd=sonarqube_home,
        ).wait()
        self._chmod_ancestor_dir(sonarqube_home, 0o777)

        return self._start_local_sonarqube(
            ["sudo", "-u", user, "bash", "-c", "export PATH=%s/bin:$PATH && ./bin/run.sh" % java_home]
        )

    def _start_local_sonarqube(self, cmd):
        self._kill_sonar()

        envs = os.environ
        sonarqube_home = envs.get("SONARQUBE_HOME")
        property_path = os.path.join(sonarqube_home, "conf", "sonar.properties")
        property_temp = os.path.join(sonarqube_home, "conf", "sonar.properties.temp")

        if "SONAR_SERVER_PARAMS" in envs:
            if not os.path.exists(property_temp):
                copyfile(property_path, property_temp)
            # default: SONAR_SERVER_PARAMS=sonar.web.javaOpts=-Xmx512m -Xms128m;sonar.ce.javaOpts=-Xmx512m -Xms128m
            sonar_server_params = envs.get("SONAR_SERVER_PARAMS").strip('"').split(";")
            f = open(property_path, "a")
            for param in sonar_server_params:
                f.write("\n%s" % param)
            f.close()

        print("[info] cmd: %s" % " ".join(cmd))
        p = SonarQube.Process(
            cmd,
            sonarqube_home,
            self._start_sonarqube,
        )
        timeout = time() + self.timeout
        while not p.p.pid:
            sleep(self.sleep_second)
            if timeout < time():
                self._raise_error("获取Sq进程PID超时，请查看log排查原因", err_type="analyze")
        return p.p.pid

    def _start_sonarqube(self, line):
        """

        :param line:
        :return:
        """
        print(f"SQServer: {line}")
        if (
            line.find("app[][o.s.a.SchedulerImpl] SonarQube is stopped") != -1
            or line.find("错误: 找不到或无法加载主类 org.sonar.application.App") != -1
            or line.find("sudo: pam_open_session: Permission denied") != -1
            or line.find("sudo: pam_open_session：拒绝权限") != -1
            or line.find("java.lang.IllegalStateException: SonarQube requires Java 11 to run") != -1
            or line.find("sudo: sorry, you must have a tty to run sudo") != -1
            or line.find("sudo：抱歉，您必须拥有一个终端来执行 sudo") != -1
            or line.find(
                "org.elasticsearch.cluster.block.ClusterBlockException: blocked by: [FORBIDDEN/12/index read-only / allow delete (api)];"
            )
            != -1
            or line.find("sudoers.so must be only be writable by owner") != -1
            or line.find("fatal error, unable to load plugins") != -1
        ):
            if SQ_COMMON_USER:
                print("[warning] Change to common...")
                self._use_common_sonarqube()
        elif line.find("SonarQube is up") != -1:
            print("[warning] Linking Server.")
            self.is_local_up = True

    def _wait_until_task_succeed(self, sonar_handle, sonar_report):
        if not sonar_report or not os.path.exists(sonar_report):
            self._raise_error(f"结果文件({sonar_report})不存在，分析失败，请查看log排查失败原因", err_type="analyze")
        with open(sonar_report) as f:
            id = f.readlines()[4].strip().split("=")[-1]
            print("[warning] Task ID is %s" % id)
        timeout = time() + self.timeout
        is_success = False
        while not is_success:
            res = None
            try:
                sleep(self.sleep_second)
                res = sonar_handle.ce_task(id_=id)
                print("[info] Server response is %s" % str(res))
                is_success = True if res["task"]["status"] == "SUCCESS" else False
            except Exception as e:
                print("[info] exception: %s" % str(e))
                is_success = False

            if res and res["task"]["status"] == "FAILED":
                if re.match(
                    "load called twice for thread '.*' or state wasn't cleared last time it was used",
                    res["task"]["errorMessage"],
                    re.I,
                ):
                    self._raise_error("SonarQube Server异常，需要重启SonarQube Server。", err_type="analyze")
                elif "Java heap space" == res["task"]["errorMessage"]:
                    self._raise_error("SonarQube Server异常, Server Java堆溢出异常。", err_type="analyze")
                elif "Unrecoverable indexation failures: 1 errors among 1 requests" == res["task"]["errorMessage"]:
                    self._raise_error(
                        "SonarQube Server异常, 达到文件系统已用空间的85％，90％或95％的elasticsearch操作可能导致索引失败，请检查清理机器存储空间或者重启SonarQube Server。",
                        err_type="analyze",
                    )
                else:
                    self._raise_error("SonarQube Server异常, 请查看log排查。", err_type="analyze")

            if timeout < time():
                self._raise_error("判断任务执行是否执行完成操作超时，请查看log排查原因", err_type="analyze")
        print("[warning] Task completed.")

    def _wait_until_sonarqube_on(self):
        timeout = time() + self.timeout
        is_server_up = False
        print("[warning] Wait for Server...")
        while not is_server_up or not self.is_local_up:
            try:
                sleep(self.sleep_second)
                print(f"Checking {self.model} Status...")
                status = self.sonar_handle.get_system_status().get("status", "DOWN")
                print("[info] Status is %s" % str(status)[0])
                is_server_up = True if status == "UP" else False
            except Exception as e:
                is_server_up = False

            if timeout < time():
                self._raise_error("等待Sq工具启动超时，请查看log排查原因", err_type="analyze")
        print("[warning] Server is %s" % str(is_server_up))
        print("[warning] Own is %s" % str(self.is_local_up))
        print("[warning] Linking Server.")

    def _wait_until_project_create(self):
        timeout = time() + self.timeout
        is_project_created = False
        retry_times = 5
        cnt = 0
        print("[warning] Start to create project...")
        while not is_project_created:
            try:
                cnt += 1
                self.sonar_handle.project_create(name=self.projectKey, project=self.projectKey)
                is_project_created = True
            except ValidationError as e:
                print("[info] exception: %s" % str(e))
                is_project_created = True
            except ClientError as e:
                print("[info] exception: %s" % str(e))
                sleep(self.sleep_second)
            if cnt > retry_times:
                self._raise_error(f"SQ项目创建重试超出限制次数{retry_times}次，项目创建失败，请查看log排查原因", err_type="analyze")
            if timeout < time():
                self._raise_error("等待SQ项目创建超时，请查看log排查原因", err_type="analyze")
        print("[warning] Project created success.")

    def _dump_measures(self, sonar_handle, project_key, dump_path):
        measures = sonar_handle.get_component_measures(
            metricKeys="ncloc,sqale_index,sqale_debt_ratio,bugs,vulnerabilities,code_smells",
            component=project_key,
            additionalFields="metrics,periods",
        )
        print("[info] SQ measures is %s" % str(measures))
        measures_result = dict()
        for index, value in enumerate(measures["component"]["measures"]):
            if value["metric"].startswith("new"):
                measures_result[value["metric"]] = float(value["periods"][0]["value"])
            else:
                measures_result[value["metric"]] = float(value["value"])

            if value["metric"].endswith("_ratio"):
                measures_result[value["metric"]] = "%.3f%%" % (measures_result[value["metric"]])
            else:
                measures_result[value["metric"]] = int(measures_result[value["metric"]])

        self.params["summary"] = dict()
        self.params["summary"]["sqdebt"] = measures_result

        print("[info] SQ result is %s" % str(measures_result))
        with open(dump_path, "w") as f:
            json.dump(measures_result, f, indent=2)

    def _set_qualityprofiles(self, sonar_handle, project_key, languages):
        source_dir = os.environ.get("SOURCE_DIR", None)
        work_dir = self.work_dir
        rules = self.params["rules"]
        rule_list = self.params.get("rule_list", [])
        envs = os.environ
        langs = languages.split(",")

        default_profiles = self.get_dir_files(
            os.path.join(os.path.dirname(settings.TOOL_DIR), "profiles"), "_SonarQube_Profile.xml".lower()
        )
        qualityprofile_filepaths = dict()
        profiles_path = os.path.join(work_dir, "profiles")
        if not os.path.exists(profiles_path):
            os.mkdir(profiles_path)

        for profile in default_profiles:
            profile_name = os.path.basename(profile)
            lang = profile_name.split("_")[0].lower()
            if self.model in (LOCAL_MODEL, COMMON_MODEL) and lang not in COMMON_SONAR_LANGS:
                continue
            profile_path = os.path.join(profiles_path, profile_name)
            copyfile(profile, profile_path)
            qualityprofile_filepaths[lang] = profile_path

        if "SONAR_QUALITYPROFILE_TYPE" in envs:
            print(f"启用{envs.get('SONAR_QUALITYPROFILE_TYPE', '')}模式配置文件")
            for path in self.get_dir_files(
                os.path.join(os.path.dirname(settings.TOOL_DIR), "profiles"),
                f"_{envs.get('SONAR_QUALITYPROFILE_TYPE', '')}.xml".lower(),
            ):
                info = self._get_profile_info(path)
                if info["lang"] not in langs:
                    continue
                profile_name = os.path.basename(path)
                profile_path = os.path.join(profiles_path, profile_name)
                copyfile(path, profile_path)
                qualityprofile_filepaths[info["lang"]] = profile_path

        if envs.get("SONAR_QUALITYPROFILE", None):
            print("[warning] 使用项目指定质量配置文件")
            for path in str(envs.get("SONAR_QUALITYPROFILE")).split(";"):
                profile_path = os.path.join(source_dir, path)
                if not os.path.exists(profile_path):
                    self._raise_error(f"自主设置的配置文件({path})不存在, 请自查，填写正确的配置文件路径。", err_type="config")
                info = self._get_profile_info(profile_path)
                if info["lang"] not in langs:
                    continue
                qualityprofile_filepaths[info["lang"]] = profile_path

        for lang in qualityprofile_filepaths:
            profile_path = qualityprofile_filepaths[lang]
            if not profile_path.lower().endswith("_SonarQube_Profile.xml".lower()):
                continue
            tree = ET.ElementTree(file=profile_path)
            root = tree.getroot()
            all_rules = root.find("rules")
            removed_rules = list()
            for rule in all_rules:
                real_name = "%s:%s" % (rule.find("repositoryKey").text, rule.find("key").text)
                if real_name not in rules:
                    removed_rules.append(rule)
                    continue
                rule_param = None
                for rule_info in rule_list:
                    if rule_info["name"] == real_name:
                        rule_param = rule_info["params"]
                        break
                if not rule_param:
                    continue
                if "[sq]" not in rule_param:
                    rule_param = "[sq]\n" + rule_param
                rule_params_dict = ConfigReader(cfg_string=rule_param).read("sq")
                if not rule_params_dict:
                    continue
                parameters = rule.find("parameters")
                for parameter in parameters:
                    key = parameter.find("key")
                    value = parameter.find("value")
                    if key.text in rule_params_dict:
                        value.text = rule_params_dict[key.text]

            for rule in removed_rules:
                all_rules.remove(rule)
            tree.write(profile_path)

        for lang in qualityprofile_filepaths:
            path = qualityprofile_filepaths[lang]
            sonar_handle.qualityprofiles_restore(path)
            info = self._get_profile_info(path)
            sonar_handle.qualityprofiles_add_project(
                project=project_key, language=info["lang"], qualityProfile=info["name"]
            )

    def _get_profile_info(self, path):
        tree = ET.ElementTree(file=path)
        children = tree.getroot().getchildren()
        return {"lang": children[1].text, "name": children[0].text}

    def _kill_sonar(self):
        pids = psutil.pids()
        for pid in pids:
            try:
                p = psutil.Process(pid)
                if p.name().lower().startswith("java") and " ".join(p.cmdline()).find("lib/sonar-application") != -1:
                    self.kill_proc_famliy(pid)
                    break
            except Exception as e:
                print("[info] exception: %s" % str(e))

    def _get_common_cmds(self):
        cmds = [
            "-Dsonar.projectKey=%s" % self.projectKey,
            "-Dsonar.host.url=%s:%s%s" % (self.base_url, str(self.port), self.base_path),
            "-Dsonar.login=%s" % self.user,
            "-Dsonar.password=%s" % self.password,
            "-Dsonar.scm.disabled=true",
            "-Dsonar.import_unknown_files=true",
            "-Dsonar.sourceEncoding=UTF-8",
            "-Dsonar.working.directory=%s" % self.scannerwork,
        ]

        # for example:
        # SQ_CLIENT_PARAMS="-Dsonar.javascript.globals=;-Dsonar.javascript.environments="
        if "SQ_CLIENT_PARAMS" in os.environ:
            sonar_params = os.environ.get("SQ_CLIENT_PARAMS", "")
            sonar_params = sonar_params.strip('"').split(";") if sonar_params else []
            cmds.extend(sonar_params)

        return cmds

    def change_to_vs_cmd(self, cmd):
        result = list()
        for c in cmd:
            if c.startswith("-Dsonar.projectKey="):
                result.append(f'/k:"{c.split("=")[1]}"')
            elif c.startswith("-D"):
                token = c.split("=")
                result.append(f'/d:{token[0][2:]}="{token[1]}"')
            else:
                result.append(c)
        return result

    def _change_to_win_cmd(self, cmd):
        if sys.platform != "win32":
            return cmd
        result = list()
        for c in cmd:
            if c.startswith("-D"):
                result.append('-D"' + c[2:] + '"')
            else:
                result.append(c)
        return result

    def run_cmd(self, command, cwd=None, cmd_type=None):
        print("[warning] run cmd: %s" % " ".join(command))
        print("[warning] Start cmd...")
        p = SonarQube.Process(
            command,
            cwd,
            out=print,
            err=self.__handle,
        )
        p.wait()
        if p.p == None or p.p.returncode != 0:
            if cmd_type == "compile":
                self._raise_error(msg="编译失败，请确认编译命令正确，并查看log排查失败原因。", err_type=cmd_type)
            elif cmd_type == "analyze":
                self._raise_error(msg="工具执行分析失败，请查看log排查失败原因。", err_type=cmd_type)

    def __handle(self, line):
        print(line)
        if line.find("java.lang.IllegalStateException: No files nor directories matching") != -1:
            self._raise_error(msg="Tool_BIN指定的路径下没有找到class文件，请确认Tool_BIN设置正确。", err_type="analyze")
        elif line.find("java.lang.IllegalStateException: Unable to read file") != -1:
            self._raise_error(msg=f"解析该文件失败，请确保该文件是不是软链接、编码或者语法有问题: {line}", err_type="config")

    def scan_java_proj(self, build_type, build_cwd, build_cmd=None):
        if build_type.lower() in ("any", "no_build"):
            if os.environ.get("SQ_JAVA_BUILD") and build_cmd:
                self.run_cmd(command=shlex.split(build_cmd), cwd=build_cwd)
            scan_cmd = [
                "sonar-scanner",
                "-X",
                "-Dsonar.sources=%s" % os.environ.get("SONAR_JAVA_SRC", "."),
                "-Dsonar.language=java,jsp",
                "-Dsonar.java.binaries=%s" % os.environ.get("SONAR_BIN", "**/*"),
            ] + self.com_cmd
            if os.environ.get("SONAR_LIB", None):
                scan_cmd.append("-Dsonar.java.libraries=%s" % os.environ.get("SONAR_LIB"))
            if os.environ.get("SONAR_JAVA_VERSION", None):
                scan_cmd.append("-Dsonar.java.source=%s" % os.environ.get("SONAR_JAVA_VERSION"))
            scan_cmd = self._change_to_win_cmd(scan_cmd)
            self.run_cmd(command=scan_cmd, cwd=build_cwd, cmd_type="analyze")

            if self.scannerwork and os.path.exists(self.scannerwork):
                return os.path.join(self.scannerwork, "report-task.txt")
            return os.path.join(build_cwd, ".scannerwork", "report-task.txt")

        elif build_type.lower() in ("gradle",):
            if not build_cmd:
                self._raise_error(msg="SQ工具执行Java静态分析时候需要输入编译命令，请填入编译命令后重试。", err_type="compile")
            self.run_cmd(
                command=self._change_to_win_cmd(shlex.split(build_cmd) + ["sonarqube"] + self.com_cmd),
                cwd=build_cwd,
                cmd_type="compile",
            )

            if self.scannerwork and os.path.exists(self.scannerwork):
                return os.path.join(self.scannerwork, "report-task.txt")
            return os.path.join(build_cwd, "build", "sonar", "report-task.txt")

        elif build_type.lower() in ("maven", "mvn"):
            compile_cmd = list()
            if build_cmd:
                compile_cmd = shlex.split(build_cmd)
            else:
                print("[warning] 没有检测到编译命令，尝试使用默认编译命令。")
                compile_cmd = ["mvn"]
            compile_cmd.extend(["sonar:sonar", "-Dsonar.java.binaries=%s" % os.environ.get("SONAR_BIN", "**/*")])
            compile_cmd.extend(self.com_cmd)
            self.run_cmd(command=self._change_to_win_cmd(compile_cmd), cwd=build_cwd, cmd_type="compile")

        elif build_type.lower() in ("ant",):
            if not build_cmd:
                self._raise_error(msg="SQ工具执行Java静态分析时候需要输入编译命令，请填入编译命令后重试。", err_type="compile")
            self.run_cmd(
                command=self._change_to_win_cmd(["ant", "sonar", "-v"] + self.com_cmd),
                cwd=build_cwd,
                cmd_type="compile",
            )

        else:
            self._raise_error(
                "设置SONAR_BUILD_TYPE异常: 当前SQJava仅支持设置SONAR_BUILD_TYPE为no_build、gradle、maven或ant模式，请检查是否设置错误。",
                err_type="config",
            )

    def scan_cs_proj(self, build_cmd, build_cwd):
        if not build_cmd:
            self._raise_error(msg="SQ工具执行C#静态分析时候需要输入编译命令，请填入编译命令后重试。", err_type="compile")
        # 1. “classic” .NET Framework
        scan_cmd = [
            "SonarScanner.MSBuild.exe",
            "begin",
        ] + self.change_to_vs_cmd(self.com_cmd)
        self.run_cmd(command=scan_cmd, cwd=build_cwd, cmd_type="compile")
        self.run_cmd(command=shlex.split(self.generate_shell_file(build_cmd)), cwd=build_cwd, cmd_type="compile")
        self.run_cmd(
            command=[
                "SonarScanner.MSBuild.exe",
                "end",
                '/d:sonar.login="%s"' % self.user,
                '/d:sonar.password="%s"' % self.password,
            ],
            cwd=build_cwd,
            cmd_type="analyze",
        )
        if self.scannerwork and os.path.exists(self.scannerwork):
            return os.path.join(self.scannerwork, "report-task.txt")
        return os.path.join(build_cwd, ".sonarqube", "out", ".sonar", "report-task.txt")

        # TODO: 2. for .NET Core

    def scan_not_build_proj(self, build_cwd):
        scan_cmd = [
            "sonar-scanner",
            "-X",
            "-Dsonar.sources=%s" % os.environ.get("SONAR_SRC", "."),
            "-Dsonar.java.binaries=%s" % os.environ.get("SONAR_BIN", "**/*"),
        ] + self.com_cmd
        analyze_options = os.environ.get("SQ_ANALYZE_OPTIONS", "")
        if analyze_options:
            # -Dsonar.javascript.globals=
            # -Dsonar.javascript.environments=
            scan_cmd.extend(analyze_options.split())
        scan_cmd = self._change_to_win_cmd(scan_cmd)
        self.run_cmd(command=scan_cmd, cwd=build_cwd, cmd_type="analyze")

        if self.scannerwork and os.path.exists(self.scannerwork):
            return os.path.join(self.scannerwork, "report-task.txt")
        return os.path.join(build_cwd, ".scannerwork", "report-task.txt")

    def _sonar_path_filter(self, path_list):
        temp = list()
        for path in path_list:
            temp.append(path.replace("*", "***"))
        return temp

    def _sonar_regex_path_filter(self, path_list):
        temp = list()
        for path in path_list:
            temp.append(path.replace(".*", "***"))
        return temp

    def _add_sonar_filter_path(self):
        path_wild_exclude = self.params["path_filters"].get("wildcard_exclusion", [])
        path_wild_include = self.params["path_filters"].get("wildcard_inclusion", [])
        path_re_exclude = self.params["path_filters"].get("re_exclusion", [])
        path_re_include = self.params["path_filters"].get("re_inclusion", [])
        path_yaml_filters = self.params["path_filters"].get("yaml_filters", {})
        path_yaml_exclude = path_yaml_filters.get("lint_exclusion", [])
        path_yaml_include = path_yaml_filters.get("lint_inclusion", [])

        sonar_include = list()
        if path_wild_include:
            sonar_include.extend(self._sonar_path_filter(path_wild_include))
        if path_re_include:
            sonar_include.extend(self._sonar_regex_path_filter(path_re_include))
        if path_yaml_include:
            sonar_include.extend(self._sonar_regex_path_filter(path_yaml_include))
        sonar_exclude = list()
        if path_wild_exclude:
            sonar_exclude.extend(self._sonar_path_filter(path_wild_exclude))
        if path_re_exclude:
            sonar_exclude.extend(self._sonar_regex_path_filter(path_re_exclude))
        if path_yaml_exclude:
            sonar_exclude.extend(self._sonar_regex_path_filter(path_yaml_exclude))

        if sonar_include:
            self.com_cmd.append('-Dsonar.inclusions="%s"' % ",".join(sonar_include))
        if sonar_exclude:
            self.com_cmd.append('-Dsonar.exclusions="%s"' % ",".join(sonar_exclude))


tool = SonarQube

if __name__ == "__main__":
    pass
