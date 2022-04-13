#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Copyright (c) 2022 THL A29 Limited
#
# This source code file is made available under LGPL License
# See LICENSE for details
# ==============================================================================


import operator
import requests
import logging

from util.exceptions import ClientError, ServerError, AuthError, ValidationError

logging.getLogger("requests").setLevel(logging.WARNING)


class SQAPIHandler(object):
    def __init__(self, host="http://localhost", port=9000, base_path="", user=None, password=None, token=None):
        self._host = host
        self._port = port
        self._base_path = base_path
        self._session = requests.Session()
        # auth
        if token:
            self._session.auth = token, ""
        elif user and password:
            self._session.auth = user, password

    def _get_url(self, endpoint):
        return f"{self._host}:{self._port}{self._base_path}{endpoint}"

    def _request(self, method, endpoint, files=None, **data):
        call = getattr(self._session, method.lower())
        url = self._get_url(endpoint)
        res = call(url, data=data or {}, files=files)

        if res.status_code < 300:
            # OK, return http response
            return res
        elif res.status_code == 400:
            # Validation error
            msg = ", ".join(e["msg"] for e in res.json()["errors"])
            raise ValidationError(msg)
        elif res.status_code in (401, 403):
            # Auth error
            raise AuthError(res.reason)
        elif res.status_code < 500:
            # Other 4xx, generic client error
            raise ClientError(res.reason)
        else:
            # 5xx is server error
            raise ServerError(res.reason)

    def activate_rule(self, key, profile_key, reset=False, severity=None, **params):
        data = {"rule_key": key, "profile_key": profile_key, "reset": reset and "true" or "false"}

        if not reset:
            if severity:
                data["severity"] = severity.upper()

            params = ";".join(f"{k}={v}" for k, v in sorted(params.items()) if v)
            if params:
                data["params"] = params

        res = self._request("post", "/api/qualityprofiles/activate_rule", **data)
        return res

    def create_rule(self, key, name, description, message, xpath, severity, status, template_key):
        data = {
            "custom_key": key,
            "name": name,
            "markdown_description": description,
            "params": f"message={message};xpathQuery={xpath}",
            "severity": severity.upper(),
            "status": status.upper(),
            "template_key": template_key,
        }

        res = self._request("post", "/api/rules/create", **data)
        return res

    def get_metrics(self, fields=None):
        qs = {}
        if fields:
            if not isinstance(fields, str):
                fields = ",".join(fields)
            qs["f"] = fields.lower()

        page_num = 1
        page_size = 1
        n_metrics = 2

        while page_num * page_size < n_metrics:
            res = self._request("get", "/api/metrics/search", **qs).json()
            page_num = res["p"]
            page_size = res["ps"]
            n_metrics = res["total"]

            qs["p"] = page_num + 1

            for metric in res["metrics"]:
                yield metric

    def get_rules(self, active_only=False, profile=None, languages=None, custom_only=False, f=None):
        qs = {"is_template": "no", "statuses": "READY"}

        if profile:
            qs.update({"activation": "true", "qprofile": profile})
        elif active_only:
            qs["activation"] = "true"

        if languages:
            if not isinstance(languages, str):
                languages = ",".join(languages)
            qs["languages"] = languages.lower()

        if custom_only:
            qs["has_debt_characteristic"] = "false"
        
        if f:
            qs["f"] = f

        page_num = 1
        page_size = 1
        n_rules = 2
        while page_num * page_size < n_rules:
            res = self._request("post", "/api/rules/search", **qs).json()
            page_num = res["p"]
            page_size = res["ps"]
            n_rules = res["total"]
            qs["p"] = page_num + 1

            for rule in res["rules"]:
                yield rule

    def rules_show(self, key, actives=None):
        params = {"key": key}
        if actives is not None:
            params["actives"] = actives
        res = self._request("post", "/api/rules/show", **params).json()
        return res

    def get_resources_debt(self, resource=None, categories=None, include_trends=False, include_modules=False):
        DEBT_METRICS = ("sqale_index",)
        DEBT_CHARACTERISTICS = (
            "TESTABILITY",
            "RELIABILITY",
            "CHANGEABILITY",
            "EFFICIENCY",
            "USABILITY",
            "SECURITY",
            "MAINTAINABILITY",
            "PORTABILITY",
            "REUSABILITY",
        )

        params = {
            "model": "SQALE",
            "metrics": ",".join(DEBT_METRICS),
            "characteristics": ",".join(categories or DEBT_CHARACTERISTICS).upper(),
        }
        if resource:
            params["resource"] = resource
        if include_trends:
            params["includetrends"] = "true"
        if include_modules:
            params["qualifiers"] = "TRK,BRC"

        res = self._request("get", "/api/resources", **params).json()

        for prj in res:
            yield prj

    def get_resources_metrics(self, resource=None, metrics=None, include_trends=False, include_modules=False):
        GENERAL_METRICS = (
            # SQUALE metrics
            "sqale_index",
            "sqale_debt_ratio",
            # Violations
            "violations",
            "blocker_violations",
            "critical_violations",
            "major_violations",
            "minor_violations",
            # Coverage
            "lines_to_cover",
            "conditions_to_cover",
            "uncovered_lines",
            "uncovered_conditions",
            "coverage",
        )

        params = {}
        if not metrics:
            metrics = GENERAL_METRICS
        if resource:
            params["resource"] = resource
        if include_trends:
            params["includetrends"] = "true"
            metrics.extend([f"new_{m}" for m in metrics])
        if include_modules:
            params["qualifiers"] = "TRK,BRC"
        params["metrics"] = ",".join(metrics)

        res = self._request("get", "/api/resources", **params).json()

        for prj in res:
            yield prj

    def get_resources_full_data(
        self, resource=None, metrics=None, categories=None, include_trends=False, include_modules=False
    ):
        prjs = {
            prj["key"]: prj
            for prj in self.get_resources_metrics(
                resource=resource, metrics=metrics, include_trends=include_trends, include_modules=include_modules
            )
        }

        for prj in self.get_resources_debt(
            resource=resource, categories=categories, include_trends=include_trends, include_modules=include_modules
        ):
            if prj["key"] in prjs:
                prjs[prj["key"]]["msr"].extend(prj["msr"])
            else:
                prjs[prj["key"]] = prj

        for _, prj in sorted(prjs.items(), key=operator.itemgetter(0)):
            yield prj

    def validate_authentication(self):
        res = self._request("get", "/api/authentication/validate").json()
        return res.get("valid", False)

    def project_create(self, name, project):
        params = {"name": name, "project": project}
        res = self._request("post", "/api/projects/create", **params).json()
        return res

    def project_delete(self, project_key):
        params = {"project": project_key}
        res = self._request("post", "/api/projects/delete", **params)
        return res

    def get_project(self, projects=None, onProvisionedOnly=None, analyzedBefore=None, qualifiers=None, q=None):
        params = dict()

        if projects is not None:
            params["projects"] = projects
        if onProvisionedOnly is not None:
            params["onProvisionedOnly"] = onProvisionedOnly
        if analyzedBefore is not None:
            params["analyzedBefore"] = analyzedBefore
        if qualifiers is not None:
            params["qualifiers"] = qualifiers
        if q is not None:
            params["q"] = q

        page_num = 1
        page_size = 1
        n_projects = 2

        while page_num * page_size < n_projects:
            res = self._request("post", "/api/projects/search", **params).json()
            paging = res["paging"]
            page_num = paging["pageIndex"]
            page_size = paging["pageSize"]
            n_projects = paging["total"]

            params["p"] = page_num + 1

            for project in res["components"]:
                yield project

    def get_issues(self, languages=None, componentKeys=None, rules=None):
        params = dict()

        if languages:
            if not isinstance(languages, str):
                languages = ",".join(languages)
            params["languages"] = languages.lower()
        if componentKeys is not None:
            params["componentKeys"] = componentKeys
        if rules is not None:
            params["rules"] = rules

        page_num = 1
        page_size = 1
        n_issues = 2

        while page_num * page_size < n_issues:
            res = self._request("post", "/api/issues/search", **params).json()
            page_num = res["p"]
            page_size = res["ps"]
            n_issues = res["total"]

            params["p"] = page_num + 1

            for issue in res["issues"]:
                yield issue

    def duplications_show(self, key):
        params = {"key": key}
        res = self._request("post", "/api/duplications/show", **params).json()
        return res

    def ce_task(self, id_, additionalFields=None):
        params = {"id": id_}
        if additionalFields is not None:
            params["additionalFields"] = additionalFields
        res = self._request("post", "/api/ce/task", **params).json()
        return res

    def languages_list(self):
        res = self._request("get", "/api/languages/list").json()
        return res

    def get_system_status(self):
        res = self._request("get", "/api/system/status").json()
        return res

    def set_settings(self, key, value=None, values=None, component=None, fieldValues=None):
        params = {"key": key}
        if value is not None:
            params["value"] = value
        if values is not None:
            params["values"] = values
        if component is not None:
            params["component"] = component
        if fieldValues is not None:
            params["fieldValues"] = fieldValues
        res = self._request("post", "/api/settings/set", **params)
        return res

    def get_settings(self, keys=None, component=None):
        params = dict()
        if keys is not None:
            params["keys"] = keys
        if component is not None:
            params["component"] = component
        res = self._request("get", "/api/settings/values", **params)
        return res

    def get_component_measures(self, metricKeys, component, additionalFields=None):
        params = {"metricKeys": metricKeys, "component": component}
        if additionalFields is not None:
            params["additionalFields"] = additionalFields
        res = self._request("post", "/api/measures/component", **params).json()
        return res

    def qualityprofiles_search(self, project=None, language=None, qualityProfile=None, defaults=None):
        params = dict()
        if project is not None:
            params["project"] = project
        if language is not None:
            params["language"] = language.lower()
        if qualityProfile is not None:
            params["qualityProfile"] = qualityProfile
        if defaults is not None:
            params["defaults"] = defaults
        res = self._request("get", "/api/qualityprofiles/search", **params).json()
        return res

    def qualityprofiles_add_project(self, project, language, qualityProfile):
        params = {"project": project, "language": language.lower(), "qualityProfile": qualityProfile}
        res = self._request("post", "/api/qualityprofiles/add_project", **params)
        return res

    def qualityprofiles_remove_project(self, project, language, qualityProfile):
        params = {"project": project, "language": language.lower(), "qualityProfile": qualityProfile}
        res = self._request("post", "/api/qualityprofiles/remove_project", **params)
        return res

    def qualityprofiles_backup(self, language=None, qualityProfile=None):
        params = dict()
        if language is not None:
            params["language"] = language.lower()
        if qualityProfile is not None:
            params["qualityProfile"] = qualityProfile
        res = self._request("post", "/api/qualityprofiles/backup", **params)
        return res

    def qualityprofiles_restore(self, backup):
        """
        Restore a quality profile using an XML file.
        The restored profile name is taken from the backup file, so if a profile with the same name and language already exists, it will be overwritten.
        Example:
        curl -v POST -u test:test "http://localhost:9000/api/qualityprofiles/restore" --form backup=@/xxx/AWvZrR4RTp-uPcviwgpP.xml
        :param backup: backup path
        :return:
        """
        files = {"backup": open(backup, "rb")}
        res = self._request("post", "/api/qualityprofiles/restore", files=files)
        return res

    def qualityprofiles_export(self, exporterKey=None, language=None, qualityProfile=None):
        """
        Export a quality profile.
        :param exporterKey:
        :param language:
        :param qualityProfile:
        :return:
        """
        params = dict()
        if exporterKey is not None:
            params["exporterKey"] = exporterKey
        if language is not None:
            params["language"] = language.lower()
        if qualityProfile is not None:
            params["qualityProfile"] = qualityProfile
        res = self._request("get", "/api/qualityprofiles/export", **params)
        return res

    def qualityprofiles_create(self, name, language):
        """
        Create a quality profile.
        :param name:
        :param language:
        :return:
        """
        params = {"name": name, "language": language}
        res = self._request("post", "/api/qualityprofiles/create", **params).json()
        return res

    def qualityprofiles_delete(self, language=None, qualityProfile=None):
        """
        Delete a quality profile and all its descendants. The default quality profile cannot be deleted.
        :param language:
        :param qualityProfile:
        :return:
        """
        params = dict()
        if language is not None:
            params["language"] = language.lower()
        if qualityProfile is not None:
            params["qualityProfile"] = qualityProfile
        res = self._request("post", "/api/qualityprofiles/delete", **params)
        return res

    def qualityprofiles_projects(self, key, q=None):
        """
        List projects with their association status regarding a quality profile
        :param key:
        :param q: limit search to projects that contain the supplied string.
        :return:
        """
        params = {"key": key}
        if q is not None:
            params["q"] = q

        page_num = 1
        page_size = 1
        n_projects = 2

        while page_num * page_size < n_projects:
            res = self._request("post", "/api/qualityprofiles/projects", **params).json()
            paging = res["paging"]
            page_num = paging["pageIndex"]
            page_size = paging["pageSize"]
            n_projects = paging["total"]

            params["p"] = page_num + 1

            for project in res["results"]:
                yield project


if __name__ == "__main__":
    pass
