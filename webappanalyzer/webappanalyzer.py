import pathlib
import re
import string
from typing import Optional, Any, Union

import ijson
import requests

from webappanalyzer.web_page import WebPage


class WebAppAnalyzer:
    def __init__(self, update: bool = False, path: pathlib.Path = pathlib.Path("data")):
        self._json_path: pathlib.Path = path
        path.mkdir(parents=True, exist_ok=True)

        json_list = list(string.ascii_lowercase)
        json_list.append("_")

        if len(list(path.iterdir())) != len(json_list) or update:
            for j in json_list:
                with requests.get(f"https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{j}.json", stream=True) as r:
                    with path.joinpath(f"{j}.json").open("wb") as t:
                        for chunk in r.iter_content(chunk_size=8192):
                            t.write(chunk)

        self.version_regexp = re.compile(r"^(?:(?P<prefix>.*)?\\(?P<group>\d+)(?:\?(?P<first>.*)?:(?P<second>.*)?)?|(?P<fixed>[a-zA-Z0-9.]+)?)$")
        cpe_regex: str = r"""cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}"""
        self._cpe_pattern: re.Pattern = re.compile(cpe_regex)

    def analyze(self, webpage: WebPage):
        detected: list[dict] = []
        for file in self._json_path.iterdir():
            with file.open("rb") as techs:
                for technology, content in ijson.kvitems(techs, ""):
                    detectors: dict[str, list] = self._prepare_detectors(content)
                    detection_result: dict[str, Any] = self.detect(detectors, webpage)
                    if detection_result.get("match"):
                        detected.append({
                            "tech": technology,
                            "confidence": min(detection_result.get('confidence'), 100),
                            "cpe": content.get('cpe'),
                            "implies": detectors.get('implies'),
                            "requires": [impl.lower() for impl in content.get("requires", [])],
                            "versions": detection_result.get("versions")
                        })
        resync: bool = True
        while resync:
            resync: bool = False
            check_implies: bool = True
            to_add: set[str] = set()
            while check_implies:
                check_implies: bool = False
                for tech in detected.copy():
                    if tech.get("confidence") == 100:
                        for sub in tech.get("implies"):
                            found: bool = False
                            for t in detected:
                                if t.get("tech").lower() == sub.lower():
                                    found: bool = True
                                    if t.get("confidence") < 100:
                                        check_implies: bool = True
                                        t["confidence"] = 100
                                    continue
                            if not found:
                                to_add.add(sub.lower())
            for new_tech in to_add:
                initial: str = new_tech[0] if new_tech[0] in string.ascii_lowercase else "_"
                with self._json_path.joinpath(f"{initial}.json").open("rb") as tech_file:
                    for technology, content in ijson.kvitems(tech_file, ""):
                        if technology.lower() == new_tech.lower():
                            resync: bool = True
                            detected.append({
                                "tech": technology,
                                "confidence": 100,
                                "cpe": content.get("cpe"),
                                "implies": [impl.lower() for impl in content.get("implies", [])],
                                "requires": [impl.lower() for impl in content.get("requires", [])],
                                "versions": []
                            })
            to_add.clear()

        tech_names: set[str] = {tech.get("tech").lower() for tech in detected}

        clean_detections: list[dict] = []
        for d in detected:
            if d.get("confidence") < 100:
                continue
            contains_required: bool = not d.get("requires")
            for required in d.get("requires"):
                if required.lower() in tech_names:
                    contains_required: bool = True
            if not contains_required:
                continue
            d["version"] = None if not d.get("versions") else d.get("versions")[0]
            d.pop("implies")
            d.pop("confidence")
            d.pop("versions")
            d.pop("requires")
            if d.get("cpe") and d["version"]:
                d["cpe"] = ":".join(d["cpe"].split(":")[:5]+[d["version"]]+d["cpe"].split(":")[6:])
                if not self._is_cpe_valid(d.get("cpe")):
                    d.pop("cpe")
            clean_detections.append(d)
        return clean_detections

    def detect(self, technology_detectors: dict[str, list], webpage: WebPage) -> dict[str, Any]:
        match: bool = False
        confidence: int = 0
        versions: set[str] = set()
        for element in technology_detectors.get("headers"):
            header_match: bool = element.get("name") in webpage.headers
            value_required: bool = element.get("attributes").get("string") is not None or element.get("attributes").get("regex") is not None
            value: str = webpage.headers.get(element.get("name"))
            if value_required and value:
                result: dict[str, Any] = self._validate_value(value, element.get("attributes"), element.get("extra_tags"))
                if result.get("is_match"):
                    match: bool = True
                    confidence += result.get("confidence")
                    versions.add(result.get("version"))
            elif header_match and not value_required:
                match: bool = True
                confidence += 0 if not header_match else element.get("extra_tags").get("confidence")
        for element in technology_detectors.get("meta"):
            for web_meta in webpage.meta:
                meta_match: bool = element.get("name") in web_meta
                value_required: bool = element.get("attributes").get("string") is not None or element.get("attributes").get("regex") is not None
                value: str = web_meta.get(element.get("name"))
                if value_required and value:
                    result: dict[str, Any] = self._validate_value(value, element.get("attributes"), element.get("extra_tags"))
                    if result.get("is_match"):
                        match: bool = True
                        confidence += result.get("confidence")
                        versions.add(result.get("version"))
                elif meta_match and not value_required:
                    match: bool = True
                    confidence += 0 if not meta_match else element.get("extra_tags").get("confidence")
        for element in technology_detectors.get("cookies"):
            cookie_match: bool = element.get("name") in webpage.cookies
            value_required: bool = element.get("attributes").get("string") is not None or element.get("attributes").get("regex") is not None
            value: str = webpage.cookies.get(element.get("name"))
            if value_required and value:
                result: dict[str, Any] = self._validate_value(value, element.get("attributes"), element.get("extra_tags"))
                if result.get("is_match"):
                    match: bool = True
                    confidence += result.get("confidence")
                    versions.add(result.get("version"))
            elif cookie_match and not value_required:
                match: bool = True
                confidence += 0 if not cookie_match else element.get("extra_tags").get("confidence")
        for element in technology_detectors.get("url"):
            result: dict[str, Any] = self._validate_value(webpage.url, element.get("attributes"), element.get("extra_tags"))
            if result.get("is_match"):
                match: bool = True
                confidence += result.get("confidence")
                versions.add(result.get("version"))
        for element in technology_detectors.get("html"):
            result: dict[str, Any] = self._validate_value(webpage.parsed_html.text, element.get("attributes"), element.get("extra_tags"))
            if result.get("is_match"):
                match: bool = True
                confidence += result.get("confidence")
                versions.add(result.get("version"))
        for element in technology_detectors.get("scriptSrc"):
            for script in webpage.scripts:
                result: dict[str, Any] = self._validate_value(script, element.get("attributes"), element.get("extra_tags"))
                if result.get("is_match"):
                    match: bool = True
                    confidence += result.get("confidence")
                    versions.add(result.get("version"))
        for selector_data in technology_detectors.get("selector"):
            selector: str = selector_data.get("selector")
            for obj in webpage.parsed_html.select(selector):
                tag: str = selector_data.get("tag")
                if tag == "attribute":
                    attribute: str = selector_data.get("attribute_name")
                    if not obj.has_attr(attribute):
                        continue
                    attr_value = obj.get(attribute)
                    if isinstance(attr_value, str):
                        attr_value = [attr_value]
                    for value in attr_value:
                        detector_value: bool = selector_data.get("attribute_value").get("attributes").get("string")
                        result: dict[str, Any] = self._validate_value("" if not detector_value else value, selector_data.get("attribute_value").get("attributes"), selector_data.get("attribute_value").get("extra_tags"))
                        if result.get("is_match"):
                            match: bool = True
                            confidence += result.get("confidence")
                            versions.add(result.get("version"))
                elif tag == "property":
                    property_: str = selector_data.get("property_name")
                    if not obj.has_attr(property_):
                        continue
                    property_value = obj.get(property_)
                    if isinstance(property_value, str):
                        property_value = [property_value]
                    for value in property_value:
                        detector_value: bool = selector_data.get("property_value").get("attributes").get("string")
                        result: dict[str, Any] = self._validate_value("" if not detector_value else value, selector_data.get("property_value").get("attributes"), selector_data.get("property_value").get("extra_tags"))
                        if result.get("is_match"):
                            match: bool = True
                            confidence += result.get("confidence")
                            versions.add(result.get("version"))
                elif tag == "text":
                    result: dict[str, Any] = self._validate_value(obj.get_text(), selector_data.get("text_value").get("attributes"), selector_data.get("text_value").get("extra_tags"))
                    if result.get("is_match"):
                        match: bool = True
                        confidence += result.get("confidence")
                        versions.add(result.get("version"))
                elif tag == "literal":
                    result: dict[str, Any] = self._validate_value("", selector_data.get("literal_value").get("attributes"), selector_data.get("literal_value").get("extra_tags"))
                    if result.get("is_match"):
                        match: bool = True
                        confidence += result.get("confidence")
                        versions.add(result.get("version"))
        return {
            "match": match,
            "confidence": confidence,
            "versions": sorted(set(version for version in versions if version), key=self._cmp_to_key(self._sort_app_versions))
        }

    def _validate_value(self, value: str, attributes: dict[str, Any], extra_tags: dict[str, Any]) -> dict[str, Any]:
        match: Optional[re.Match] = None
        version: Optional[str] = None
        if not attributes.get("string"):
            is_match: bool = True
        elif not attributes.get("regex"):
            is_match: bool = value == attributes.get("string")
        else:
            match: re.Match = attributes.get("regex").search(value)
            is_match: bool = match is not None
            if is_match and extra_tags.get("version") is not None:
                version: Optional[str] = self._format_version(match, extra_tags.get("version"))
        return {
            "is_match": is_match,
            "match": match,
            "version": version,
            "confidence": 0 if not is_match else extra_tags.get("confidence")
        }

    def _is_cpe_valid(self, cpe: str) -> bool:
        return not not self._cpe_pattern.match(cpe)

    def _format_version(self, current_match: re.Match, version: str) -> Optional[str]:
        data: re.Match = self.version_regexp.match(version)
        version_detected = current_match.group(int(data.group("group")))
        final_version: Optional[str] = None
        if data.group("fixed"):
            return data.group("fixed")
        if version_detected:
            if data.group("first"):
                final_version: Optional[str] = data.group("first")
        else:
            if data.group("second"):
                final_version: Optional[str] = data.group("second")
        if not data.group("first") and not data.group("second") and version_detected and data.group("prefix"):
            final_version: Optional[str] = data.group("prefix")+version_detected
        if version_detected and not data.group("first") and not data.group("second") and not data.group("prefix"):
            final_version: Optional[str] = version_detected
        if not final_version:
            final_version: Optional[str] = None
        return final_version

    def _prepare_detectors(self, tech_content: dict):
        clean: dict[str, list] = {}
        clean["headers"] = self._process_object(tech_content.get("headers", {}))
        clean["meta"] = self._process_object(tech_content.get("meta", {}))
        clean["cookies"] = self._process_object(tech_content.get("cookies", {}))
        clean["url"] = self._process_list(tech_content.get("url", []))
        clean["html"] = self._process_list(tech_content.get("html", []))
        clean["scriptSrc"] = self._process_list(tech_content.get("scriptSrc", []))
        clean["implies"] = [impl.lower() for impl in tech_content.get("implies", [])]
        clean["requires"] = [impl.lower() for impl in tech_content.get("requires", [])]
        clean["selector"] = self._process_dom(tech_content.get("dom", []))
        return clean

    def _process_dom(self, detector: Union[list, dict]) -> list[dict]:
        parsed: list[dict] = []
        if isinstance(detector, list):
            for selector in detector:
                clean: dict[str, Any] = {"tag": "literal"}
                clean["literal_value"] = self._process_value(selector)
                clean["selector"] = clean.get("literal_value").get("attributes").get("string")
                clean["literal_value"]["attributes"]["string"] = None
                clean["literal_value"]["attributes"]["regex"] = None
                parsed.append(clean)
        elif isinstance(detector, dict):
            for selector, extra in detector.items():
                for tag, tag_value in extra.items():
                    if tag == "attributes":
                        for attribute_name, attribute_value in tag_value.items():
                            clean: dict[str, Any] = {"selector": selector, "tag": "attribute"}
                            clean["attribute_name"] = attribute_name
                            clean["attribute_value"] = self._process_value(attribute_value)
                            parsed.append(clean)
                    elif tag == "properties":
                        for attribute_name, attribute_value in tag_value.items():
                            clean: dict[str, Any] = {"selector": selector, "tag": "property"}
                            clean["property_name"] = attribute_name
                            clean["property_value"] = self._process_value(attribute_value)
                            parsed.append(clean)
                    elif tag == "text":
                        clean: dict[str, Any] = {"selector": selector, "tag": "text"}
                        clean["text_value"] = self._process_value(tag_value)
                        parsed.append(clean)
                    elif tag == "exists":
                        clean: dict[str, Any] = {"tag": "literal"}
                        clean["selector"] = selector
                        clean["literal_value"] = self._process_value("")
                        clean["literal_value"]["attributes"]["string"] = None
                        clean["literal_value"]["attributes"]["regex"] = None
                        parsed.append(clean)
        return parsed

    def _process_list(self, detector: list[str]) -> list[dict]:
        parsed: list[dict] = []
        for pattern in detector:
            parsed.append(self._process_value(pattern))
        return parsed

    def _process_object(self, detector: dict[str, str]) -> list[dict]:
        parsed: list[dict] = []
        for name, pattern in detector.items():
            detect: dict[str, Any] = {
                "name": name,
            }
            detect.update(self._process_value(pattern))
            parsed.append(detect)
        return parsed

    def _process_value(self, pattern: str) -> dict[str, Any]:
        split: list[str] = pattern.split(r"\;")
        value: str = split[0] if split[0] else None
        extra_tags: dict[str, Optional[str]] = self._parse_extra_tag(split[1:])
        try:
            if value:
                compiled: Optional[re.Pattern[str]] = re.compile(value, re.I)
            else:
                compiled: Optional[re.Pattern[str]] = None
        except re.error:
            compiled: Optional[re.Pattern[str]] = None
        return {
            "attributes": {
                "string": value,
                "regex": compiled
            },
            "extra_tags": extra_tags
        }

    @staticmethod
    def _parse_extra_tag(extra_tag: list[str]) -> dict[str, Optional[str]]:
        parsed: dict[str, Optional[str|int]] = {
            "version": None,
            "confidence": None
        }
        for extra in extra_tag:
            if extra.lower().startswith("version"):
                parsed["version"] = extra.lower().removeprefix("version:")
            elif extra.lower().startswith("confidence"):
                parsed["confidence"] = int(extra.lower().removeprefix("confidence:"))
        parsed["confidence"] = parsed["confidence"] if parsed["confidence"] is not None else 100
        return parsed

    @classmethod
    def _sort_app_versions(cls, version_a, version_b):
        return len(version_a) - len(version_b)

    def _cmp_to_key(self, mycmp):
        class CmpToKey:
            def __init__(self, obj, *args):
                self.obj = obj

            def __lt__(self, other):
                return mycmp(self.obj, other.obj) < 0

            def __gt__(self, other):
                return mycmp(self.obj, other.obj) > 0

            def __eq__(self, other):
                return mycmp(self.obj, other.obj) == 0

            def __le__(self, other):
                return mycmp(self.obj, other.obj) <= 0

            def __ge__(self, other):
                return mycmp(self.obj, other.obj) >= 0

            def __ne__(self, other):
                return mycmp(self.obj, other.obj) != 0

        return CmpToKey
