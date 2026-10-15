#!/usr/bin/env python3
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET


def extract_tag(elem):
    return elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag


def parse_cves(metadata):
    cves_list = []
    seen_cve_ids = set()

    for elem in metadata.iter():
        if extract_tag(elem) == "cve":
            cve_id = elem.text.strip() if elem.text else ""
            if not cve_id and "href" in elem.attrib:
                m = re.search(r"(CVE-\d{4}-\d+)", elem.attrib["href"])
                if m:
                    cve_id = m.group(1)

            if not cve_id or cve_id in seen_cve_ids:
                continue
            seen_cve_ids.add(cve_id)

            cvss_raw = ""
            for attr_name in ["cvss3.1", "cvss31", "cvss3", "cvss2", "cvss"]:
                if attr_name in elem.attrib:
                    cvss_raw = elem.attrib[attr_name]
                    break

            if not cvss_raw:
                for attr, val in elem.attrib.items():
                    if "cvss" in attr.lower():
                        cvss_raw = val
                        break

            cvss_score = ""
            cvss_vector = ""

            if "/" in cvss_raw:
                parts = cvss_raw.split("/", 1)
                cvss_score = parts[0]
                cvss_vector = parts[1]
            elif cvss_raw:
                cvss_score = cvss_raw

            cve_entry = {"cve_id": cve_id}
            if cvss_score:
                cve_entry["cvss_score"] = cvss_score
            if cvss_vector:
                cve_entry["cvss_vector"] = cvss_vector

            cves_list.append(cve_entry)

    return cves_list


def parse_platforms(metadata):
    platforms = []
    for platform in metadata.iter():
        if extract_tag(platform) == "platform" and platform.text:
            text = platform.text.strip()
            if "Red Hat Enterprise Linux 8" in text:
                platforms.append("RHEL-8")
            elif "CoreOS" in text:
                platforms.append("RHCOS-4")
            else:
                platforms.append(text)
    return list(dict.fromkeys(platforms))


def parse_oval(file_path, limit=5):
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except FileNotFoundError:
        sys.exit(f"Ошибка: файл не найден по пути '{file_path}'")
    except PermissionError:
        sys.exit(f"Ошибка: нет прав на чтение файла '{file_path}'")
    except ET.ParseError as e:
        sys.exit(f"Ошибка синтаксиса XML в файле '{file_path}': {e}")

    tests_idx = {}
    objects_idx = {}
    states_idx = {}

    for elem in root.iter():
        tag = extract_tag(elem)
        elem_id = elem.attrib.get("id")
        if not elem_id:
            continue
        if tag.endswith("_test"):
            tests_idx[elem_id] = elem
        elif tag.endswith("_object"):
            objects_idx[elem_id] = elem
        elif tag.endswith("_state"):
            states_idx[elem_id] = elem

    parsed_vulnerabilities = []

    for def_elem in root.iter():
        if extract_tag(def_elem) != "definition":
            continue

        def_id = def_elem.attrib.get("id", "")
        m_id = re.search(r"def:(\d{4})(\d+)", def_id)
        if m_id:
            prefix = "RHSA" if "rhsa" in def_id else ("RHEA" if "rhea" in def_id else "RHBA")
            clean_id = f"{prefix}-{m_id.group(1)}:{m_id.group(2)}"
        else:
            clean_id = def_id

        metadata = def_elem.find(".//{*}metadata")
        title = ""
        severity = "Unknown"
        cves = []
        platforms = []

        if metadata is not None:
            title_elem = metadata.find("{*}title")
            if title_elem is not None and title_elem.text:
                title = title_elem.text.strip()

            advisory = metadata.find("{*}advisory")
            if advisory is not None:
                sev_elem = advisory.find("{*}severity")
                if sev_elem is not None and sev_elem.text:
                    severity = sev_elem.text.strip()

            cves = parse_cves(metadata)
            platforms = parse_platforms(metadata)

        rules = []
        module_stream = None
        has_signed_check = False
        signed_by = None

        criteria = def_elem.find(".//{*}criteria")
        if criteria is not None:
            for crit in criteria.iter():
                if extract_tag(crit) != "criterion":
                    continue

                test_ref = crit.attrib.get("test_ref", "")
                if not test_ref or test_ref not in tests_idx:
                    continue

                test_elem = tests_idx[test_ref]
                test_tag = extract_tag(test_elem)

                # Обработка модульных стримов AppStream
                comment = crit.attrib.get("comment", "")
                mod_match = re.search(r"Module\s+([a-zA-Z0-9_\-]+:[0-9.]+)\s+is enabled", comment)
                if mod_match:
                    module_stream = mod_match.group(1)
                    continue

                obj_ref_elem = test_elem.find(".//{*}object")
                ste_ref_elem = test_elem.find(".//{*}state")

                pkg_name = None
                fixed_ver = None
                op_name = "less_than"

                if obj_ref_elem is not None:
                    obj_id = obj_ref_elem.attrib.get("object_ref")
                    if obj_id in objects_idx:
                        obj_node = objects_idx[obj_id]
                        name_node = obj_node.find(".//{*}name")
                        if name_node is not None and name_node.text:
                            pkg_name = name_node.text.strip()

                if ste_ref_elem is not None:
                    ste_id = ste_ref_elem.attrib.get("state_ref")
                    if ste_id in states_idx:
                        ste_node = states_idx[ste_id]

                        sig_node = ste_node.find(".//{*}signature_keyid")
                        if sig_node is not None and sig_node.text:
                            has_signed_check = True
                            signed_by = sig_node.text.strip()
                            continue

                        evr_node = ste_node.find(".//{*}evr")
                        if evr_node is not None and evr_node.text:
                            fixed_ver = evr_node.text.strip()
                            op_attr = evr_node.attrib.get("operation", "less than")
                            op_name = op_attr.replace(" ", "_")

                if pkg_name and fixed_ver:
                    rules.append({
                        "package": pkg_name,
                        "fixed_version": fixed_ver,
                        "operator": op_name
                    })

        if has_signed_check and signed_by:
            for rule in rules:
                rule["signed_by"] = signed_by
        elif "redhat" in def_id:
            # Дефолтный ключ дистрибутива, если тест был описан через комментарий
            for rule in rules:
                if "signed_by" not in rule:
                    rule["signed_by"] = "redhatrelease2"

        detection_block = {
            "type": "rpm",
            "operator": "OR" if len(rules) > 1 else "AND",
            "rules": rules
        }
        if module_stream:
            detection_block["module_stream"] = module_stream

        vulnerability_entry = {
            "id": clean_id,
            "title": title,
            "cves": cves,
            "severity": severity,
            "affected_platforms": platforms if platforms else ["RHEL-8"],
            "detection": detection_block
        }

        parsed_vulnerabilities.append(vulnerability_entry)

        if len(parsed_vulnerabilities) >= limit:
            break

    return parsed_vulnerabilities


def main():
    parser = argparse.ArgumentParser(
        description="Парсер OVAL XML в упрощенный JSON-формат."
    )
    parser.add_argument("oval_file", help="Путь к локальному OVAL XML-файлу")
    parser.add_argument(
        "-l", "--limit", type=int, default=5,
        help="Количество уязвимостей для извлечения (по умолчанию: 5)"
    )
    parser.add_argument(
        "--split", action="store_true",
        help="Сохранять каждую уязвимость в отдельный JSON-файл"
    )

    args = parser.parse_args()

    results = parse_oval(args.oval_file, limit=args.limit)

    if args.split:
        for item in results:
            safe_name = item["id"].replace(":", "-") + ".json"
            with open(safe_name, "w", encoding="utf-8") as f:
                json.dump(item, f, indent=2, ensure_ascii=False)
            print(f"Сохранен файл: {safe_name}")
    else:
        if len(results) == 1:
            print(json.dumps(results[0], indent=2, ensure_ascii=False))
        else:
            print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
