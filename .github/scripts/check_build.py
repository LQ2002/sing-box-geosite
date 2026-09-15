#!/usr/bin/env python3
"""校验本次构建的产物，决定要不要清理 Release 上的陈旧资产。

预期数量取自主程序写出的构建清单，而不是从 links.txt 数行数：
links.txt 里一行 `{tag}` 会展开成多个规则集，按行数只会数到 1，
于是即使有规则失败也满足 actual >= expected，照样开启清理，
把失败规则在 Release 上那份还能用的旧资产删掉。

只看主程序报成功也不够：srs 编译失败时 json 可能还留着，
必须 json 和 srs 成对存在且非空，才算这条规则真正产出。

用法: check_build.py <构建清单> <规则目录> <计数输出文件>
输出文件里写 "<expected> <actual>"，供 workflow 读取。
"""
import json
import os
import sys


def main():
    if len(sys.argv) != 4:
        print(f"用法: {os.path.basename(sys.argv[0])} <report.json> <rule_dir> <counts_out>")
        return 2

    report_path, rule_dir, counts_path = sys.argv[1:4]

    try:
        with open(report_path, encoding="utf-8") as fp:
            report = json.load(fp)
    except (OSError, ValueError) as e:
        print(f"::error::读取构建清单失败 {report_path}: {e}")
        return 1

    expected = report.get("expected", [])
    outputs = report.get("outputs", {})

    for name in report.get("failed", []):
        print(f"::warning::规则 {name} 生成失败")

    # 一个规则名可能产出多个文件（用到 ASN 时会多一个 <名称>-ip），
    # 必须它名下所有文件都成对齐全，才算这条规则真正产出。
    actual = 0
    for name, basenames in sorted(outputs.items()):
        missing = []
        for base in basenames:
            for ext in ("json", "srs"):
                path = os.path.join(rule_dir, f"{base}.{ext}")
                if not (os.path.isfile(path) and os.path.getsize(path) > 0):
                    missing.append(f"{base}.{ext}")
        if missing:
            print(f"::warning::{name} 缺少 {', '.join(missing)}，不计入成功")
        else:
            actual += 1

    print(f"expected={len(expected)} actual={actual}")
    if len(expected) != len(outputs):
        missing = sorted(set(expected) - set(outputs))
        print(f"未产出的规则: {', '.join(missing)}")

    try:
        with open(counts_path, "w", encoding="utf-8") as fp:
            fp.write(f"{len(expected)} {actual}\n")
    except OSError as e:
        print(f"::error::写出计数失败 {counts_path}: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
