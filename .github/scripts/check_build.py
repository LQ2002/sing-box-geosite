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
    generated = report.get("generated", [])

    for name in report.get("failed", []):
        print(f"::warning::规则 {name} 生成失败")

    actual = 0
    for name in generated:
        paths = [os.path.join(rule_dir, f"{name}.json"),
                 os.path.join(rule_dir, f"{name}.srs")]
        if all(os.path.isfile(p) and os.path.getsize(p) > 0 for p in paths):
            actual += 1
        else:
            print(f"::warning::{name} 缺少 json 或 srs，不计入成功")

    print(f"expected={len(expected)} actual={actual}")
    if len(expected) != len(generated):
        missing = sorted(set(expected) - set(generated))
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
