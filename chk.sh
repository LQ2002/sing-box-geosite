set -Eeuo pipefail
# links.txt 里去重后的规则名数量 = 本次应该生成的 json 个数
expected=$(awk '$1 !~ /^#/ && NF >= 2 { print $2 }' links.txt | sort -u | wc -l)

# 只数 json 不够：srs 编译失败时 json 仍在，
# 陈旧资产清理会把 Release 上那份还能用的 srs 删掉。
# 必须 json 和 srs 成对存在才算这条规则生成成功。
actual=0
for json in ./rule/*.json; do
  [ -e "$json" ] || continue
  if [ -s "${json%.json}.srs" ]; then
    actual=$((actual + 1))
  else
    echo "::warning::${json} 没有对应的 srs，不计入成功"
  fi
done
echo "expected=$expected actual=$actual"
ls -la ./rule/

if [ "$actual" -eq 0 ]; then
  echo "::error::没有生成任何规则文件，中止发布"
  exit 1
fi

# 有上游挂掉时只上传、不做陈旧资产清理，避免把订阅中的 srs 删掉
if [ "$actual" -lt "$expected" ]; then
  echo "::warning::只生成了 $actual/$expected 个规则，疑似上游源不可用；本次跳过陈旧资产清理"
  echo "PRUNE_STALE=false" >> "$GITHUB_ENV"
else
  echo "PRUNE_STALE=true" >> "$GITHUB_ENV"
fi
