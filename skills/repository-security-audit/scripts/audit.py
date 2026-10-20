#!/usr/bin/env python3
"""Offline triage + evidence gate. Python 3.10+, standard library only.

This is NOT a replacement for SAST/SCA/history/runtime testing. It never
promotes a lack of regex matches to PASS. Do not run on a changing checkout:
use an immutable, read-only sandbox snapshot with no credentials/network.
"""
from __future__ import annotations
import argparse
import base64
import collections
from datetime import datetime, timezone, timedelta
import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any

HOME = Path(__file__).resolve().parent.parent
VERSION = '9.2.0'
EVIDENCE_SCHEMA = 3
STATES = ('PASS', 'FAIL', 'REVIEW', 'NOT_RUN', 'BLOCKED', 'ERROR', 'NOT_APPLICABLE', 'WAIVED')
FINAL_GOOD = {'PASS', 'NOT_APPLICABLE'}
COVERAGE = {
    'source_tree': '全ソース・未追跡・ignored・monorepoの範囲',
    'history': '全取得Git履歴・refs・submodule・LFS',
    'dependencies': '全依存・悪性版・SCA・SBOM',
    'release_artifacts': '実配布物・全コンテナ層・公開アセット',
    'platform': 'リポジトリホスト・CI/CD・SaaSの実設定',
    'runtime': 'クラウド・本番相当実環境・認可境界',
    'security_tests': '承認済み環境での否定・回帰テスト',
    'threat_intel': '実行時の一次情報・脆弱性DBの更新確認',
}
STATIC_COVERAGE = {k: v for k, v in COVERAGE.items() if k in {'source_tree', 'history', 'dependencies', 'release_artifacts', 'threat_intel'}}
STATIC_COVERAGE['static_configs'] = 'CI/CD・IaC・宣言的設定の静的レビュー範囲'
PROFILE_LABELS = {'static': '静的解析のみ', 'full': '実環境を含む証拠監査'}
EXCLUDED = {'.git', 'node_modules', '.venv', 'venv', 'vendor', '__pycache__', '.mypy_cache', '.pytest_cache'}
# Signals only: a hit is REVIEW, not a confirmed vulnerability.
RULES = [
 ('SEC-01','secret-prefix','any',r'\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,})\b','認証情報の形式候補。実値は出力しません。'),
 ('SEC-01','literal-secret','any',r'''(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)\s*[:=]\s*["'][^"'\n]{8,}["']''','秘密情報らしいリテラル。無効fixtureか確認。'),
 ('SEC-02','private-key','any',r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----','秘密鍵形式。実運用鍵か確認。'),
 ('SEC-02','key-container','path',r'(?i)\.(?:p12|pfx|jks|keystore)$','鍵コンテナ候補。別途安全に解析。'),
 ('SEC-03','env-file','path',r'(?:^|/)\.env(?:\.[^/]*)?$','環境設定ファイル。値と配布経路を確認。'),
 ('SEC-03','credential-file','path',r'(?:^|/)(?:\.npmrc|\.pypirc|credentials|kubeconfig|id_rsa|id_ed25519)$','認証設定候補。実値の有無を確認。'),
 ('SEC-04','url-password','any',r'(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|https?)://[^\s/@:]+:[^\s/@]+@','URL内の認証情報候補。'),
 ('SEC-05','public-secret','any',r'\b(?:NEXT_PUBLIC|VITE|PUBLIC)_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*','公開変数に秘密用途の名前。実bundleを確認。'),
 ('SEC-06','notebook','path',r'(?i)\.(?:ipynb|har)$','保存出力・通信記録の別途サニタイズ確認。'),
 ('CIC-02','permissions-write-all','workflow',r'(?im)^\s*permissions\s*:\s*write-all\b','広域write permissions候補。'),
 ('CIC-03','privileged-trigger','workflow',r'\b(?:pull_request_target|workflow_run|issue_comment)\b','特権イベントと未信頼コードの組合せを追跡。'),
 ('CIC-04','expression-input','workflow',r'\$\{\{[^}\n]*github\.event\.(?:issue|pull_request|comment|head_commit)[^}\n]*\}\}','未信頼event値の式展開。runへの流れを確認。'),
 ('CIC-05','persist-credentials','workflow',r'(?im)persist-credentials\s*:\s*true\b','checkout資格情報保持の明示指定。'),
 ('CIC-06','inherit-secrets','workflow',r'(?im)secrets\s*:\s*inherit\b','秘密情報の一括継承。'),
 ('CIC-07','self-hosted','workflow',r'\bself-hosted\b','永続runner・信頼境界の確認が必要。'),
 ('CIC-09','cache-restore','workflow',r'\b(?:restore-keys|download-artifact|actions/cache)\b','cache/artifactの出所と信頼境界を確認。'),
 ('SUP-04','lifecycle-script','package',r'"(?:preinstall|install|postinstall|prepare)"\s*:','install時等のコード実行。内容・間接依存を確認。'),
 ('SUP-05','extra-index','any',r'(?i)(?:--extra-index-url|extra-index-url\s*=)','複数registry間のdependency confusionを確認。'),
 ('SUP-07','mutable-git-dependency','any',r'(?i)git\+(?:https?|ssh)://[^\s"\']+','Git依存の固定commitと取得元を確認。'),
 ('REL-02','source-map','path',r'(?i)\.map$','source mapの内容と公開方針を確認。'),
 ('REL-02','sources-content','any',r'"sourcesContent"\s*:','ソース内包mapの候補。'),
 ('REL-03','backup-dump','path',r'(?i)\.(?:bak|backup|sql|dump|sqlite|sqlite3)$','バックアップ・DBファイルの配布と機密性を確認。'),
 ('REL-05','docker-secret','docker',r'(?im)^\s*(?:ARG|ENV)\s+[^\n]*(?:PASSWORD|SECRET|TOKEN|PRIVATE_KEY)','image metadata/layerへの秘密値残留を確認。'),
 ('AUT-03','weak-password-hash','code',r'(?i)\b(?:md5|sha1)\s*\(','hashの用途がpassword等でないか確認。'),
 ('AUT-07','jwt-no-verify','code',r'(?i)(?:verify_signature["\']?\s*:\s*False|algorithms?\s*[:=]\s*\[["\']none)','JWT検証無効化候補。'),
 ('INJ-01','sql-concat','code',r'(?i)(?:SELECT|UPDATE|DELETE\s+FROM|INSERT\s+INTO)[^\n]*(?:\+|\$\{|\{[a-zA-Z_])','query文字列への値の直接埋込候補。'),
 ('INJ-02','shell-exec','code',r'(?i)(?:shell\s*=\s*True|os\.system\s*\(|child_process\.exec\s*\()','shell実行と入力経路を確認。'),
 ('INJ-03','eval','code',r'\b(?:eval|exec)\s*\(','動的コード評価の入力元を確認。'),
 ('INJ-04','unsafe-deserialization','code',r'\b(?:pickle\.loads?|yaml\.load|unserialize|ObjectInputStream)\s*\(','未信頼deserializationの有無を確認。'),
 ('INJ-08','upload-processing','code',r'\b(?:multer|formidable|UploadFile|fileupload)\b','upload内容・保存先・容量の検証を確認。'),
 ('INJ-09','deep-merge','code',r'\b(?:deepmerge|mergeDeep|lodash\.merge)\s*\(','prototype pollution耐性を確認。'),
 ('WEB-01','html-sink','code',r'\b(?:dangerouslySetInnerHTML|innerHTML|v-html|bypassSecurityTrustHtml)\b','HTML出力までの信頼境界を確認。'),
 ('WEB-03','cors-wildcard','any',r'(?i)(?:Access-Control-Allow-Origin[^\n]*\*|allow_origins\s*=\s*\[["\']\*|origin\s*:\s*true)','CORSの実効許可範囲を確認。'),
 ('WEB-05','tls-disable','any',r'(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0|insecureSkipVerify\s*:\s*true)','TLS検証無効化候補。'),
 ('WEB-06','debug-enabled','any',r'(?im)\bDEBUG\s*[:=]\s*(?:True|true|1)\b','本番debugの実効値を確認。'),
 ('CLD-01','public-acl','iac',r'(?i)(?:public-read|allUsers|allAuthenticatedUsers)','公開ACLの対象データを確認。'),
 ('CLD-02','open-cidr','iac',r'(?:0\.0\.0\.0/0|::/0)','公開CIDRのport・用途を確認。'),
 ('CLD-03','iam-star','iac',r'''(?i)["']?(?:Action|Resource)["']?\s*[:=]\s*["']\*["']''','IAM wildcardの実効権限を確認。'),
 ('CLD-06','terraform-state','path',r'(?i)\.tfstate(?:\.backup)?$','stateは秘密情報を含み得る。'),
 ('CTR-02','root-user','docker',r'(?im)^\s*USER\s+(?:root|0)(?:\s|$)','root実行候補。'),
 ('CTR-03','privileged','iac',r'(?im)\b(?:privileged|allowPrivilegeEscalation)\s*:\s*true\b','特権container候補。'),
 ('CTR-04','host-access','any',r'(?:/var/run/docker\.sock|hostPath\s*:|hostPID\s*:\s*true|hostNetwork\s*:\s*true)','host境界を越える構成候補。'),
 ('CTR-06','cluster-admin','iac',r'\bcluster-admin\b','cluster管理権限の必要性を確認。'),
 ('CTR-07','token-automount','iac',r'(?im)automountServiceAccountToken\s*:\s*true','tokenの不要なmountを確認。'),
 ('OBS-01','log-secret','code',r'(?i)(?:console\.(?:log|debug)|logger?\.(?:info|debug|error)|print)\s*\([^\n]*(?:password|secret|token|authorization|cookie)','ログへの秘密情報出力候補。'),
 ('OBS-04','ci-env-dump','workflow',r'(?:\bprintenv\b|\bset\s+-x\b|toJSON\s*\(\s*secrets\s*\))','CI環境・秘密値のdump候補。'),
 ('OBS-05','session-replay','any',r'(?i)(?:sessionReplay|replayIntegration|recordSession|sendDefaultPii\s*:\s*true)','第三者telemetryの送信内容を確認。'),
 ('AIM-06','mcp-server','path',r'(?:^|/)(?:\.mcp\.json|mcp\.json)$','MCP設定の供給元・scope・実行権限を確認。'),
 ('DEV-01','ide-extensions','path',r'(?:^|/)\.vscode/extensions\.json$','推奨IDE拡張と承認台帳を確認。'),
 ('DEV-02','devcontainer-exec','any',r'"(?:postCreateCommand|initializeCommand|postStartCommand)"\s*:','環境起動に伴う自動コード実行候補。'),
 ('DEV-05','pipe-shell','any',r'(?i)\b(?:curl|wget)\b[^\n]*\|\s*(?:bash|sh|zsh)\b','未検証downloadの即時実行候補。'),
 ('DEV-07','audit-instructions','path',r'(?:^|/)(?:AGENTS\.md|CLAUDE\.md|\.cursorrules)$','対象内指示を監査の権限・承認として扱わない。'),
 ('TST-08','suppression','any',r'(?i)(?:nosemgrep|nosec\b|gitleaks:allow|trivy:ignore|checkov:skip)','抑制の理由・所有者・期限を確認。'),
 ('TST-08','scanner-ignore-file','path',r'(?:^|/)(?:\.semgrepignore|\.gitleaksignore|\.trivyignore|osv-scanner\.toml)$','対象内の除外設定を無条件に信頼しない。'),
]

# v6: IPA response-oriented lexical triage. These are review signals, never proof
# of a vulnerability or of absence. The IPA does not prescribe these regexes.
RULES += [
 ('AZ-06','bulk-export-entry','code',r"""(?i)(?:@\w+\.(?:route|get|post)|\b(?:app|router)\.(?:get|post|put))\s*\(\s*["'][^"'\n]*(?:export|download-all|bulk)[^"'\n]*["']""",'一括取得routeの検査起点。受付・worker・取得の主体/tenant認可を追跡。認可欠如の断定ではありません。'),
 ('WEB-09','zero-negative-query-limit','code',r'\.(?:limit|take)\s*\(\s*(?:0|-[1-9][0-9]*)\s*\)','0/負数の件数指定。利用ライブラリの意味と無制限取得への分岐を確認。'),
 ('WEB-09','request-controlled-query-limit','code',r"""(?:\.(?:limit|take)\s*\(\s*req\.query\.(?:limit|take|pageSize)|\blimit\s*:\s*req\.query\.(?:limit|take|pageSize))""",'query件数へリクエスト値を直接渡す候補。上流の型検証・上限適用まで追跡。'),
 ('INT-04','account-reactivation','code',r'(?im)\b(?:is_active|account_enabled|accountEnabled)\s*[:=]\s*(?:True|true|1)\b','アカウント有効化の経路。承認・停止状態・同期再試行・監査記録を確認。'),
 ('DAT-02','whole-record-response','code',r"""(?i)(?:\bres\.json\s*\(\s*(?:user|customer|account)\s*\)|\bfields\s*=\s*["']__all__["']|\bSELECT\s+\*\s+FROM\s+(?:users|customers|accounts)\b)""",'レコード全体の取得/返却候補。必要なfieldの許可リストとserializerまで追跡。'),
 ('OBS-07','audit-logging-disabled','iac',r'(?im)\b(?:enable_logging|enable_audit_logging|audit_logging_enabled|access_log_enabled)\s*[:=]\s*(?:false|0)\b','監査/アクセスログを明示的に無効化する設定候補。実際の製品schemaと対象を確認。'),
 ('OBS-06','short-log-retention','iac',r'(?im)\bretention_in_days\s*[:=]\s*(?:1|3|5|7|14)\b','短期ログ保持の確認候補。調査可能期間と最小化を両立する根拠を確認。一律90日要件ではありません。'),
 ('INT-02','broad-oauth-scope','any',r'\b(?:Directory\.ReadWrite\.All|RoleManagement\.ReadWrite\.Directory|https://www\.googleapis\.com/auth/cloud-platform)\b','広域OAuth scopeの候補。実利用APIに必要か、同意・解除・権限範囲を確認。'),
 ('DAT-03','storage-encryption-disabled','iac',r'(?im)\b(?:storage_encrypted|enable_encryption|disk_encryption_enabled)\s*[:=]\s*(?:false|0)\b','保存時暗号化の明示的無効化候補。製品schema・代替暗号化・鍵の分離を確認。'),
]


# v8: agent-assisted attacker defenses. Signals, NOT ARTEX attribution.
ARTEX_RULES = [
 ('AUT-04','auth-memory-limiter','code',r'''(?:\bnew\s+MemoryStore\s*\(|\bstorage_uri\s*=\s*["']memory://)''','プロセス内制限ストアの候補。複数ノードの共有制限・障害時分岐をレビュー。'),
 ('WEB-08','trust-all-proxies','code',r'''(?:\.set\s*\(\s*["']trust proxy["']\s*,\s*true\b|\btrustProxy\s*:\s*true\b)''','proxy全面信頼の候補。最終proxyのヘッダー上書き・origin直通制限まで確認。trueだけでFAILにしない。'),
 ('WEB-08','forwarded-client-identity','code',r'''(?i)\b(?:clientIp|client_ip|remoteIp|remote_ip)\s*[:=]\s*(?:req|request)\.headers(?:\s*\[\s*|\.get\s*\(\s*)["'](?:x-forwarded-for|x-real-ip|forwarded)["']''','外部ヘッダーからclient IPへ直接代入する候補。信頼proxy・正規化・利用先を追跡。'),
 ('AUT-04','limiter-store-fail-open','code',r'\bpassOnStoreError\s*:\s*true\b','制限ストア障害時に通過する設定候補。認証・高リスク操作の代替制御と安全な縮退を確認。'),
 ('WEB-09','graphql-http-batching','code',r'\ballowBatchedHttpRequests\s*:\s*true\b','GraphQL HTTP batching有効化。1リクエスト内の操作数・コスト・共有予算を確認。'),
 ('WEB-09','bulk-concurrency-entry','code',r'\bPromise\.all\s*\(\s*(?:req|request)\.body\.(?:items|ids|operations)\.map\s*\(','入力件数分を並列処理する候補。上流の件数検証・同時数・主体別予算を確認。'),
 ('AZ-10','dataloader-lifetime','code',r'\bnew\s+DataLoader\s*\(','DataLoaderの寿命確認点。request/tenantを越える再利用・cache hit時の認可をレビュー。'),
 ('RAN-01-09','api-schema-inventory','path',r'(?i)(?:^|/)(?:openapi|swagger)(?:[._-][^/]*)?\.(?:ya?ml|json)$','API schemaの公開面突合起点。backend/旧版/ingressとの一致を確認。仕様公開自体を問題にしない。'),
 ('DEV-07','agent-policy-or-hook-file','path',r'(?:^|/)(?:\.claude/(?:settings(?:\.local)?\.json|(?:skills|commands|agents|rules)/[^\n]+)|\.cursor/(?:hooks\.json|rules/[^\n]+|skills/[^\n]+)|\.github/copilot-instructions\.md|\.windsurfrules)$','監査対象内のagent設定・指示・hook。実行や信頼済みpolicyへの昇格は禁止。存在は脆弱性の証明ではない。'),
 ('DEV-07','audit-verdict-coercion','any',r'(?im)(?:\b(?:always|must|only)\s+(?:report|output|return|say)\s+["\x27`]?(?:all clean|review passed)\b|(?:必ず|無条件で)[^\n]{0,24}(?:all clean|review passed)[^\n]{0,24}(?:表示|報告|出力))','合格を強制する対象内テキストの候補。fixture/説明との文脈を確認し、監査指示には採用しない。'),
]
RULES += ARTEX_RULES

COMPILED = [(cid, name, scope, re.compile(pattern), msg) for cid,name,scope,pattern,msg in RULES]
CODE_SUFFIX = {'.py','.js','.ts','.jsx','.tsx','.mjs','.cjs','.java','.kt','.go','.rs','.rb','.php','.cs','.c','.cpp','.h','.swift','.scala','.vue','.svelte'}

class AuditError(ValueError):
    pass

def now() -> datetime:
    return datetime.now(timezone.utc)

def iso() -> str:
    return now().isoformat(timespec='seconds')

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',',':')).encode()

def safe_text(value: Any) -> str:
    """Best effort only. Do not supply raw secrets in human-written evidence."""
    s = str(value)
    s = re.sub(RULES[0][3], '[REDACTED]', s)
    s = re.sub(r'(?i)((?:password|client[_-]?secret|api[_-]?key|access[_-]?token)\s*[:=]\s*)["\']?[^\s,"\';]+', r'\1[REDACTED]', s)
    s = re.sub(r'(?i)([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@',r'\1[REDACTED]@',s)
    s = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]+', 'Bearer [REDACTED]', s)
    s = ''.join(c if c in '\n\t' or ord(c)>=32 else '\uFFFD' for c in s)
    return s[:12000]

def esc(value: Any) -> str:
    return html.escape(safe_text(value), quote=True)

def read_json(path: Path, limit: int = 12_000_000) -> Any:
    def pairs(items):
        out={}
        for k,v in items:
            if k in out:
                raise AuditError('JSONに重複キーがあります。')
            out[k]=v
        return out
    if path.is_symlink() or not path.is_file() or path.stat().st_size>limit:
        raise AuditError('JSON入力が不正、symlink、または上限超過です。')
    try:
        return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(AuditError('非有限JSON数値。')))
    except (UnicodeError,json.JSONDecodeError) as e:
        raise AuditError('JSONを解析できません。') from e

def checks() -> list[dict]:
    data=read_json(HOME/'references/checks.json')
    if len(data)!=220 or len({x['id'] for x in data})!=220:
        raise AuditError('信頼済みチェック台帳の件数・IDが不正です。')
    return data

def applies(scope: str, path: str) -> bool:
    p=Path(path)
    return (scope in {'any','path'} or
            scope=='workflow' and ('.github/workflows/' in path or p.name in {'action.yml','action.yaml','.gitlab-ci.yml','Jenkinsfile'}) or
            scope=='package' and p.name=='package.json' or
            scope=='docker' and (p.name.startswith('Dockerfile') or p.suffix=='.dockerfile') or
            scope=='iac' and p.suffix.lower() in {'.tf','.tfvars','.yaml','.yml','.json','.bicep'} or
            scope=='code' and p.suffix.lower() in CODE_SUFFIX)

def inventory(repo: Path, target_id: str, max_files=20000, max_file_bytes=2*1024*1024,
              max_total_bytes=200*1024*1024, timeout=90) -> dict:
    start=time.monotonic(); manifest=[]; gaps=[]; observations=[]; failures=[]
    total=0; visited=0; read_files=0; scanned=0; dirs_count=0
    def gap(path,kind,extra=''):
        item={'path':safe_text(path),'path_id':sha(os.fsencode(path)),'kind':kind,'detail':safe_text(extra)}
        item['id']='G-'+sha(canonical(item))[:20]
        gaps.append(item)
    def observe(cid,rule,path,line,msg):
        nonlocal stop
        if len(observations)>=10000:
            if not stop: gap('.', 'observation_budget', '総候補件数の上限')
            stop=True
            return
        item={'check_id':cid,'rule':rule,'path':safe_text(path),'path_id':sha(os.fsencode(path)),'line':line,'message':msg}
        item['id']='O-'+sha(canonical(item))[:20]
        observations.append(item)
    def walkerror(err):
        failures.append('ファイルツリーの一部を列挙できません。')
    stop=False
    for directory, subdirs, filenames in os.walk(repo, topdown=True, onerror=walkerror, followlinks=False):
        subdirs.sort(); filenames.sort(); dirs_count+=1
        if time.monotonic()-start>timeout or dirs_count>20000:
            gap('.', 'inventory_limit','時間またはディレクトリ件数の上限'); stop=True; break
        for d in list(subdirs):
            p=Path(directory)/d; rel=p.relative_to(repo).as_posix()
            if p.is_symlink():
                gap(rel,'symlink_directory'); subdirs.remove(d)
            elif d in EXCLUDED:
                gap(rel,'excluded_directory','別スキャナー等による補完が必要'); subdirs.remove(d)
        for filename in filenames:
            if stop: break
            visited+=1
            if visited>max_files or time.monotonic()-start>timeout:
                gap('.', 'inventory_limit','ファイル件数または時間の上限'); stop=True; break
            p=Path(directory)/filename; rel=p.relative_to(repo).as_posix()
            for cid, rule, scope, pattern, msg in COMPILED:
                if scope=='path' and pattern.search(rel): observe(cid,rule,rel,0,msg)
            try:
                st=p.lstat()
                if stat.S_ISLNK(st.st_mode):
                    gap(rel,'symlink_file'); continue
                if not stat.S_ISREG(st.st_mode):
                    gap(rel,'special_file'); continue
                if filename=='.git':
                    gap(rel,'git_metadata_pointer','外部worktree metadataは自動追跡しません'); continue
                if st.st_size>max_file_bytes:
                    gap(rel,'oversized_file',f'{st.st_size} bytes'); continue
                if total+st.st_size>max_total_bytes:
                    gap('.', 'byte_budget','総読取byte数の上限'); stop=True; break
                # O_NOFOLLOW protects the final component. Immutable sandbox is
                # still mandatory to eliminate parent-directory race conditions.
                flags=os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_NONBLOCK',0)
                fd=os.open(p,flags)
                with os.fdopen(fd,'rb') as handle:
                    before=os.fstat(handle.fileno())
                    if not stat.S_ISREG(before.st_mode): raise OSError('non-regular')
                    data=handle.read(max_file_bytes+1)
                    after=os.fstat(handle.fileno())
                if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns) or len(data)>max_file_bytes:
                    failures.append('読取中にファイルが変化、または上限を超過しました。'); gap(rel,'changed_during_read'); continue
                total+=len(data); read_files+=1
                manifest.append({'path':safe_text(rel),'path_id':sha(os.fsencode(rel)),'sha256':sha(data),'bytes':len(data)})
                if b'\0' in data:
                    gap(rel,'binary_file','内容はhashのみ。別途解析が必要'); continue
                try: text=data.decode('utf-8')
                except UnicodeDecodeError:
                    gap(rel,'non_utf8','別文字コード・バイナリは未解析'); continue
                scanned+=1
                for cid,rule,scope,pattern,msg in COMPILED:
                    if stop: break
                    if scope=='path' or not applies(scope,rel): continue
                    hits=0
                    for m in pattern.finditer(text):
                        observe(cid,rule,rel,text.count('\n',0,m.start())+1,msg); hits+=1
                        if hits>=30:
                            gap(rel,'observation_limit',rule); break
                if not stop and applies('workflow',rel):
                    # Conservative YAML lexical triage, never a semantic PASS.
                    for m in re.finditer(r'''(?m)^\s*(?:-\s*)?uses\s*:\s*["']?([^\s"'#]+)''',text):
                        value=m.group(1)
                        if value.startswith('./'): continue
                        pinned=bool(re.fullmatch(r'[^@]+@[0-9a-fA-F]{40}',value))
                        if value.startswith('docker://'): pinned=bool(re.search(r'@sha256:[0-9a-fA-F]{64}$',value))
                        if not pinned: observe('CIC-01','mutable-action-ref',rel,text.count('\n',0,m.start())+1,'不変参照と確認できないuses候補。YAML・間接依存を別途検証。')
                if not stop and applies('docker',rel):
                    for m in re.finditer(r'(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)',text):
                        if m.group(1).lower()!='scratch' and '@sha256:' not in m.group(1):
                            observe('CTR-01','mutable-base-image',rel,text.count('\n',0,m.start())+1,'digest固定でないFROM候補。stage参照なら理由を記録。')
            except OSError:
                failures.append('ファイルを安全に読み取れません。'); gap(rel,'read_error')
        if stop: break
    if scanned==0: gap('.','empty_text_scope','解析可能なUTF-8テキストが0件')
    # path hashes disambiguate redacted filenames without recording raw names.
    # Inventory alone is NOT a full Git/tree fingerprint: excluded assets need
    # independently hashed receipts and domain attestations in the evidence file.
    catalog_hash=sha((HOME/'references/checks.json').read_bytes())
    rules_hash=sha(Path(__file__).read_bytes())
    binding={'target_id':target_id,'manifest':manifest,'gaps':gaps,'catalog':catalog_hash,
             'engine':rules_hash,'ipa_mapping':sha((HOME/'references/ipa-mapping.json').read_bytes()),'artex_mapping':sha((HOME/'references/artex-mapping.json').read_bytes()),'limits':[max_files,max_file_bytes,max_total_bytes,timeout]}
    return {'scope_id':sha(canonical(binding)),'target_id':safe_text(target_id),'manifest':manifest,
            'gaps':gaps,'observations':observations,'errors':failures,'catalog_sha256':catalog_hash,
            'engine_sha256':rules_hash,'artex_mapping_sha256':binding['artex_mapping'],'files_seen':visited,'files_read':read_files,'text_files_scanned':scanned,
            'bytes_read':total,'baseline_full_repository_verified':False}

def timestamp(value, max_age_days=7):
    if not isinstance(value,str): raise AuditError('証拠の日時がありません。')
    try: t=datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError as e: raise AuditError('証拠の日時が不正です。') from e
    if t.tzinfo is None or t>now()+timedelta(minutes=5) or now()-t>timedelta(days=max_age_days):
        raise AuditError('証拠が古い、未来、またはタイムゾーン未指定です。')

def required_text(obj,key,minlen=1):
    v=obj.get(key)
    if not isinstance(v,str) or len(v.strip())<minlen or len(v)>12000:
        raise AuditError(f'証拠に必要な文字列がありません: {key}')
    if '<REQUIRED' in v or '<replace' in v:
        raise AuditError('証拠に未記入placeholderがあります。')
    return v

def validate_receipts(records, root: Path, repo: Path):
    if not isinstance(records,list) or not 1<=len(records)<=30:
        raise AuditError('1〜30件の証拠artifactが必要です。')
    clean=[]
    for ref in records:
        if not isinstance(ref,dict): raise AuditError('証拠artifactの形式が不正です。')
        rel=required_text(ref,'artifact'); expected=required_text(ref,'sha256')
        summary=required_text(ref,'summary',8)
        if not re.fullmatch('[a-f0-9]{64}',expected): raise AuditError('証拠artifactのSHA256が不正です。')
        relative=Path(rel)
        if relative.is_absolute() or '..' in relative.parts: raise AuditError('証拠artifactは安全な相対pathで指定してください。')
        p=root/relative
        cursor=root
        for part in relative.parts:
            cursor=cursor/part
            if cursor.is_symlink(): raise AuditError('証拠artifactのsymlinkは禁止です。')
        real=p.resolve()
        if not real.is_relative_to(root) or real.is_relative_to(repo): raise AuditError('証拠が許可された外部root外にあります。')
        if not real.is_file() or real.stat().st_size>10_000_000: raise AuditError('証拠artifactが欠落、または上限超過です。')
        content=real.read_bytes()
        if not content or sha(content)!=expected: raise AuditError('証拠artifactが空、またはhash不一致です。')
        clean.append({'artifact':safe_text(rel),'sha256':expected,'summary':safe_text(summary)})
    return clean

def validate_record(record, root, repo, *, coverage=False):
    if not isinstance(record,dict) or record.get('status') not in STATES:
        raise AuditError('不明な証拠statusです。')
    status=record['status']
    result={'status':status}
    if status in {'NOT_RUN','REVIEW','BLOCKED','ERROR'}:
        result['rationale']=safe_text(record.get('rationale','未検証です。'))
        return result
    for k in ('reviewer','rationale','reviewed_at'):
        required_text(record,k,8 if k=='rationale' else 1)
    timestamp(record['reviewed_at'])
    if record.get('redacted') is not True: raise AuditError('証拠のredaction確認が必要です。')
    if status=='NOT_APPLICABLE': required_text(record,'approved_by')
    if status=='WAIVED':
        required_text(record,'approved_by'); required_text(record,'expires_at')
        # WAIVED never enables a clean result, including before expiry.
    result.update({k:safe_text(record[k]) for k in ('reviewer','rationale','reviewed_at')})
    result['evidence']=validate_receipts(record.get('evidence'),root,repo)
    for key in ('approved_by','expires_at','owner','due_at','recommendation'):
        if key in record: result[key]=safe_text(record[key])
    return result

def validate_criteria(item: dict, definition: dict, checked: dict, root: Path, repo: Path) -> dict:
    """Validate named acceptance criteria; parent PASS cannot conceal missing proof.

    Criterion text comes ONLY from the trusted catalog, never from input JSON.
    This validates receipts and assertions, not the truth of human evidence.
    """
    definitions=definition.get('criteria',[])
    expected={d['id']:d for d in definitions}
    submitted=item.get('criteria_results',[])
    if not isinstance(submitted,list) or len(submitted)>len(expected):
        raise AuditError('criteria_resultsの形式・件数が不正です: '+definition['id'])
    found={}
    for sub in submitted:
        if not isinstance(sub,dict) or sub.get('id') not in expected or sub.get('id') in found:
            raise AuditError('合格条件に未知・重複IDがあります: '+definition['id'])
        found[sub['id']]=validate_record(sub,root,repo)
    if not definitions:
        return checked
    original_status=checked['status']
    if original_status=='NOT_APPLICABLE':
        # Proven whole-control non-applicability covers its criteria. Contradictory
        # evidence (applicable / failed / waived) must not be hidden by parent N/A.
        if any(v['status'] not in {'NOT_APPLICABLE','NOT_RUN'} for v in found.values()):
            raise AuditError('親の非該当と個別条件の判定が矛盾します: '+definition['id'])
        checked['criteria_results']=[{'id':d['id'],'status':'NOT_APPLICABLE',
            'covered_by_parent':True,'rationale':'親項目の証拠・承認で非該当を確認。',
            'approved_by':checked['approved_by']} for d in definitions]
        return checked
    ordered=[{'id':d['id'],**found.get(d['id'],{'status':'NOT_RUN','rationale':'この条件の証拠が未提出です。'})} for d in definitions]
    checked['criteria_results']=ordered
    if original_status=='PASS':
        statuses={r['status'] for r in ordered}
        for bad in ('ERROR','FAIL','WAIVED','BLOCKED','REVIEW','NOT_RUN'):
            if bad in statuses:
                checked['requested_status']='PASS'
                checked['status']=bad
                checked['rationale']='親項目の申告PASSを受理できません。個別合格条件に '+bad+' が残っています。 '+checked.get('rationale','')
                break
        else:
            if 'PASS' not in statuses:
                checked['requested_status']='PASS'; checked['status']='REVIEW'
                checked['rationale']='個別条件が全て非該当です。親項目の適用条件を再確認してください。'
    return checked

def assemble_core(inv: dict, catalog: list[dict], evidence_path: Path|None, repo: Path, profile: str) -> dict:
    coverage_def = STATIC_COVERAGE if profile == 'static' else COVERAGE
    expected_count = len(catalog)
    result={c['id']:{**c,'status':'NOT_RUN','rationale':'証拠に基づく検証が未実行です。','observations':[], 'criteria_results':[{'id':d['id'],'status':'NOT_RUN','rationale':'未検証です。'} for d in c.get('criteria',[])]} for c in catalog}
    for obs in inv['observations']:
        row=result[obs['check_id']]; row['observations'].append(obs)
        row['status']='REVIEW'; row['rationale']='静的な確認候補があります。脆弱性確定でも合格でもありません。'
    domain={k:{'title':v,'status':'NOT_RUN'} for k,v in coverage_def.items()}
    resolved_gaps={}
    if evidence_path:
        if evidence_path.is_symlink(): raise AuditError('証拠JSONのsymlinkは禁止です。')
        evidence_path=evidence_path.resolve()
        if evidence_path.is_relative_to(repo): raise AuditError('証拠は監査対象の外に置いてください。')
        ev=read_json(evidence_path); root=evidence_path.parent
        if not isinstance(ev,dict) or ev.get('schema_version')!=EVIDENCE_SCHEMA or ev.get('scope_id')!=inv['scope_id'] or ev.get('profile')!=profile:
            raise AuditError('証拠schema、profileまたはscope_idが現在のsnapshot/検査範囲と一致しません。')
        timestamp(ev.get('created_at'))
        rows=ev.get('checks',[])
        if not isinstance(rows,list) or len(rows)>expected_count: raise AuditError('証拠checks一覧が不正です。')
        seen=set()
        for item in rows:
            if not isinstance(item,dict): raise AuditError('証拠checkが不正です。')
            cid=item.get('id')
            if cid not in result or cid in seen: raise AuditError('証拠に未知または重複したcheck IDがあります。')
            seen.add(cid); checked=validate_record(item,root,repo)
            checked=validate_criteria(item,result[cid],checked,root,repo)
            if checked['status'] in FINAL_GOOD:
                resolutions=item.get('resolved_observations',[])
                if not isinstance(resolutions,list): raise AuditError('候補の判定一覧が不正です。')
                ids=set()
                valid_ids={o['id'] for o in result[cid]['observations']}
                for r in resolutions:
                    if not isinstance(r,dict) or r.get('id') not in valid_ids or r.get('id') in ids:
                        raise AuditError('候補の判定IDが不正・重複です。')
                    required_text(r,'rationale',8); ids.add(r['id'])
                if ids!=valid_ids: raise AuditError('未解決の静的候補をPASS/N/Aへ変更できません。')
                checked['resolved_observations']=[{'id':r['id'],'rationale':safe_text(r['rationale'])} for r in resolutions]
            result[cid].update(checked)
        coverage_ev=ev.get('coverage',{})
        if not isinstance(coverage_ev,dict) or set(coverage_ev)-set(coverage_def): raise AuditError('不明なcoverage領域です。')
        for key,item in coverage_ev.items():
            checked=validate_record(item,root,repo,coverage=True)
            if key in {'source_tree','threat_intel'} and checked['status']=='NOT_APPLICABLE':
                raise AuditError('ソース範囲・脅威情報確認はN/Aにできません。')
            if key=='threat_intel' and checked['status']=='PASS':
                timestamp(item.get('as_of'),max_age_days=1); checked['as_of']=item['as_of']
            domain[key].update(checked)
        gap_ev=ev.get('gap_resolutions',[])
        if not isinstance(gap_ev,list): raise AuditError('gap補完の形式が不正です。')
        expected_gaps={g['id'] for g in inv['gaps']}
        for item in gap_ev:
            if not isinstance(item,dict) or item.get('id') not in expected_gaps or item.get('id') in resolved_gaps:
                raise AuditError('未知または重複したgap補完です。')
            resolved_gaps[item['id']]=validate_record(item,root,repo)
    rows=list(result.values()); counts=dict(collections.Counter(r['status'] for r in rows))
    unresolved=[g for g in inv['gaps'] if resolved_gaps.get(g['id'],{}).get('status') not in FINAL_GOOD]
    clean=(len(rows)==expected_count and len({r['id'] for r in rows})==expected_count and
           all(r['status'] in FINAL_GOOD for r in rows) and
           all(x['status'] in FINAL_GOOD for r in rows for x in r.get('criteria_results',[])) and counts.get('PASS',0)>0 and
           all(d['status'] in FINAL_GOOD for d in domain.values()) and not unresolved and not inv['errors'] and
           inv['text_files_scanned']>0)
    all_states=[r['status'] for r in rows]+[x['status'] for r in rows for x in r.get('criteria_results',[])]+[d['status'] for d in domain.values()]+[g['status'] for g in resolved_gaps.values()]
    incomplete=(any(s in {'REVIEW','NOT_RUN','BLOCKED','ERROR'} for s in all_states)
                or any(d['status'] not in FINAL_GOOD for d in domain.values()) or bool(unresolved)
                or bool(inv['errors']) or inv['text_files_scanned']==0 or counts.get('PASS',0)==0)
    if inv['errors'] or 'ERROR' in all_states: verdict='ERROR'; code=2
    elif 'FAIL' in all_states: verdict='FINDINGS'; code=1
    elif 'WAIVED' in all_states: verdict='EXCEPTIONS'; code=1
    elif clean: verdict='REVIEW PASSED'; code=0
    else: verdict='INCOMPLETE'; code=2
    return {'schema_version':EVIDENCE_SCHEMA,'engine_version':VERSION,'generated_at':iso(),'verdict':verdict,
            'exit_code':code,'all_clean':clean,'scope_passed':clean,'incomplete':incomplete,'scope':inv,
            'coverage':domain,'gap_resolutions':resolved_gaps,'unresolved_gaps':unresolved,
            'counts':{s:counts.get(s,0) for s in STATES},'checks':rows}

def template_core(inv: dict, catalog: list[dict], profile: str) -> dict:
    coverage_def = STATIC_COVERAGE if profile == 'static' else COVERAGE
    def pending():
        return {'status':'NOT_RUN','reviewer':'','reviewed_at':'','redacted':False,
                'rationale':'','evidence':[]}
    rows=[]
    for c in catalog:
        record={'id':c['id'],**pending(),'resolved_observations':[]}
        if c.get('criteria'):
            record['criteria_results']=[{'id':d['id'], 'expectation':d['expectation'], **pending()} for d in c['criteria']]
        rows.append(record)
    return {'schema_version':EVIDENCE_SCHEMA,'scope_id':inv['scope_id'],'profile':profile,'created_at':iso(),
            'instructions':'NOT_RUNのまま保存可能。PASS/FAIL/N/A/WAIVEDには証拠artifact、hash、日時、reviewer、根拠が必要。N/Aはapproved_byも必要。現在のprofileの全criteria_resultsの検証も必要。別profileへの証拠流用は禁止。自動合格は禁止。',
            'checks':rows,'coverage':{k:{**pending(),**({'as_of':''} if k=='threat_intel' else {})} for k in coverage_def},
            'gap_resolutions':[{'id':g['id'],**pending()} for g in inv['gaps']]}


def static_catalog(catalog: list[dict]) -> list[dict]:
    """Project source/config aspects; never weaken the original full contract."""
    out=[]
    for c in catalog:
        d=c.get('static_review',{})
        if d.get('in_scope') is not True:
            continue
        criteria=d.get('criteria',[])
        if not criteria or any(not x.get('id') or not x.get('expectation') for x in criteria):
            raise AuditError('静的プロファイルの条件定義が不正です。')
        row={**c,'criteria':criteria,'verification':' '.join(x['verification'] for x in criteria),
             'pass_criteria':' '.join(x['expectation'] for x in criteria),
             'full_verification':c['verification'],'full_pass_criteria':c['pass_criteria'],
             'full_criteria':c.get('criteria',[]),'assessment_scope':'static','full_status':'NOT_RUN'}
        out.append(row)
    if not out or len({c['id'] for c in out})!=len(out):
        raise AuditError('静的プロファイルの項目一覧が不正です。')
    return out

def aggregate_status(statuses: list[str]) -> str:
    if not statuses: return 'NOT_RUN'
    for state in ('ERROR','FAIL','WAIVED','BLOCKED','REVIEW','NOT_RUN','OUT_OF_SCOPE'):
        if state in statuses: return state
    if all(x in FINAL_GOOD for x in statuses):
        return 'PASS' if 'PASS' in statuses else 'NOT_APPLICABLE'
    return 'ERROR'

def ipa_assessment(report: dict) -> dict:
    mapping=read_json(HOME/'references/ipa-mapping.json')
    rows={r['id']:r for r in report['checks']}
    groups=[]
    for g in mapping['groups']:
        if len(set(g['check_ids']))!=len(g['check_ids']) or set(g['check_ids'])-set(rows):
            raise AuditError('IPA対応表に未知・重複check IDがあります。')
        states=[]
        for cid in g['check_ids']:
            r=rows[cid]; states.append(r['status'])
            if r['status']!='OUT_OF_SCOPE':
                states.extend(c['status'] for c in r.get('criteria_results',[]))
        state=aggregate_status(states)
        external='NOT_RUN' if report['profile']=='static' else state
        groups.append({**g,'static_status':state,'external_status':external,
                       'overall_status':aggregate_status([state,external]),
                       'external_note':'実環境未確認。コード/設定の合格では代用しません。' if report['profile']=='static' else '全範囲の項目・個別条件の証拠判定を参照。'})
    return {**mapping,'groups':groups,'verified_groups':sum(g['overall_status'] in FINAL_GOOD for g in groups),
            'group_count':len(groups),'mapped_check_count':len({c for g in groups for c in g['check_ids']})}

def artex_assessment(report: dict) -> dict:
    """Derived view from verified control results; never accepts input flags."""
    mapping=read_json(HOME/'references/artex-mapping.json')
    if not isinstance(mapping,dict) or mapping.get('schema_version')!=1 or not isinstance(mapping.get('groups'),list) or not mapping['groups']:
        raise AuditError('ARTEX対応表の形式が不正です。')
    rows={r['id']:r for r in report['checks']}; groups=[]; seen=set()
    for g in mapping['groups']:
        if not isinstance(g,dict) or not isinstance(g.get('id'),str) or g['id'] in seen:
            raise AuditError('ARTEX対応表に未知・重複theme IDがあります。')
        seen.add(g['id']); ids=g.get('check_ids')
        if not isinstance(ids,list) or not ids or any(not isinstance(cid,str) for cid in ids) or len(set(ids))!=len(ids) or set(ids)-set(rows):
            raise AuditError('ARTEX対応表に未知・重複check IDがあります。')
        states=[]
        for cid in ids:
            row=rows[cid]; states.append(row['status'])
            if row['status']!='OUT_OF_SCOPE': states.extend(x['status'] for x in row.get('criteria_results',[]))
        state=aggregate_status(states)
        groups.append({**g,'control_status':state,'static_status':state if report['profile']=='static' else 'NOT_ASSESSED',
                       'external_status':'NOT_RUN' if report['profile']=='static' else state,
                       'attack_simulation_status':'NOT_PERFORMED'})
    return {**mapping,'groups':groups,'group_count':len(groups),
            'mapped_check_count':len({cid for g in groups for cid in g['check_ids']}),
            'verified_control_groups':sum(g['control_status'] in FINAL_GOOD for g in groups),
            'attack_simulation_performed':False,'artex_attribution':'NOT_ASSESSED',
            'resistance_certified':False,'status_basis':report['profile']}

def assemble(inv: dict, catalog: list[dict], evidence_path: Path|None, repo: Path, *, profile='full') -> dict:
    if profile not in PROFILE_LABELS: raise AuditError('不明な検査profileです。')
    scoped=static_catalog(catalog) if profile=='static' else catalog
    allowed={c['id'] for c in scoped}
    if any(o.get('check_id') not in allowed for o in inv['observations']):
        raise AuditError('このprofileでは扱えない静的指摘があります。範囲設定を見直してください。')
    r=assemble_core(inv,scoped,evidence_path,repo,profile)
    r.update(profile=profile,profile_label=PROFILE_LABELS[profile],total_check_count=len(catalog),
             scope_check_count=len(scoped),all_clean_scope='STATIC_ONLY' if profile=='static' else 'FULL',
             full_audit={'verdict':'NOT_ASSESSED' if profile=='static' else r['verdict'],
                         'all_clean':False if profile=='static' else r['all_clean']})
    if profile=='static':
        done={x['id']:x for x in r['checks']}; rows=[]
        for c in catalog:
            if c['id'] in done: rows.append(done[c['id']]); continue
            rows.append({**c,'status':'OUT_OF_SCOPE','full_status':'NOT_RUN','assessment_scope':'external_only',
                         'rationale':c['static_review']['reason'],'observations':[],
                         'criteria_results':[{'id':d['id'],'status':'NOT_RUN','rationale':'実環境を含む検証が必要です。'} for d in c.get('criteria',[])]})
        r['checks']=rows
        r['counts']['OUT_OF_SCOPE']=len(catalog)-len(scoped)
    else:
        r['counts']['OUT_OF_SCOPE']=0
        for row in r['checks']: row['assessment_scope']='full'
    r['ipa']=ipa_assessment(r)
    r['artex']=artex_assessment(r)
    return r

def template(inv: dict, catalog: list[dict], *, profile='full') -> dict:
    if profile not in PROFILE_LABELS: raise AuditError('不明な検査profileです。')
    return template_core(inv,static_catalog(catalog) if profile=='static' else catalog,profile)

STYLE = '''
:root{color-scheme:light;--ink:#192d3c;--muted:#617281;--line:#dce4e9;--accent:#176b66;--paper:#f3f6f8;--red:#a92e3f}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans JP",sans-serif}a{color:var(--accent);text-underline-offset:3px}button,input,select{font:inherit;color:var(--ink)}button,select{cursor:pointer}button,input,select{background:#fff;border:1px solid #bbc9d2;border-radius:6px;padding:9px 11px;max-width:100%}button:hover{border-color:var(--accent);background:#f3f9f8}a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid #2c8b83;outline-offset:3px}[hidden]{display:none!important}h1,h2,h3,p{margin-top:0}h1{font-size:27px;line-height:1.35;margin-bottom:0}h2{font-size:19px;line-height:1.5;margin-bottom:0}h3{font-size:16px}p:last-child{margin-bottom:0}small,.muted,.legend,.section-intro,.section-meta{color:var(--muted)}small{font-size:11px}.legend{font-size:12px;margin:12px 0}.section-intro{font-size:13px;margin:6px 0 16px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.report-header{background:#fff;border-bottom:1px solid var(--line)}.header-inner,main{max-width:1264px;margin:auto;padding:22px 32px}.eyebrow{font-size:10px;font-weight:750;letter-spacing:.12em;color:var(--accent);display:flex;justify-content:space-between;margin-bottom:10px}.eyebrow span{color:var(--muted);letter-spacing:0}.header-heading,.verdict-line{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.header-heading{justify-content:space-between}.status{display:inline-block;border:1px solid #e3c37a;background:#fff7e4;color:#80590b;border-radius:6px;padding:4px 10px;font-size:12px;font-weight:700}.status.bad{background:#fff0f2;color:var(--red);border-color:#e4b7bf}.status.clean{background:#e8f5f0;color:#08614e;border-color:#a3cfbe}.scope-label{font-size:10px;letter-spacing:.02em;border:1px solid var(--line);padding:4px 8px;border-radius:5px;color:var(--muted)}.lead{margin:10px 0 0;color:var(--muted);font-size:12px;display:flex;gap:6px 24px;flex-wrap:wrap;overflow-wrap:anywhere}.lead strong{color:var(--ink);font-weight:500}.result-message{font-size:12px;color:var(--muted);margin:4px 0 0}.provenance-note{font-size:12px;border:1px solid #e5d3a7;border-radius:6px;background:#fff9eb;margin:0 0 16px}.provenance-note summary{padding:9px 12px;color:#785b22}.provenance-note p{padding:0 12px 12px;margin:0}.example-note{font-size:12px;background:#edf5fa;padding:9px 12px;border:1px solid #bed3e2;border-radius:6px;margin-bottom:16px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:12px}.metric{display:block;background:#fff;border:1px solid var(--line);border-radius:9px;padding:12px 18px;text-decoration:none;color:var(--ink);border-top:3px solid #bbc7d0}.metric:hover{box-shadow:0 3px 14px #21384612;border-color:#9aafb9}.metric>span{font-size:12px;font-weight:650}.metric b{display:block;font-size:32px;line-height:1.35;letter-spacing:-.025em;font-variant-numeric:tabular-nums}.metric .metric-unit{font-size:11px;font-weight:400;color:var(--muted);margin-left:7px;letter-spacing:0}.metric small{display:flex;justify-content:space-between;gap:5px;font-size:10px}.metric-fail{border-top-color:#bd4856}.metric-fail b{color:var(--red)}.metric-pending{border-top-color:#b89945}.metric-pass{border-top-color:var(--accent)}.metric-pass b{color:var(--accent)}.scope-context{display:flex;justify-content:space-between;flex-wrap:wrap;gap:2px 12px;font-size:11px;color:var(--muted)}.scope-context p{margin:0}.secondary-states{font-size:10px;margin:5px 0 12px}.view-nav{display:flex;gap:6px;position:sticky;top:0;z-index:3;background:var(--paper);padding:10px 0;margin-bottom:16px;border-bottom:1px solid var(--line)}.view-nav a{display:block;padding:9px 16px;text-decoration:none;color:var(--muted);font-weight:650;font-size:13px;border-radius:6px}.view-nav a:hover{background:#e7efef;color:var(--accent)}.view-nav a[aria-current=page]{background:var(--accent);color:#fff}.view-nav span{display:inline-block;border-radius:4px;font-size:10px;padding:0 5px;margin-left:4px;background:#ffffff24;color:inherit}.report-view{scroll-margin-top:70px}.section-heading{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}.section-heading>a{font-size:12px}.section-meta{font-size:12px}.summary-lead{font-size:15px;margin:8px 0 20px}.dashboard-grid{display:grid;grid-template-columns:1.12fr 1fr;gap:18px;align-items:start}.panel{background:#fff;border:1px solid var(--line);border-radius:9px;padding:20px;min-width:0}.dashboard-grid .panel{margin:0}.action-list{list-style:none;padding:0;margin:0}.action-list li{display:flex;gap:13px;align-items:start;border-top:1px solid var(--line);padding:15px 0}.action-list li:last-child{padding-bottom:0}.action-list .action-number{font:12px/1.8 ui-monospace,monospace;color:#a6b2ba}.action-list li>div{flex:1;min-width:0}.action-list a{font-size:14px;font-weight:650;color:var(--ink);text-decoration:none}.action-list a:hover{text-decoration:underline;color:var(--accent)}.action-list p{font-size:12px;color:var(--muted);margin:3px 0 0}.method-list{border-top:1px solid var(--line)}.method-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:11px 0;border-bottom:1px solid var(--line);text-decoration:none;color:var(--ink)}.method-row:hover strong{color:var(--accent);text-decoration:underline}.method-row>span{min-width:0}.method-row strong{font-size:13px;font-weight:650}.method-row small{display:block;font-size:10px;margin-top:2px}.method-row b{font-size:21px;font-weight:600;line-height:1.3;text-align:right;flex-shrink:0;font-variant-numeric:tabular-nums}.method-row b small{font-size:10px;font-weight:400;white-space:nowrap}.method-explanations summary{padding:12px 0 0;color:var(--muted);font-size:11px}.method-explanations dl{font-size:12px;grid-template-columns:1fr;gap:4px;margin-bottom:0}.method-explanations dd{margin:0 0 8px}.next-steps{margin:18px 0}.next-steps ul{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:22px;list-style:none;padding:0;margin:16px 0 0}.next-steps li{min-width:0;border-left:2px solid #bed4d1;padding-left:14px}.next-steps li strong{font-size:13px}.next-steps li p{font-size:12px;color:var(--muted);margin:5px 0 8px}.next-steps li a{font-size:11px}.category-summary{margin:18px 0}.category-summary table{font-variant-numeric:tabular-nums}.category-summary th,.category-summary td{padding:8px 10px}.category-summary tbody td{text-align:center;color:var(--muted)}.category-summary thead th:not(:first-child){text-align:center}.category-summary tbody th{font-size:12px;font-weight:500}.category-summary .has-findings{color:var(--red);font-weight:750;background:#fff5f6}
.toolbar{background:#fff;border:1px solid var(--line);border-radius:9px;padding:14px;margin:18px 0 0}.quick-filters{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:12px}.quick-filters button{padding:6px 11px;border:1px solid transparent;background:#eef3f5;font-size:12px}.quick-filters button[aria-pressed=true]{background:#dceeea;border-color:#9bbfb7;color:#0a5d55;font-weight:650}.filter-row{display:flex;gap:8px;flex-wrap:wrap}.filter-row input{flex:2;min-width:160px}.filter-row select{flex:1;min-width:0;font-size:12px}.filter-row button{font-size:12px}.advanced-filters{margin-top:10px}.advanced-filters summary{font-size:11px;padding:0;color:var(--muted)}.advanced-filters .filter-row{padding-top:10px}.list-meta{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 2px}.list-meta p{font-size:12px;font-weight:650;margin:0}.list-meta label{font-size:11px;color:var(--muted)}.list-meta select{font-size:11px;padding:5px 8px;border-color:var(--line)}.table-wrap{overflow-x:auto;max-width:100%;border-radius:7px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border-bottom:1px solid var(--line);padding:12px;text-align:left;vertical-align:top}thead th{background:#eaf0f4;color:#5a6c79;font-weight:600;font-size:11px}tbody th{font-weight:500}td,th{overflow-wrap:anywhere}.overview-wrap{border:1px solid var(--line);background:#fff}.overview-wrap table{table-layout:fixed}.overview-wrap thead th:nth-child(1){width:27%}.overview-wrap thead th:nth-child(2){width:18%}.overview-wrap thead th:nth-child(3){width:17%}.overview-row>th>a{font-size:13px;font-weight:650;color:var(--ink);text-decoration:none;display:block}.overview-row>th>a:hover{color:var(--accent);text-decoration:underline}.overview-row th small{display:block;font-size:10px;margin-top:5px}.overview-row .row-open{font-size:12px;color:#80939f}.overview-row td{font-size:12px}.overview-row[data-finding=true]>th{border-left:3px solid #c9626c;padding-left:9px}.overview-row[data-status=OUT_OF_SCOPE]{background:#f8fafb}.brief-cell p{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;font-size:11px;line-height:1.75;margin:0;color:#526572}.child-warning{display:block;color:var(--red);font-size:10px;margin-top:5px}.pill{display:inline-block;border:1px solid var(--line);border-radius:5px;padding:2px 6px;font-size:10px;font-weight:600;line-height:1.65;overflow-wrap:anywhere}.pill.PASS{color:#07604e;background:#edf7f2;border-color:#c3ddd0}.pill.FAIL,.pill.ERROR{color:var(--red);background:#fff1f3;border-color:#ebc8ce}.pill.REVIEW,.pill.BLOCKED,.pill.WAIVED{color:#7e601e;background:#fdf7e9;border-color:#e5dac0}.pill.NOT_RUN{color:#5e6b77;background:#f4f6f8}.pill.OUT_OF_SCOPE{color:#657582;background:#edf1f4}.pill.NOT_APPLICABLE{color:#536c75;background:#eef5f7}.method-label{color:#506571;background:#f0f5f5;border-color:#dbe5e7;font-size:10px;font-weight:500}.overview-row .pill{max-width:100%}.overview-row .method-label{border:0;background:transparent;padding:2px 0}
summary{cursor:pointer;padding:14px;line-height:1.6}summary:hover{background:#f7fafb}.title{flex:1;min-width:0;font-weight:650}.disclosure{border:1px solid var(--line);border-radius:9px;background:#fff;margin:16px 0;min-width:0}.disclosure>summary{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-weight:650}.disclosure>summary:before{content:'＋';color:var(--accent)}.disclosure[open]>summary:before{content:'−'}.disclosure[open]>summary{border-bottom:1px solid var(--line)}.disclosure-title{flex:1;min-width:0}.disclosure-body{padding:16px 20px;min-width:0}.disclosure-body h2{margin:6px 0 12px}.disclosure-body h3{margin-top:14px}.callout{border-left:3px solid #b28b33;background:#fff8e8;padding:12px 16px;font-size:12px;margin:16px 0}.callout.danger{border-color:#bd4858;background:#fff1f3}.coverage-panel{margin-top:0}.coverage-panel h2{margin-bottom:6px}.coverage-grid,.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.coverage-item{border:1px solid var(--line);border-radius:7px;min-width:0}.coverage-item summary{display:flex;align-items:center;gap:8px;font-size:12px;flex-wrap:wrap}.coverage-item p{padding:0 14px 14px;font-size:12px}.coverage-item[open] summary{border-bottom:1px solid var(--line);margin-bottom:12px}.pending-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:16px 0}.pending-item{border:1px solid var(--line);padding:14px;border-radius:7px;background:#fff}.pending-item b{font-size:22px;margin-left:8px}.pending-item p{font-size:12px;color:var(--muted);margin:6px 0}.pending-note{color:var(--muted);font-size:12px}.review-list{list-style:none;padding:0}.review-list li{padding:12px 0;border-bottom:1px solid var(--line)}.review-list li p{margin:5px 0;font-size:12px}.ipa-theme{border:1px solid var(--line);border-radius:8px;margin:10px 0}.ipa-theme summary{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.ipa-body{padding:10px 16px}.ipa-body p{font-size:12px}.ipa-links{padding:0 16px 16px}.check-link{display:inline-block;border:1px solid var(--line);border-radius:5px;padding:3px 7px;margin:3px;font-size:11px;text-decoration:none}.section-title{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:10px 0}.appendix-title{margin-top:26px}.sources{padding-left:20px}.sources li{margin:14px 0;overflow-wrap:anywhere}.scope-banner{background:#eef7f5;border:1px solid #b7d2cc;border-radius:8px;padding:16px;margin:16px 0}
dl{display:grid;grid-template-columns:135px minmax(0,1fr);gap:10px 18px}dt{font-weight:650;color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}code{font:11px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1b3445;color:#eef7fc;padding:16px;border-radius:7px}.criterion{border:1px solid #c9ddda;border-left:3px solid var(--accent);padding:12px 14px;margin:14px 0;border-radius:5px;background:#f5faf8}.criterion p{margin:5px 0}.criterion dl{margin:10px 0}details.check{background:#fff;border:1px solid var(--line);border-radius:8px;margin:12px 0;scroll-margin-top:80px;overflow:hidden}details.check>summary{display:flex;align-items:center;flex-wrap:wrap;gap:8px 12px}.check-summary-status{margin-left:auto}.version-badge{font-size:10px;display:none}.check-body{padding:4px 20px 20px;border-top:1px solid var(--line);font-size:12px}.check-body h4{margin-bottom:8px}.check-body>p{margin:14px 0}.check-body .muted{font-size:10px}#check-details>h2{margin-top:24px}#check-dialog{padding:0;border:1px solid #c6d4dc;border-radius:12px;width:min(840px,calc(100vw - 40px));max-width:none;max-height:88dvh;color:var(--ink);box-shadow:0 18px 70px #14293e38;overscroll-behavior:contain}#check-dialog::backdrop{background:#152e4599}.dialog-toolbar{position:sticky;top:0;z-index:1;background:#fff;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 18px;border-bottom:1px solid var(--line)}.dialog-toolbar h2{font-size:13px;color:var(--muted);font-weight:500}.dialog-toolbar button{font-size:12px;padding:6px 12px}#detail-content{padding:0 18px 18px}#detail-content details.check{margin:0;border:0;border-radius:0}#detail-content details.check>summary{pointer-events:none;padding:18px 0;font-size:17px;list-style:none}#detail-content details.check>summary::-webkit-details-marker{display:none}#detail-content details.check .check-body{padding:0;border:0}body.inspector-open{overflow:hidden}footer{font-size:10px;color:var(--muted);border-top:1px solid var(--line);padding:18px 0;margin-top:28px;overflow-wrap:anywhere}#priority,#methods,#pending,#sources,#audit-info{scroll-margin-top:75px}
@media(max-width:900px){.header-heading{align-items:flex-start}.header-inner,main{padding-left:22px;padding-right:22px}.dashboard-grid{grid-template-columns:1fr 1fr}.overview-wrap thead th:nth-child(1){width:28%}.overview-wrap thead th:nth-child(2){width:21%}.overview-wrap thead th:nth-child(3){width:20%}.metric{padding:12px}.next-steps ul{gap:14px}.filter-row input{flex-basis:100%}}
@media(max-width:650px){.header-inner,main{padding:17px 14px}h1{font-size:22px}.eyebrow{font-size:9px}.header-heading{gap:9px}.lead{display:block;font-size:11px;margin-top:9px}.lead span{display:block;margin-top:3px}.verdict-line{gap:6px}.status{font-size:11px}.scope-label{font-size:9px}.result-message{font-size:11px}.provenance-note{font-size:10px;margin-bottom:12px}.cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.metric{padding:9px 12px}.metric b{font-size:28px}.metric>span{font-size:11px}.metric small{font-size:9px}.scope-context{font-size:10px}.secondary-states{font-size:9px}.view-nav{gap:4px;padding:8px 0;margin-bottom:14px}.view-nav a{font-size:11px;padding:8px 9px;white-space:nowrap}.view-nav span{font-size:9px;padding:0 3px;margin-left:2px}.dashboard-grid{grid-template-columns:1fr;gap:12px}.summary-lead{font-size:13px;margin:6px 0 14px}.panel{padding:16px}.section-heading h2{font-size:17px}.summary-findings .section-heading{align-items:start}.section-heading>a{font-size:11px}.action-list li{gap:10px;padding:13px 0}.action-list a{font-size:13px}.action-list p{font-size:11px}.next-steps ul{grid-template-columns:1fr;gap:15px}.category-summary{padding:14px 10px}.category-summary th,.category-summary td{padding:8px 5px;font-size:10px}.category-summary th:first-child{min-width:110px}.category-summary tbody th{font-size:10px}.category-summary thead th{font-size:9px}.category-summary .section-heading,.category-summary .section-intro,.category-summary .legend{margin-left:4px;margin-right:4px}.category-summary .table-wrap{overflow-x:auto}.toolbar{padding:12px}.quick-filters{gap:5px}.quick-filters button{font-size:10px;padding:5px 8px}.filter-row input{width:100%;min-width:0}.filter-row select{flex-basis:calc(50% - 8px);font-size:10px;padding:9px 6px}.filter-row button{font-size:10px}.advanced-filters .filter-row select{flex-basis:100%}.list-meta p{font-size:11px}.list-meta label,.list-meta select{font-size:10px}.list-meta{gap:5px}.overview-wrap{border:0;border-radius:0;background:transparent;overflow:visible}.overview-wrap table,.overview-wrap tbody{display:block}.overview-wrap thead{position:absolute;width:1px;height:1px;clip:rect(0,0,0,0);overflow:hidden;white-space:nowrap}.overview-row{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);background:#fff;border:1px solid var(--line);border-radius:8px;margin:0 0 10px;padding:13px;gap:9px 8px}.overview-row th,.overview-row td{display:block;padding:0;border:0}.overview-row th{grid-column:1/-1}.overview-row>th>a{font-size:13px;min-height:22px}.overview-row[data-finding=true]>th{border:0;padding-left:0}.overview-row[data-finding=true]{border-left:3px solid #c9626c;padding-left:11px}.overview-row th small{margin-top:3px}.overview-row td[data-label]:before{content:attr(data-label);display:block;font-size:9px;color:var(--muted);margin-bottom:3px}.overview-row .brief-cell{grid-column:1/-1;border-top:1px solid var(--line);padding-top:9px}.brief-cell p{font-size:11px}.overview-row .pill{font-size:9px}.overview-row .method-label{padding:2px 0}.coverage-grid,.grid2{grid-template-columns:1fr}.pending-grid{grid-template-columns:1fr}.disclosure-body{padding:14px}.disclosure>summary{font-size:12px;padding:12px}dl{grid-template-columns:1fr;gap:4px}dd{margin-bottom:10px}.check-body{padding:0 14px 14px}.check-body .pill{font-size:9px}#check-dialog{width:calc(100vw - 20px);max-height:92dvh;border-radius:9px}.dialog-toolbar{padding:10px 13px}#detail-content{padding:0 14px 14px}#detail-content details.check>summary{font-size:15px}.check-summary-status{margin-left:0}.check-body dt{margin-top:8px}.criterion{padding:10px}.pill{white-space:normal}.ipa-theme .title{flex-basis:100%}footer{font-size:9px}}
@media print{body{background:#fff;font-size:10px}.header-inner,main{max-width:none;padding:0}.report-header{padding-bottom:10px}.view-nav,.toolbar,.list-meta,#empty-state,.dialog-toolbar,button{display:none!important}.cards{gap:8px}.metric{padding:9px}.metric b{font-size:24px}.dashboard-grid{grid-template-columns:1fr 1fr}.report-view{margin:20px 0}.overview-wrap table{table-layout:auto;font-size:9px}.overview-wrap th,.overview-wrap td{padding:5px}.overview-row{display:table-row}.overview-row th,.overview-row td{display:table-cell}.brief-cell p{display:block;overflow:visible;-webkit-line-clamp:unset}.panel{break-inside:avoid}.category-summary{break-inside:auto}.check{break-inside:avoid}.check-body{font-size:10px}#check-dialog{display:none}footer{font-size:9px}.next-steps ul{grid-template-columns:1fr 1fr 1fr}.provenance-note p{display:block}a{color:inherit}}
'''

# Presentation labels only; stored statuses and evidence semantics stay unchanged.
STATUS_LABELS = {'PASS':'確認済み','FAIL':'不備あり','REVIEW':'判断待ち',
    'NOT_RUN':'未確認','BLOCKED':'確認できず','ERROR':'エラー',
    'NOT_APPLICABLE':'承認済み非該当','WAIVED':'リスク受容','OUT_OF_SCOPE':'今回対象外',
    'NOT_ASSESSED':'未評価','NOT_PERFORMED':'未実施'}

def status_text(state: str) -> str:
    return STATUS_LABELS.get(state,state)+' / '+state if state in STATUS_LABELS else state

def status_pill(state: str) -> str:
    return '<span class="pill '+esc(state)+'">'+esc(status_text(state))+'</span>'

# These are presentation categories for the required verification, not proof of
# execution. Static projection always takes precedence over the full check.
VERIFICATION_METHODS = {
    'static': ('静的解析', 'コード・設定・提供された資料を読みます。テストコードも定義の確認までで、実行成功は証明しません。'),
    'runtime': ('動作検証', 'アプリやAPIを動かした実行結果・応答で確認します。静的モードでは実施せず、別途認可された環境の証拠が必要です。'),
    'configuration': ('実環境の設定・権限確認', '実際のクラウド・ID・公開範囲などを設定の取得記録と照合します。Terraformの記述だけでは適用済みと判断しません。'),
    'records': ('ログ・運用記録の確認', '対象期間・資産を特定した実ログや判断記録を確認します。監視ルールの定義と、実際に調査した記録を分けます。'),
    'drill': ('復旧・対応訓練', '復元、失効、封じ込めなどの演習記録で確認します。手順書やバックアップ成功の記録だけで復旧可能と判断しません。'),
}
METHOD_CONFIGURATION = frozenset(('GIT-05','GIT-06','GIT-08','GIT-10','REL-07','CLD-07','CLD-10','DEV-04','RAN-02-10'))
METHOD_RECORDS = frozenset(('REL-10','AIM-09','IR-04','IR-08','IR-10','RAN-01-06','RAN-01-10','RAN-02-09','RAN-03-03','RAN-04-01','RAN-04-02','RAN-04-03','RAN-04-10'))
METHOD_DRILL = frozenset(('IR-02','IR-03','IR-06','IR-07','RAN-04-04','RAN-04-05','RAN-04-06','RAN-04-07','RAN-04-08','RAN-04-09'))

def verification_method(row: dict) -> str:
    scope=row.get('assessment_scope')
    if scope=='static' or (scope is None and row.get('static_review',{}).get('in_scope')):
        return 'static'
    cid=row['id']
    if cid in METHOD_DRILL: return 'drill'
    if cid in METHOD_RECORDS: return 'records'
    if cid in METHOD_CONFIGURATION: return 'configuration'
    if not row.get('static_review',{}).get('in_scope'): return 'runtime'
    if cid.startswith(('AUT-','AZ-','INJ-','WEB-','INT-','AIM-')) and cid not in {'WEB-06','INT-01'}:
        return 'runtime'
    if cid.startswith(('CLD-','CTR-')): return 'configuration'
    if cid.startswith(('OBS-','IR-')) or cid in {'INT-01','DAT-01','TST-10'}: return 'records'
    if cid in {'DAT-05','DAT-06','TST-02','TST-07','TST-09'}: return 'runtime'
    return 'static'

def method_pill(row: dict) -> str:
    return '<span class="pill method-label">'+VERIFICATION_METHODS[verification_method(row)][0]+'</span>'

def verification_html(report: dict) -> str:
    groups={key:[] for key in VERIFICATION_METHODS}
    for row in report['checks']: groups[verification_method(row)].append(row)
    body='<section id="methods" class="panel method-summary"><div class="section-heading"><h2>確認方法ごとのサマリー</h2></div><p class="section-intro">主な確認方法で分類しています。分類は実施済みの意味ではありません。</p><div class="method-list">'
    for key,(label,explanation) in VERIFICATION_METHODS.items():
        rows=groups[key]
        counts=collections.Counter(r['status'] for r in rows)
        state_summary=' / '.join(STATUS_LABELS.get(state,state)+' '+str(counts[state]) for state in (*STATES,'OUT_OF_SCOPE') if counts[state]) or '該当項目なし'
        body+='<a class="method-row" href="#checks" data-method-shortcut="'+key+'"><span><strong>'+label+'</strong><small>'+esc(state_summary)+'</small></span><b>'+str(len(rows))+'<small>項目 →</small></b></a>'
    body+='</div><details class="method-explanations"><summary>確認方法の違いを読む</summary><dl>'
    for label,explanation in VERIFICATION_METHODS.values():
        body+='<dt>'+label+'</dt><dd>'+explanation+'</dd>'
    return body+'</dl></details></section>'

def static_finding_help(row: dict) -> str:
    if row.get('assessment_scope')!='static': return ''
    help_text={
        'WEB-04': ('ブラウザーが実行してよいスクリプトを制限する防御の確認です。不備だけでXSSの成立を断定するものではありません。','HTML配信のヘッダーや関連設定。必要なスクリプトの許可方法も合わせて設計します。'),
        'OBS-07': ('後から「誰が・何を・どう操作したか」を追跡できるかの確認です。','アプリのログ出力と保存設定。実際に記録・保管されるかは追加の確認が必要です。'),
        'OBS-09': ('データ取得の異常を検知し、対応する担当へつなぐ仕組みの確認です。','監視ルール、通知先、停止・失効の手順。閾値は業務の通常利用とリスクに合わせて決めます。'),
        'TST-02': ('権限のない操作を拒否するテストの「定義」の確認です。権限を突破できたと実証した指摘ではありません。','テストコードとケース定義。追加後のテスト成功は別の動作検証で確認します。'),
    }
    meaning,location=help_text.get(row['id'],('提供されたコード・設定・資料が、静的な合格条件を満たしているかの確認です。','該当するソース・設定・資料。修正内容を新しいsnapshotで再レビューします。'))
    return '<p>'+esc(meaning)+'</p><p><strong>対応する場所：</strong>'+esc(location)+'</p>'

SCRIPT = '''
const items=[...document.querySelectorAll('details.check')];
const byId=new Map(items.map(el=>[el.id,el]));
const rows=[...document.querySelectorAll('.overview-row')];
const q=document.getElementById('search'),s=document.getElementById('status-filter'),c=document.getElementById('category-filter'),v=document.getElementById('revision-filter'),m=document.getElementById('method-filter');
const views=[...document.querySelectorAll('[data-report-view]')];
const store=document.getElementById('check-details'),dialog=document.getElementById('check-dialog'),content=document.getElementById('detail-content');
const modalAvailable=Boolean(dialog&&typeof dialog.showModal==='function');
let currentView='summary',activeCheck=null,placeholder=null,originView='checks',originFocus=null;
function activateView(name){
  if(!views.some(el=>el.dataset.reportView===name))return;
  currentView=name;
  views.forEach(el=>el.hidden=el.dataset.reportView!==name);
  document.querySelectorAll('[data-view-link]').forEach(el=>{
    if(el.dataset.viewLink===name)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');
  });
}
function restoreCheck(){
  if(!activeCheck)return;
  activeCheck.querySelector('summary')?.removeAttribute('tabindex');
  if(placeholder?.isConnected)placeholder.replaceWith(activeCheck);
  activeCheck=null;placeholder=null;
  document.body.classList.remove('inspector-open');
}
function dismissInspector(reason='close'){
  if(!activeCheck&&!dialog?.open)return;
  const returnView=originView,returnFocus=originFocus;
  restoreCheck();
  if(dialog?.open)dialog.close(reason);
  if(reason==='close'){
    activateView(returnView);
    const anchor=returnView==='reference'?'coverage':returnView;
    history.replaceState(null,'','#'+anchor);
    if(returnFocus?.isConnected&&!returnFocus.closest('[hidden]'))returnFocus.focus({preventScroll:true});
  }
}
function openCheck(el){
  if(!modalAvailable){
    activateView('checks');if(store)store.hidden=false;
    el.hidden=false;el.open=true;el.scrollIntoView({block:'start'});return;
  }
  if(activeCheck===el)return;
  if(activeCheck)restoreCheck();
  originView=currentView;originFocus=document.activeElement;
  placeholder=document.createComment('check detail position');
  el.before(placeholder);content.appendChild(el);activeCheck=el;
  el.hidden=false;el.open=true;el.querySelector('summary')?.setAttribute('tabindex','-1');
  document.body.classList.add('inspector-open');
  dialog.returnValue='';if(!dialog.open)dialog.showModal();
  dialog.scrollTop=0;document.getElementById('detail-close')?.focus();
}
function filter(){
  const term=(q?.value||'').trim().toLocaleLowerCase();let count=0;
  for(const row of rows){
    const el=byId.get(row.dataset.checkId);if(!el)continue;
    const revision=!v?.value||(v.value==='8'?el.dataset.artexRevision==='8':v.value==='artex'?el.dataset.artex==='true':v.value==='6'?el.dataset.ipaRevision==='6':v.value==='ipa'?el.dataset.ipa==='true':v.value==='static'?el.dataset.static==='true':v.value==='external'?el.dataset.static==='false':el.dataset.revision===v.value);
    const status=!s?.value||(s.value==='findings'?row.dataset.finding==='true':s.value==='pending'?['REVIEW','NOT_RUN','BLOCKED','ERROR'].includes(el.dataset.status):el.dataset.status===s.value);
    const ok=revision&&status&&(!m?.value||el.dataset.method===m.value)&&(!c?.value||el.dataset.category===c.value)&&el.textContent.toLocaleLowerCase().includes(term);
    row.hidden=!ok;if(el!==activeCheck)el.hidden=!ok;if(ok)count++;
  }
  const n=document.getElementById('visible-count');if(n)n.textContent=count+' / '+rows.length+' 項目を表示';
  const empty=document.getElementById('empty-state');if(empty)empty.hidden=count!==0;
  document.querySelectorAll('button[data-status-shortcut]').forEach(el=>el.setAttribute('aria-pressed',String(el.dataset.statusShortcut===(s?.value||''))));
}
function resetFilters(){[q,s,c,v,m].filter(Boolean).forEach(el=>el.value='');}
function showChecks(){
  dismissInspector('navigate');activateView('checks');
  if(location.hash!=='#checks')location.hash='checks';else document.getElementById('checks')?.scrollIntoView({block:'start'});
}
[q,s,c,v,m].filter(Boolean).forEach(el=>el.addEventListener('input',filter));
document.querySelectorAll('[data-status-shortcut],[data-method-shortcut],[data-category-shortcut]').forEach(el=>el.addEventListener('click',event=>{
  event.preventDefault();resetFilters();
  if(el.hasAttribute('data-status-shortcut')&&s)s.value=el.dataset.statusShortcut;
  if(el.hasAttribute('data-method-shortcut')&&m)m.value=el.dataset.methodShortcut;
  if(el.hasAttribute('data-category-shortcut')&&c)c.value=el.dataset.categoryShortcut;
  filter();showChecks();
}));
document.querySelectorAll('[data-reset-filters]').forEach(el=>el.addEventListener('click',()=>{resetFilters();filter()}));
document.getElementById('sort-order')?.addEventListener('input',event=>{
  const key=event.target.value==='definition'?'order':'priority';
  [...rows].sort((a,b)=>Number(a.dataset[key])-Number(b.dataset[key])).forEach(el=>el.parentElement.appendChild(el));
});
document.getElementById('detail-close')?.addEventListener('click',()=>dismissInspector());
dialog?.addEventListener('cancel',event=>{event.preventDefault();dismissInspector()});
dialog?.addEventListener('close',restoreCheck);
function revealHash(scroll=true){
  let id;try{id=decodeURIComponent(location.hash.slice(1))}catch{return}
  if(byId.has(id)){dismissInspector('navigate');activateView('checks');openCheck(byId.get(id));return}
  dismissInspector('navigate');
  const el=document.getElementById(id);
  if(!el){activateView('summary');return}
  const view=el.closest('[data-report-view]');activateView(view?.dataset.reportView||'summary');
  if(el.matches('details'))el.open=true;
  let parent=el.parentElement?.closest('details');while(parent){parent.open=true;parent=parent.parentElement?.closest('details')}
  if(scroll)el.scrollIntoView({block:'start'});
}
window.addEventListener('hashchange',()=>revealHash());
document.addEventListener('click',event=>{
  const link=event.target.closest('a[href^="#"]');if(!link)return;
  let id;try{id=decodeURIComponent(link.hash.slice(1))}catch{return}
  if(byId.has(id)){
    event.preventDefault();openCheck(byId.get(id));
    if(location.hash!==link.hash)history.pushState(null,'',link.hash);
  }else if(link.hash===location.hash&&!link.hasAttribute('data-status-shortcut')&&!link.hasAttribute('data-method-shortcut')&&!link.hasAttribute('data-category-shortcut')){
    event.preventDefault();revealHash();
  }
});
let printState=null;
window.addEventListener('beforeprint',()=>{
  const selected=activeCheck,view=currentView;
  dismissInspector('print');
  const disclosures=[...document.querySelectorAll('details')];
  printState={view,selected,open:disclosures.map(el=>[el,el.open])};
  disclosures.forEach(el=>el.open=true);views.forEach(el=>el.hidden=false);
  if(store)store.hidden=false;items.forEach(el=>el.hidden=false);rows.forEach(el=>el.hidden=false);
});
window.addEventListener('afterprint',()=>{
  if(!printState)return;
  printState.open.forEach(([el,open])=>el.open=open);
  activateView(printState.view);if(store&&modalAvailable)store.hidden=true;filter();
  if(printState.selected)openCheck(printState.selected);printState=null;
});
if(store&&modalAvailable)store.hidden=true;
activateView('summary');filter();revealHash(Boolean(location.hash));
'''

def document(title: str, body: str) -> str:
    digest=base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    csp=f"default-src 'none'; script-src 'sha256-{digest}'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'"
    return '<!doctype html>\n<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="'+html.escape(csp,quote=True)+'"><meta name="referrer" content="no-referrer"><title>'+esc(title)+'</title><style>'+STYLE+'</style></head><body>'+body+'<script>'+SCRIPT+'</script></body></html>'

def toolbar(catalog, report=True):
    cats={x['category_id']:x['category'] for x in catalog}
    opts=''.join('<option value="'+esc(k)+'">'+esc(v)+'</option>' for k,v in cats.items())
    method_opts='<select id="method-filter" aria-label="確認方法"><option value="">すべての確認方法</option>'+''.join('<option value="'+key+'">'+label+'</option>' for key,(label,_) in VERIFICATION_METHODS.items())+'</select>'
    states=''.join('<option value="'+x+'">'+esc(status_text(x))+'</option>' for x in (*STATES, 'OUT_OF_SCOPE'))
    shortcuts='<div class="quick-filters" aria-label="よく使う絞り込み">'+''.join('<button type="button" data-status-shortcut="'+value+'" aria-pressed="'+('true' if not value else 'false')+'">'+label+'</button>' for value,label in (('','すべて'),('findings','不備あり'),('pending','確認待ち'),('PASS','確認済み'),('OUT_OF_SCOPE','今回対象外')))+'</div>' if report else ''
    revision='<select id="revision-filter" aria-label="変更箇所"><option value="">全項目</option><option value="8">v8で強化した8項目</option><option value="artex">ARTEX関連の53項目</option><option value="5">v5で強化した54項目</option><option value="6">v6で強化した8項目</option><option value="ipa">IPAに対応する36項目</option><option value="static">静的判定の対象172項目</option><option value="external">実環境中心の48項目</option></select>'
    return '<div class="toolbar">'+shortcuts+'<div class="filter-row"><input id="search" type="search" aria-label="項目を検索" placeholder="項目名・ID・判定根拠を検索">'+method_opts+'<select id="category-filter" aria-label="分野"><option value="">全分野</option>'+opts+'</select><button type="button" data-reset-filters>リセット</button></div><details class="advanced-filters"><summary>判定・変更箇所で絞り込む</summary><div class="filter-row">'+('<select id="status-filter" aria-label="判定"><option value="">全判定</option><option value="findings">不備あり（個別条件を含む）</option><option value="pending">確認待ち</option>'+states+'</select>' if report else '')+revision+'</div></details></div><div class="list-meta"><p id="visible-count" aria-live="polite"></p><label>並び順 <select id="sort-order"><option value="priority">不備・確認待ちから</option><option value="definition">定義順</option></select></label></div>'


def cards_html(rows, design=False):
    parts=[]
    public_source_ids={s['id'] for s in public_sources()}
    for row in rows:
        state='NOT_RUN' if design else row['status']
        method=verification_method(row)
        pairs=[('確認方法',VERIFICATION_METHODS[method][0]+'：'+VERIFICATION_METHODS[method][1]),('内部照合ID',row['id']),('適用条件',row['applicability']),('検証方法',row['verification']),('合格条件',row['pass_criteria']),('修正方針',row['remediation'])]
        if not design:
            pairs+=[('判定根拠',row.get('rationale','')),('確認者',row.get('reviewer','未確認')),('確認日時',row.get('reviewed_at','未確認'))]
            if row.get('approved_by'): pairs.append(('適用外・例外承認',row['approved_by']))
            if row.get('owner'): pairs.append(('修正担当',row['owner']))
            if row.get('due_at'): pairs.append(('対応期限',row['due_at']))
        if row.get('static_review',{}).get('in_scope') and row.get('assessment_scope')!='static':
            pairs.append(('静的profileでの検証',' '.join(x['verification'] for x in row['static_review']['criteria'])))
            pairs.append(('静的側の合格条件',' '.join(x['expectation'] for x in row['static_review']['criteria'])))
        if row.get('static_review',{}).get('limitation'): pairs.append(('静的検証の限界',row['static_review']['limitation']))
        if row.get('full_verification'): pairs.extend([('実環境を含む元の検証（未実施）',row['full_verification']),('全体側の合格条件（未判定）',row['full_pass_criteria'])])
        if row.get('artex_groups'): pairs.append(('ARTEX / AI悪用対策', ' / '.join(row['artex_groups'])+' — '+row.get('artex_decision','REUSE_EXISTING')+'（攻撃実施・帰属認定ではない）'))
        if row.get('ipa_groups'): pairs.append(('IPA対応', ' / '.join(row['ipa_groups'])+' — '+row.get('ipa_decision','REUSE_EXISTING')))
        if row.get('scope_boundary'): pairs.append(('重複の整理',row['scope_boundary']))
        dt=''.join('<dt>'+esc(k)+'</dt><dd>'+esc(v)+'</dd>' for k,v in pairs)
        obs=''
        if row.get('observations'):
            obs='<h4>静的確認候補（秘密値・コード断片は非表示）</h4><div class="table-wrap"><table><thead><tr><th>位置</th><th>確認内容</th><th>候補ID</th></tr></thead><tbody>'
            for o in row['observations']:
                obs+='<tr><td><code>'+esc(o['path'])+(':'+str(o['line']) if o['line'] else '')+'</code></td><td>'+esc(o['message'])+'</td><td><code>'+esc(o['id'])+'</code></td></tr>'
            obs+='</tbody></table></div>'
        evid=''
        for ref in row.get('evidence',[]):
            evid+='<p><strong>証拠：</strong><code>'+esc(ref['artifact'])+'</code><br>'+esc(ref['summary'])+'<br><small>SHA256 '+esc(ref['sha256'])+'</small></p>'
        for r in row.get('resolved_observations',[]):
            evid+='<p><strong>候補判定：</strong><code>'+esc(r['id'])+'</code> — '+esc(r['rationale'])+'</p>'
        criteria=''
        child_results={x['id']:x for x in row.get('criteria_results',[])}
        if row.get('criteria'):
            criteria='<h4>この検査範囲の個別合格条件（項目数には重複加算しません）</h4>'
            for d in row['criteria']:
                r=child_results.get(d['id'],{'status':'NOT_RUN'})
                cs='NOT_RUN' if design else r['status']
                criteria+='<section class="criterion"><p><code>'+esc(d['id'])+'</code> <span class="pill '+esc(cs)+'">'+('未監査' if design else esc(status_text(cs)))+'</span></p><p><strong>'+esc(d['expectation'])+'</strong></p><dl><dt>具体的な検証</dt><dd>'+esc(d['verification'])+'</dd><dt>必要証拠</dt><dd>'+esc(' / '.join(d['required_evidence']))+'</dd>'
                if not design:
                    criteria+='<dt>判定根拠</dt><dd>'+esc(r.get('rationale','未検証'))+'</dd><dt>確認者</dt><dd>'+esc(r.get('reviewer','親の非該当承認を参照' if r.get('covered_by_parent') else '未確認'))+'</dd>'
                    for ref in r.get('evidence',[]):
                        criteria+='<dt>証拠</dt><dd><code>'+esc(ref['artifact'])+'</code><br>'+esc(ref['summary'])+'<br><small>SHA256 '+esc(ref['sha256'])+'</small></dd>'
                criteria+='</dl></section>'
        refs=' '.join('<a href="#'+esc(sid)+'">'+esc(sid)+'</a>' for sid in row.get('source_ids',[]) if sid in public_source_ids)
        if not refs: refs='一般化した防御条件。個別事例は配布対象外。'
        help_text=static_finding_help(row) if not design and (state=='FAIL' or any(r['status']=='FAIL' for r in row.get('criteria_results',[]))) else ''
        parts.append('<details id="'+esc(row['id'])+'" class="check" data-artex-revision="'+str(row.get('artex_revision',0))+'" data-artex="'+('true' if row.get('artex_groups') else 'false')+'" data-ipa-revision="'+str(row.get('ipa_revision',0))+'" data-ipa="'+('true' if row.get('ipa_groups') else 'false')+'" data-static="'+('true' if row.get('static_review',{}).get('in_scope') else 'false')+'" data-revision="'+str(row.get('revision',4))+'" data-status="'+esc(state)+'" data-category="'+esc(row['category_id'])+'" data-method="'+method+'"><summary>'+method_pill(row)+'<span class="title">'+esc(row['title'])+'</span>'+('<span class="version-badge">v8 強化</span>' if row.get('artex_revision')==8 else '<span class="version-badge">v6 強化</span>' if row.get('ipa_revision')==6 else '<span class="version-badge">v5 強化</span>' if row.get('revision')==5 else '')+'<span class="check-summary-status pill '+esc(state)+'">'+('未監査' if design else esc(status_text(state)))+'</span></summary><div class="check-body"><p class="muted">'+esc(row['category'])+' / 統制の既定優先度：'+esc(row['severity'])+'（今回の指摘の重大度を表すものではありません）。</p>'+help_text+'<dl>'+dt+'</dl>'+criteria+obs+evid+'<p><small>設計背景：'+refs+'</small></p></div></details>')
    return ''.join(parts)

def public_sources() -> list[dict]:
    # Only explicitly distributable references may enter generated HTML.
    # Private provenance stays outside the skill; do not load a local case folder.
    path=HOME/'references/sources.json'
    if not path.exists(): return []
    return [s for s in read_json(path) if s.get('visibility')=='public']

def source_html() -> str:
    out='<h2 id="sources">公式の技術資料・指針</h2><p>一般的な対策の設計に参照した公式資料です。個別企業・組織の事故説明や事例記事は掲載しません。確認時点は各資料に記録し、今回一律に再検証したとは扱いません。統制は本スキル独自の設計であり、規格認証を表しません。</p><ol class="sources">'
    for s in public_sources():
        url=s['url']
        if not url.startswith('https://'): continue
        out+='<li id="'+esc(s['id'])+'"><strong>'+esc(s['id']+' · '+s['publisher'])+'</strong> — <a href="'+html.escape(url,quote=True)+'" rel="noreferrer noopener">'+esc(s['title'])+'</a><br><small>'+esc(s['date_note']+' / '+s.get('verification_note','旧版からの参照。実監査時に再確認。'))+'</small></li>'
    return out+'</ol>'

def failed_checks(report: dict) -> list[dict]:
    # A pending parent must not hide a FAIL in its individual conditions.
    return [r for r in report['checks'] if r['status']=='FAIL' or
        any(c['status']=='FAIL' for c in r.get('criteria_results',[]))]

PENDING_STATES = ('REVIEW','NOT_RUN','BLOCKED','ERROR')

def report_buckets(rows: list[dict]) -> dict:
    """Exclusive parent-status counts for presentation; never infer a verdict."""
    counts=collections.Counter(row['status'] for row in rows)
    return {'total':len(rows),'fail':counts['FAIL'],
            'pending':sum(counts[state] for state in PENDING_STATES),
            'pass':counts['PASS'],'outside':counts['OUT_OF_SCOPE'],
            'not_applicable':counts['NOT_APPLICABLE'],'waived':counts['WAIVED']}

def check_brief(row: dict) -> str:
    failed=[c for c in row.get('criteria_results',[]) if c['status']=='FAIL']
    if failed and row['status']!='FAIL':
        return '個別条件に不備。'+failed[0].get('rationale','詳細の根拠を確認してください。')
    if row['status']=='OUT_OF_SCOPE':
        return '今回の静的確認の対象外。実環境での確認が必要です。'
    return row.get('rationale') or '詳細の検証方法と必要な証拠を確認してください。'

def overview_html(report: dict) -> str:
    """A compact index over the same controls whose evidence appears in details."""
    rank={'FAIL':0,'ERROR':1,'REVIEW':2,'BLOCKED':3,'NOT_RUN':4,
          'WAIVED':5,'PASS':6,'NOT_APPLICABLE':7,'OUT_OF_SCOPE':8}
    findings={r['id'] for r in failed_checks(report)}
    ordered=sorted(enumerate(report['checks']),key=lambda p:(-1 if p[1]['id'] in findings else rank.get(p[1]['status'],9),p[0]))
    body='<div class="table-wrap overview-wrap"><table id="check-overview"><caption class="sr-only">全チェック項目の判定・確認方法・要点。項目名から詳細を開けます。</caption><thead><tr><th scope="col">項目 / 分野</th><th scope="col">判定</th><th scope="col">確認方法</th><th scope="col">今回の要点</th></tr></thead><tbody>'
    for priority,(order,row) in enumerate(ordered):
        finding=row['id'] in findings
        body+='<tr class="overview-row" data-check-id="'+esc(row['id'])+'" data-status="'+esc(row['status'])+'" data-method="'+verification_method(row)+'" data-category="'+esc(row['category_id'])+'" data-finding="'+str(finding).lower()+'" data-order="'+str(order)+'" data-priority="'+str(priority)+'">'
        body+='<th scope="row"><a href="#'+esc(row['id'])+'">'+esc(row['title'])+'<span class="row-open" aria-hidden="true"> ↗</span></a><small>'+esc(row['category'])+'</small></th>'
        body+='<td data-label="判定">'+status_pill(row['status'])+('<small class="child-warning">個別条件に不備</small>' if finding and row['status']!='FAIL' else '')+'</td>'
        body+='<td data-label="確認方法">'+method_pill(row)+'</td><td class="brief-cell"><p>'+esc(check_brief(row))+'</p></td></tr>'
    return body+'</tbody></table></div><p id="empty-state" class="panel" hidden>一致する項目がありません。<button type="button" data-reset-filters>絞り込みを解除</button></p>'

def category_summary_html(report: dict) -> str:
    groups={}
    for row in report['checks']:
        group=groups.setdefault(row['category_id'],{'title':row['category'],'rows':[]})
        group['rows'].append(row)
    other=any(row['status'] in {'NOT_APPLICABLE','WAIVED'} for row in report['checks'])
    body='<section class="panel category-summary"><div class="section-heading"><h2>分野別サマリー</h2><span class="section-meta">'+str(len(groups))+'分野</span></div><p class="section-intro">分野名を選ぶと、その分野の項目を一覧で確認できます。</p><div class="table-wrap"><table id="category-summary"><thead><tr><th scope="col">分野</th><th scope="col">全項目</th><th scope="col">不備</th><th scope="col">確認待ち</th><th scope="col">確認済み</th><th scope="col">対象外</th>'+('<th scope="col">非該当 / 受容</th>' if other else '')+'</tr></thead><tbody>'
    for cid,g in groups.items():
        b=report_buckets(g['rows'])
        body+='<tr data-category-summary="'+esc(cid)+'"><th scope="row"><a href="#checks" data-category-shortcut="'+esc(cid)+'">'+esc(g['title'])+'</a></th>'
        for key in ('total','fail','pending','pass','outside'):
            body+='<td data-count="'+key+'"'+(' class="has-findings"' if key=='fail' and b[key] else '')+'>'+str(b[key])+'</td>'
        if other: body+='<td>'+str(b['not_applicable'])+' / '+str(b['waived'])+'</td>'
        body+='</tr>'
    return body+'</tbody></table></div><p class="legend">親項目の判定を集計。対象外も全項目に含みます。個別条件の不備は上の不備一覧にも表示します。</p></section>'

def summary_findings_html(report: dict) -> str:
    failed=failed_checks(report)
    labels={'WEB-04':'スクリプトの実行制限','OBS-07':'操作を追跡するログ',
            'OBS-09':'大量取得の監視・通知','TST-02':'権限拒否のテスト定義'}
    locations={'WEB-04':'HTML配信・CSP設定','OBS-07':'アプリのログ出力・保存設定',
               'OBS-09':'監視ルール・通知先・対応手順','TST-02':'テストコード・ケース定義'}
    body='<section id="priority" class="panel summary-findings"><div class="section-heading"><h2>確認できた不備 · '+str(len(failed))+'項目</h2><a href="#checks" data-status-shortcut="findings">一覧で見る →</a></div>'
    if not failed:
        return body+'<p>証拠付きのFAILはまだありません。未確認・対象外が残る場合は、安全性を判断できません。</p></section>'
    body+='<p class="section-intro">修正の入口をまとめています。項目名から根拠と合格条件を開けます。</p><ol class="action-list">'
    for i,row in enumerate(failed,1):
        location=locations.get(row['id'],row['remediation']) if row.get('assessment_scope')=='static' else row['remediation']
        body+='<li><span class="action-number" aria-hidden="true">'+str(i).zfill(2)+'</span><div><a href="#'+esc(row['id'])+'">'+esc(labels.get(row['id'],row['title']))+' <span aria-hidden="true">↗</span></a><p>'+esc(location)+'</p>'+('<small class="child-warning">親判定は'+esc(STATUS_LABELS.get(row['status'],row['status']))+'・個別条件にFAIL</small>' if row['status']!='FAIL' else '')+'</div>'+status_pill('FAIL')+'</li>'
    return body+'</ol><p class="legend">FAILは証拠に基づく不備です。修正後の再確認が必要です。</p></section>'

def next_steps_html(report: dict) -> str:
    pending=sum(report['counts'].get(state,0) for state in PENDING_STATES)
    missing=[d['title'] for d in report['coverage'].values() if d['status'] not in {'PASS','NOT_APPLICABLE'}]
    body='<section class="panel next-steps"><div class="section-heading"><h2>次に進めること</h2></div><ul>'
    if failed_checks(report): body+='<li><strong>不備の修正</strong><p>根拠と修正先を確認し、更新したsnapshotで再確認します。</p></li>'
    if report['counts'].get('WAIVED',0): body+='<li><strong>受容したリスクの確認</strong><p>例外の理由、担当、期限を確認します。受容は合格と区別します。</p><a href="#checks" data-status-shortcut="WAIVED">受容リスクを見る →</a></li>'
    if pending: body+='<li><strong>確認待ち '+str(pending)+'項目の整理</strong><p>判断・証拠・資料の不足を一覧から確認します。</p><a href="#checks" data-status-shortcut="pending">確認待ちを見る →</a></li>'
    if missing:
        body+='<li><strong>検査資料の補完</strong><p>'+esc('、'.join(missing))+'。</p><a href="#coverage">不足している範囲を見る →</a></li>'
    elif report.get('incomplete'):
        body+='<li><strong>個別条件・未解析範囲の確認</strong><p>親項目以外の未完了条件も確認します。</p><a href="#coverage">確認範囲を見る →</a></li>'
    else:
        body+='<li><strong>今回の範囲と判定条件の確認</strong><p>確認済みの範囲と、別途必要な確認を記録します。</p><a href="#coverage">確認範囲を見る →</a></li>'
    return body+'</ul></section>'

def priority_html(report: dict) -> str:
    failed=failed_checks(report)
    headings={'WEB-04':'ブラウザーで実行するスクリプトの制限',
        'OBS-07':'誰が何を操作したかを追える記録',
        'OBS-09':'大量のデータ取得を検知する仕組み',
        'TST-02':'権限のない操作を拒否するテスト'}
    body='<section id="priority"><h2>確認できた不備 · '+str(len(failed))+'項目</h2><p class="section-intro">証拠に基づいてFAILとなった項目・個別条件です。各項目の根拠と対応方針を確認してください。</p>'
    if not failed:
        return body+'<p class="panel">証拠付きのFAILはまだありません。未確認・対象外が残る場合は、安全性を判断できません。</p></section>'
    body+='<div class="finding-grid">'
    for row in failed:
        body+='<article class="finding"><div class="finding-meta">'+method_pill(row)+status_pill('FAIL')+'</div><h3>'+esc(headings.get(row['id'],row['title']))+'</h3>'+static_finding_help(row)+'<dl><dt>今回の判定根拠</dt><dd>'+esc(row.get('rationale','個別条件の判定を確認してください。'))+'</dd>'
        conditions=[condition for condition in row.get('criteria_results',[]) if condition['status']=='FAIL']
        if conditions:
            body+='<dt>不備のある個別条件</dt><dd>'+str(len(conditions))+'件（詳細で条件と照合IDを確認できます）</dd>'
        seen={row.get('rationale','')}
        for condition in conditions:
            rationale=condition.get('rationale','未記載')
            if rationale in seen: continue
            seen.add(rationale)
            body+='<dt>個別条件の根拠</dt><dd class="finding-condition"><code>'+esc(condition['id'])+'</code><br>'+esc(rationale)+'</dd>'
        body+='<dt>統制の標準的な対応方針</dt><dd>'+esc(row['remediation'])+'</dd></dl>'
        if row['status']!='FAIL': body+='<p class="pending-note">親項目の判定は '+esc(status_text(row['status']))+' です。不備の対応と残りの条件の確認が必要です。</p>'
        body+='<a href="#'+esc(row['id'])+'">根拠・合格条件の詳細を見る →</a></article>'
    return body+'</div><p class="legend">統制の既定優先度は、今回の指摘の重大度を表すものではありません。未確認の条件は不備の対応後も確認が必要です。</p></section>'

def candidate_html(report: dict) -> str:
    """Group the same check/path/line; keep all observation IDs in check details."""
    rank={'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
    groups={}
    for row in report['checks']:
        resolved={o['id'] for o in row.get('resolved_observations',[])}
        for o in row.get('observations',[]):
            if o['id'] in resolved: continue
            key=(row['id'],o['path_id'],o['line'])
            item=groups.setdefault(key,{'row':row,'path':o['path'],'line':o['line'],'messages':[],'rules':[]})
            if o['message'] not in item['messages']: item['messages'].append(o['message'])
            if o['rule'] not in item['rules']: item['rules'].append(o['rule'])
    body='<details class="disclosure"><summary><span class="disclosure-title">自動検出の確認候補 · '+str(len(groups))+'箇所</span></summary><div class="disclosure-body"><p>文字列の一致による確認候補です。脆弱性や修正の必要性は確定していません。同じ項目・ファイル・行の候補をまとめています。候補IDは項目の詳細に残しています。</p>'
    if not groups:
        return body+'<p>未解決の文字列一致候補はありません。判断待ち・未確認・検査範囲の不足は別途確認が必要です。</p></div></details>'
    body+='<div class="table-wrap"><table><thead><tr><th>判定</th><th>項目と位置</th><th>確認内容</th><th>確認後の修正方針</th></tr></thead><tbody>'
    for item in sorted(groups.values(),key=lambda x:(rank.get(x['row']['severity'],5),x['row']['id'],x['path'],x['line'])):
        row=item['row']
        body+='<tr><td>'+status_pill(row['status'])+'</td><td><a href="#'+esc(row['id'])+'">'+esc(row['title'])+'</a><br>'+method_pill(row)+'<br><code>'+esc(item['path'])+(':'+str(item['line']) if item['line'] else '')+'</code></td><td>'+esc(' / '.join(item['messages']))+'<br><small>'+esc(' / '.join(item['rules']))+'</small></td><td>'+esc(row['remediation'])+'</td></tr>'
    return body+'</tbody></table></div></div></details>'

def pending_html(report: dict) -> str:
    c=report['counts']
    pending=report.get('incomplete') or any(c.get(state,0) for state in ('REVIEW','NOT_RUN','BLOCKED','ERROR'))
    heading='確認待ちが残る理由' if pending else '確認待ちの内訳'
    intro='判断・証拠・資料の確認が必要です。未確認をPASSとして扱いません。' if pending else '親項目の未完了の状態を区別して表示します。対象外は別の集計です。'
    body='<section id="pending"><h2>'+heading+'</h2><p class="section-intro">'+intro+'</p><div class="pending-grid">'
    for state,explanation in (
        ('REVIEW','設定の是非や適用条件について、判断・追加レビューが必要です。'),
        ('NOT_RUN','確認が未実施、または必要な証拠がそろっていません。'),
        ('BLOCKED','資料不足などにより確認を進められません。'),
        ('ERROR','解析・証拠検証のエラーを解消する必要があります。')):
        if state=='ERROR' and not c.get(state,0): continue
        body+='<div class="pending-item"><strong>'+esc(STATUS_LABELS[state])+'</strong><b>'+str(c.get(state,0))+'</b> 項目<p>'+explanation+'</p><small>'+state+'</small></div>'
    body+='</div><p class="pending-note">親項目の判定を集計しています。個別条件・検査領域・未解析範囲の不足も、確認完了の条件に含まれます。</p>'
    reviews=[r for r in report['checks'] if r['status']=='REVIEW']
    if reviews:
        body+='<details class="disclosure"><summary><span class="disclosure-title">判断待ち '+str(len(reviews))+'項目の理由を見る</span></summary><div class="disclosure-body"><ul class="review-list">'
        for row in reviews:
            body+='<li>'+method_pill(row)+' <a href="#'+esc(row['id'])+'">'+esc(row['title'])+'</a><p>'+esc(row.get('rationale','詳細の検証方法を確認してください。'))+'</p></li>'
        body+='</ul></div></details>'
    return body+candidate_html(report)+'</section>'

def ipa_html(report: dict) -> str:
    ipa=report.get('ipa')
    if not ipa: return ''
    titles={row['id']:row['title'] for row in report['checks']}
    body='<section id="ipa"><div class="section-title"><h2>IPA注意喚起への対応状況</h2><span class="pill">2026-10-09</span></div>'
    body+='<p>対策を既存の'+str(ipa['mapped_check_count'])+'項目へ対応付けています。下の'+str(ipa['group_count'])+'テーマは表示用のまとまりであり、検査件数には加算しません。IPAによる認証・公式チェックリストではありません。</p>'
    body+='<div class="callout"><strong>実環境を含む確認完了：'+str(ipa['verified_groups'])+' / '+str(ipa['group_count'])+' テーマ</strong><br>コードのPASSと、実アカウント・実ログ・実稼働設定の確認済みは別です。静的モードでは右側を自動的に合格・非該当へ変更しません。</div>'
    for g in ipa['groups']:
        body+='<details class="ipa-theme"><summary><span class="title">'+esc(g['title'])+'</span><span class="pill '+esc(g['static_status'])+'">静的 '+esc(g['static_status'])+'</span><span class="pill '+esc(g['external_status'])+'">実環境 '+esc(g['external_status'])+'</span></summary><div class="ipa-body grid2"><div><h3>静的解析で確認</h3><p>'+esc(g['static_action'])+'</p></div><div><h3>別途確認が必要</h3><p>'+esc(g['external_action'])+'</p><small>'+esc(g['external_note'])+'</small></div></div><div class="ipa-links">'
        body+=' '.join('<a class="check-link" href="#'+esc(cid)+'">'+esc(titles.get(cid,cid))+'</a>' for cid in g['check_ids'])
        if g['derived_control']: body+='<p class="muted">IPAがこの具体的な実装テストを列挙しているわけではありません。注意喚起の論点を本スキルで実装向けに具体化したものです。</p>'
        body+='</div></details>'
    return body+'<p><a href="'+html.escape(ipa['url'],quote=True)+'" rel="noopener noreferrer">IPA原文を確認</a> · 本文確認日 '+esc(ipa['verified_on'])+'。将来の監査では追記・更新を再確認してください。</p></section>'

def artex_html(report: dict) -> str:
    info=report.get('artex')
    if not info: return ''
    titles={row['id']:row['title'] for row in report['checks']}
    static=report['profile']=='static'
    label='静的対策' if static else '証拠付き統制'
    body='<section id="artex"><div class="section-title"><h2>ARTEX / フロンティアAI悪用への対策</h2><span class="pill">v8</span></div>'
    body+='<p>既存'+str(info['mapped_check_count'])+'項目を'+str(info['group_count'])+'テーマで表示します。テーマは検査件数に加算しません。AI非搭載のプロダクトも対象です。AI機能固有の最終テーマだけは、証拠付き非該当を利用できます。</p>'
    body+='<div class="callout"><strong>攻撃実行：NOT_PERFORMED / ARTEX帰属：NOT_ASSESSED</strong><p>ARTEXをインストール・起動せず、侵入・payload送信・自律攻撃・負荷試験を実施していません。PASSは定義した対策の証拠判定で、ARTEX耐性や未知の攻撃を防げる保証ではありません。</p></div>'
    body+='<p><strong>'+label+'の条件充足 '+str(info['verified_control_groups'])+' / '+str(info['group_count'])+' テーマ</strong></p>'
    for g in info['groups']:
        body+='<details class="ipa-theme artex-theme" id="'+esc(g['id'])+'"><summary><span class="title">'+esc(g['title'])+'</span><span class="pill '+esc(g['control_status'])+'">'+label+' '+esc(g['control_status'])+'</span><span class="pill '+esc(g['external_status'])+'">実環境 '+esc(g['external_status'])+'</span></summary><div class="ipa-body grid2"><div><h3>今回の確認内容</h3><p>'+esc(g['static_action'])+'</p></div><div><h3>限界・別途確認</h3><p>'+esc(g['external_action'])+'</p></div></div><div class="ipa-links">'
        body+=' '.join('<a class="check-link" href="#'+esc(cid)+'">'+esc(titles.get(cid,cid))+'</a>' for cid in g['check_ids'])
        body+='<p class="muted">'+esc(g['derivation'])+'</p></div></details>'
    return body+'</section>'

def render(report: dict) -> str:
    c=report['counts']; inv=report['scope']; verdict=report['verdict']; profile=report.get('profile','full')
    is_static=profile=='static'
    legacy=inv.get('catalog_sha256')!=sha((HOME/'references/checks.json').read_bytes()) or inv.get('engine_sha256')!=sha(Path(__file__).read_bytes())
    css='clean' if report['all_clean'] else 'bad' if verdict in {'FINDINGS','ERROR'} else ''
    messages={'FINDINGS':'不備が見つかりました。'+('確認はまだ途中です。' if report.get('incomplete') else '対応方針を確認してください。'),
        'INCOMPLETE':'確認が完了していません。', 'ERROR':'確認中にエラーが発生しました。',
        'EXCEPTIONS':'受容されたリスクが残っています。',
        'REVIEW PASSED':'静的な確認の条件を満たしています。' if is_static else '監査範囲の確認条件を満たしています。'}
    labels={'FINDINGS':'要対応','INCOMPLETE':'確認途中','ERROR':'エラー','EXCEPTIONS':'リスク受容あり','REVIEW PASSED':'範囲内の確認完了'}
    target=inv['target_id'].split('@sha256:',1)[0]
    try:
        reviewed=datetime.fromisoformat(report['generated_at']).astimezone(timezone(timedelta(hours=9))).strftime('%Y/%m/%d %H:%M JST')
    except (ValueError,TypeError): reviewed=report['generated_at']
    body='<header class="report-header"><div class="header-inner"><div class="eyebrow">REPOSITORY SECURITY AUDIT <span>v'+VERSION+'</span></div><div class="header-heading"><h1>セキュリティ確認レポート</h1><div class="verdict-line"><span id="verdict" class="status '+css+'">'+esc(labels.get(verdict,verdict))+' / '+esc(verdict)+'</span><span class="scope-label">'+('静的解析のみ / STATIC ONLY' if is_static else 'FULL EVIDENCE AUDIT')+'</span></div></div><p class="lead"><strong>'+esc(target)+'</strong><span>判定日時：'+esc(reviewed)+'</span></p><p class="result-message">'+esc(messages.get(verdict,verdict))+'</p></div></header><main>'
    if report.get('example'): body+='<p class="example-note">架空の検証用リポジトリによる動作例です。実プロダクトの監査結果ではありません。</p>'
    if legacy:
        body+='<details class="provenance-note"><summary>旧基準の保存結果を表示中（'+esc(report.get('engine_version','未記録'))+'）・追加条件の再監査は未実施</summary><p>保存済みの旧基準による判定です。説明・確認方法の分類を更新して表示しています。現行基準の追加条件での再監査は行っていません。元の判定・証拠・日時はそのままです。</p></details>'
    metrics=[(c['FAIL'],'不備あり','FAIL','fail','FAIL'),(sum(c.get(k,0) for k in PENDING_STATES),'確認待ち','判断・証拠・資料の不足','pending','pending'),(c['PASS'],'確認済み','PASS · 今回の範囲のみ','pass','PASS'),(c.get('OUT_OF_SCOPE',0),'今回対象外','OUT_OF_SCOPE','external','OUT_OF_SCOPE')]
    body+='<div class="cards" aria-label="親項目の判定件数">'+''.join('<a href="#checks" data-status-shortcut="'+state+'" class="metric metric-'+kind+'"><span>'+label+'</span><b>'+str(n)+'<span class="metric-unit">項目</span></b><small>'+code+' <span aria-hidden="true">→</span></small></a>' for n,label,code,kind,state in metrics)+'</div>'
    body+='<div class="scope-context"><p>判定対象 <strong>'+str(report['scope_check_count'])+'</strong>項目 / 全'+str(report['total_check_count'])+'項目</p>'
    if is_static: body+='<p>実環境中心の48項目は対象外・監査全体は <strong>未評価 / NOT_ASSESSED</strong></p>'
    body+='</div><p class="legend secondary-states">親項目の判定を集計。承認済み非該当 <a href="#checks" data-status-shortcut="NOT_APPLICABLE">'+str(c['NOT_APPLICABLE'])+'項目</a> · リスク受容 <a href="#checks" data-status-shortcut="WAIVED">'+str(c['WAIVED'])+'項目</a>。PASSや無検出は安全性の保証ではありません。</p>'
    child_only=[r for r in failed_checks(report) if r['status']!='FAIL']
    if child_only: body+='<p class="callout danger">親項目のFAIL集計とは別に、個別条件で不備が確認された項目が '+str(len(child_only))+'件あります。サマリーと不備の絞り込みに含めています。</p>'
    body+='<nav class="view-nav" aria-label="レポートの表示"><a href="#summary" data-view-link="summary" aria-current="page">サマリー</a><a href="#checks" data-view-link="checks">全項目一覧 <span>'+str(report['total_check_count'])+'</span></a><a href="#coverage" data-view-link="reference">確認範囲・資料</a></nav>'
    body+='<section id="summary" class="report-view" data-report-view="summary"><div class="section-heading"><h2>今回のサマリー</h2></div><p class="summary-lead">'+str(len(failed_checks(report)))+'項目の不備を確認。'+str(sum(c.get(k,0) for k in PENDING_STATES))+'項目は判断・証拠・資料の確認待ちです。</p><div class="dashboard-grid">'+summary_findings_html(report)+verification_html(report)+'</div>'+next_steps_html(report)+category_summary_html(report)+'</section>'
    body+='<section id="checks" class="report-view" data-report-view="checks"><div class="section-heading"><h2>全項目一覧</h2><span class="section-meta">'+str(report['total_check_count'])+'項目</span></div><p class="section-intro">判定・確認方法・要点を一覧で確認できます。項目名を選ぶと根拠と合格条件が開きます。</p>'+toolbar(report['checks'])+overview_html(report)+'<div id="check-details"><h2>項目の詳細</h2>'+cards_html(report['checks'])+'</div><dialog id="check-dialog" aria-labelledby="detail-heading"><div class="dialog-toolbar"><h2 id="detail-heading">項目の詳細</h2><button type="button" id="detail-close" autofocus>閉じる ×</button></div><div id="detail-content"></div></dialog></section>'
    domain_labels={'source_tree':'ソースコードの取得範囲','static_configs':'設定・Terraformなどの取得範囲','history':'Git履歴','dependencies':'依存ライブラリ・SBOM','release_artifacts':'実際の配布物','threat_intel':'最新の脆弱性情報との照合'}
    body+='<section id="coverage" class="report-view" data-report-view="reference"><div class="panel coverage-panel"><h2>確認した範囲と、足りない資料</h2><p class="section-intro">領域ごとの状態です。開くと、確認済みの範囲・未取得の資料・判断根拠が分かります。範囲の把握がPASSでも、含まれる実装の安全性を示すものではありません。</p><div class="coverage-grid">'
    for key,d in report['coverage'].items():
        body+='<details class="coverage-item"><summary><span class="title">'+esc(domain_labels.get(key,d['title']))+'</span>'+status_pill(d['status'])+'</summary><p><strong>'+esc(d['title'])+'</strong><br>'+esc(d.get('rationale','未確認'))+'</p></details>'
    body+='</div>'
    if inv['errors']: body+='<h2>実行エラー</h2>'+''.join('<p class="callout danger">'+esc(e)+'</p>' for e in inv['errors'])
    if inv['gaps']:
        body+='<h2>未解析・補完台帳</h2><div class="table-wrap"><table><thead><tr><th>対象</th><th>理由</th><th>gap ID / 補完状態</th></tr></thead><tbody>'
        for g in inv['gaps']:
            resolved=report['gap_resolutions'].get(g['id'],{})
            body+='<tr><td><code>'+esc(g['path'])+'</code></td><td>'+esc(g['kind']+' '+g['detail'])+'</td><td><code>'+esc(g['id'])+'</code><br>'+esc(resolved.get('status','NOT_RUN'))+'</td></tr>'
        body+='</tbody></table></div>'
    body+='</div><details class="disclosure"><summary><span class="disclosure-title">確認待ちの内訳・自動検出の候補</span></summary><div class="disclosure-body">'+pending_html(report)+'</div></details>'
    body+='<h2 class="appendix-title">対応表・監査情報</h2>'
    body+='<details class="disclosure"><summary><span class="disclosure-title">課金監視と利用者への通知で確認すること</span></summary><div class="disclosure-body"><p>一般化した防御条件として、アプリからAPIまでの境界・認可・秘密情報・保存データ・ログを確認します。</p><ul><li>静的解析：クラウドの課金対象APIについて、利用量・費用の監視定義、通知先と停止・失効の手順を確認します。AI未搭載でも、クラウドIDからの不正利用を評価します。</li><li>ログ・運用記録：初回公表、対象者通知、詐欺等への注意喚起のひな型と判断権限・更新手順を確認します。必要な期限は適用条件に沿って確認します。</li></ul><p>条件は本スキルで具体化した防御策です。実ログ調査・アプリ実行・課金・通知は実施していません。</p></div></details>'
    for label,content in (('ARTEX / AI悪用対策の対応表',artex_html(report)),('IPA注意喚起の対応表',ipa_html(report)),('一次情報・公式資料と確認日',source_html())):
        if content: body+='<details class="disclosure"><summary><span class="disclosure-title">'+label+'</span></summary><div class="disclosure-body">'+content+'</div></details>'
    body+='<details id="audit-info" class="disclosure"><summary><span class="disclosure-title">監査情報・判定の条件</span></summary><div class="disclosure-body"><dl><dt>対象の完全な識別子</dt><dd><code>'+esc(inv['target_id'])+'</code></dd><dt>判定日時（原記録）</dt><dd>'+esc(report['generated_at'])+'</dd><dt>検査profile</dt><dd>'+esc(report.get('profile_label',profile))+'</dd><dt>scope ID</dt><dd><code>'+esc(inv['scope_id'])+'</code></dd><dt>判定時のエンジンSHA256</dt><dd><code>'+esc(inv.get('engine_sha256','未記録'))+'</code></dd><dt>テキスト解析</dt><dd>'+str(inv['text_files_scanned'])+' files / 列挙 '+str(inv['files_seen'])+' files</dd><dt>取得snapshot内の未補完gap</dt><dd>'+str(len(report['unresolved_gaps']))+'件（未取得の履歴・依存等は検査領域を参照）</dd><dt>文字列一致候補（集約前）</dt><dd>'+str(len(inv['observations']))+'件</dd><dt>判定未完了</dt><dd>'+('あり' if report.get('incomplete') else 'なし')+'</dd><dt>CLI終了コード</dt><dd>'+str(report['exit_code'])+'（0=当該profileの条件充足、1=指摘/受容リスク、2=未完了/エラー）</dd><dt>監査全体</dt><dd>'+esc(report.get('full_audit',{}).get('verdict','NOT_ASSESSED'))+'</dd></dl><p class="muted">scope IDは取得済み入力・台帳・エンジン・IPA/ARTEX対応表・実行上限へ結び付きます。操作者が指定したcommitの真正性、未取得履歴、証拠内容の真偽は自動証明しません。証拠はprofile間でも流用できません。</p>'
    if is_static: body+='<p>「REVIEW PASSED / STATIC ONLY」は、静的スコープの適用条件と証拠がそろった意味に限ります。アプリの起動、DAST、ペネトレーション、実アカウント棚卸し、実ログ調査、復旧試験は実行していません。</p>'
    body+='<div class="callout"><strong>REVIEW PASSEDになる条件</strong><br>当該profileの全適用項目と個別条件が証拠付きPASS、非該当は証拠と承認あり、全必須領域の確認済み、未補完gap・未実行・未解決候補・受容リスク・エラーがない場合のみREVIEW PASSEDです。未知脆弱性や侵害不存在の保証ではありません。</div></div></details></section><footer>REPOSITORY SECURITY AUDIT · v'+VERSION+' · 外部ライブラリ・CDN・外部フォント・外部自動通信なし。HTML/JSONも機密資料として保管してください。</footer></main>'
    return document('Repository Security Audit — '+profile+' — '+verdict,body)

def write_json(path, data):
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    try: path.chmod(0o600)
    except OSError: pass

def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('static','full'), default='static', help='default: static; full requires additional external evidence and never performs penetration tests')
    parser.add_argument('--repo',type=Path,required=True,help='read-only snapshot root')
    parser.add_argument('--target-id',required=True,help='operator-verified repository + commit/snapshot identity')
    parser.add_argument('--out',type=Path,required=True,help='new directory outside target; existing directories rejected')
    parser.add_argument('--evidence',type=Path,help='trusted review JSON outside target')
    args=parser.parse_args(argv)
    repo=args.repo.resolve(); out=args.out.resolve()
    # No subprocesses, imports from target, build/install, hooks, or network.
    if not repo.is_dir() or args.repo.is_symlink():
        print('ERROR: --repo は実ディレクトリを指定してください。',file=sys.stderr); return 2
    if out.is_relative_to(repo) or out.exists() or out==HOME or HOME.is_relative_to(repo):
        print('ERROR: スキルと新規出力先を監査対象外に置いてください。既存出力への上書きはしません。',file=sys.stderr); return 2
    if not args.target_id.strip() or len(args.target_id)>512:
        print('ERROR: --target-id が不正です。',file=sys.stderr); return 2
    try:
        out.mkdir(parents=True,exist_ok=False,mode=0o700)
        catalog=checks(); inv=inventory(repo,args.target_id)
        try: report=assemble(inv,catalog,args.evidence,repo,profile=args.profile)
        except (AuditError,OSError,TypeError,KeyError) as err:
            inv['errors'].append('証拠検証エラー: '+(str(err) if isinstance(err,AuditError) else type(err).__name__))
            report=assemble(inv,catalog,None,repo,profile=args.profile)
        write_json(out/'results.json',report)
        write_json(out/'evidence.template.json',template(inv,catalog,profile=args.profile))
        page=out/'report.html'; page.write_text(render(report),encoding='utf-8'); page.chmod(0o600)
        print(report['verdict']+' | '+str(out/'report.html'))
        return report['exit_code']
    except (OSError,AuditError,ValueError,TypeError,KeyError) as err:
        # Never show raw exception content from potentially sensitive paths/data.
        msg='実行失敗: '+type(err).__name__+'。出力を成功扱いせず、入力・権限・信頼済み台帳を確認してください。'
        print('ERROR: '+msg,file=sys.stderr)
        if out.is_dir():
            try:
                (out/'report.html').write_text(document('監査エラー','<header><h1>ERROR</h1></header><main><p>'+esc(msg)+'</p><p>全220項目の検証は完了していません。</p></main>'),encoding='utf-8')
                (out/'report.html').chmod(0o600)
                write_json(out/'results.json',{'verdict':'ERROR','all_clean':False,'scope_passed':False,'exit_code':2,'error':msg})
            except OSError: pass
        return 2

if __name__=='__main__':
    raise SystemExit(main())
