#!/usr/bin/env python3
"""Prepare disjoint review assignments and reconcile per-control evidence.

No agents, subprocesses, scanners, network calls, or target code are launched.
The host runs the subagents; audit.py remains the only audit verdict command.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

HOME = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('review_audit_engine', HOME/'scripts/audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
WorkflowError = audit.AuditError


def read_object(path: Path) -> dict:
    if 'private-case-studies' in path.resolve().parts:
        raise WorkflowError('非公開の事例フォルダは読み込みません。')
    if path.is_symlink():
        raise WorkflowError('入力JSONのsymlinkは禁止です。')
    value = audit.read_json(path)
    if not isinstance(value, dict):
        raise WorkflowError('入力JSONはobjectで指定してください。')
    return value


def write_new(path: Path, value: dict):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    path.chmod(0o600)


def bindings() -> dict:
    return {name: audit.sha((HOME/name).read_bytes()) for name in (
        'scripts/audit.py', 'scripts/review_workflow.py', 'references/checks.json',
        'references/ipa-mapping.json', 'references/artex-mapping.json')}


def definitions(profile: str) -> list[dict]:
    if profile not in {'static', 'full'}:
        raise WorkflowError('profileが不正です。')
    catalog = audit.checks()
    return audit.static_catalog(catalog) if profile=='static' else catalog


def assignments(catalog: list[dict], workers: int) -> list[dict]:
    groups = {}
    for control in catalog:
        groups.setdefault(control['category_id'], []).append(control)
    if isinstance(workers, bool) or not isinstance(workers, int) or not 2 <= workers <= len(groups):
        raise WorkflowError('worker数は2以上、対象分野数以下にしてください。')
    shards = [{'worker_id':f'worker-{i+1:02d}', 'check_ids':[], 'weight':0} for i in range(workers)]
    for group in groups.values():
        shard = min(shards, key=lambda s:s['weight'])
        shard['check_ids'].extend(c['id'] for c in group)
        shard['weight'] += sum(max(1, len(c.get('criteria', []))) for c in group)
    return [{'worker_id':s['worker_id'], 'check_ids':s['check_ids']} for s in shards]


def require_external(path: Path, repo: Path):
    if path.resolve().is_relative_to(repo):
        raise WorkflowError('計画・証拠・出力は対象snapshotの外に置いてください。')


def prepare(results: Path, repo: Path, out: Path, workers: int = 3, profile: str = 'static') -> dict:
    if repo.is_symlink():
        raise WorkflowError('snapshot rootのsymlinkは禁止です。')
    repo = repo.resolve()
    if not repo.is_dir() or HOME.is_relative_to(repo) or 'private-case-studies' in repo.parts:
        raise WorkflowError('スキルと分離したsnapshotを指定してください。')
    require_external(results, repo)
    require_external(out, repo)
    if out.exists() or out.is_symlink() or out.resolve().is_relative_to(HOME):
        raise WorkflowError('スキル外の新規reviewディレクトリを指定してください。')
    report = read_object(results)
    current = bindings()
    inv = report.get('scope', {})
    if not isinstance(inv, dict):
        raise WorkflowError('初期結果のscopeの形式が不正です。')
    if report.get('profile')!=profile or report.get('schema_version')!=audit.EVIDENCE_SCHEMA:
        raise WorkflowError('初期結果のschema/profileが一致しません。fullは明示指定が必要です。')
    if (inv.get('catalog_sha256')!=current['references/checks.json'] or
            inv.get('engine_sha256')!=current['scripts/audit.py'] or
            inv.get('artex_mapping_sha256')!=current['references/artex-mapping.json']):
        raise WorkflowError('初期結果の台帳・エンジン・対応表が現行と一致しません。')
    rows = report.get('checks')
    if (not isinstance(rows, list) or any(not isinstance(c, dict) for c in rows) or
            [c.get('id') for c in rows] != [c['id'] for c in audit.checks()]):
        raise WorkflowError('初期結果の220 IDが正本と一致しません。')
    observations = inv.get('observations')
    if not isinstance(observations, list) or any(not isinstance(o, dict) for o in observations):
        raise WorkflowError('初期結果の確認候補の形式が不正です。')
    audit.required_text(inv, 'scope_id')
    catalog = definitions(profile)
    active_ids = {c['id'] for c in catalog}
    plan = {'schema_version':1, 'profile':profile, 'scope_id':inv['scope_id'],
            'repo':str(repo), 'bindings':current, 'inventory':inv,
            'assignments':assignments(catalog, workers),
            'out_of_scope':[{'id':c['id'], 'status':'OUT_OF_SCOPE',
                             'reason':'static profileの固定対象外。合格・非該当ではない。'}
                            for c in audit.checks() if c['id'] not in active_ids]}
    plan['plan_id'] = audit.sha(audit.canonical(plan))
    template = audit.template(inv, audit.checks(), profile=profile)
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    write_new(out/'plan.json', plan)
    by_id = {c['id']:c for c in catalog}
    for shard in plan['assignments']:
        wid = shard['worker_id']
        selected = set(shard['check_ids'])
        task = {'plan_id':plan['plan_id'], 'worker_id':wid, 'profile':profile,
                'scope_id':inv['scope_id'], 'snapshot':str(repo),
                'evidence_file':wid+'.json', 'artifact_prefix':'artifacts/'+wid+'/',
                'checks':[{k:v for k,v in by_id[cid].items() if k in {
                    'id','category','title','applicability','verification','pass_criteria',
                    'remediation','criteria','required_evidence','scope_boundary','assessment_scope'}}
                          for cid in shard['check_ids']],
                'observations':[o for o in inv['observations'] if o['check_id'] in selected]}
        fragment = {k:copy.deepcopy(template[k]) for k in ('schema_version','scope_id','profile','created_at')}
        fragment['coordination'] = {'plan_id':plan['plan_id'], 'worker_id':wid,
                                    'agent_id':'', 'execution_status':'PENDING', 'reason':''}
        fragment['checks'] = [copy.deepcopy(c) for c in template['checks'] if c['id'] in selected]
        write_new(out/(wid+'.assignment.json'), task)
        write_new(out/(wid+'.json'), fragment)
    parent = copy.deepcopy(template)
    parent['checks'] = []
    write_new(out/'parent.json', parent)
    return plan


def exact_ids(rows, expected, label):
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise WorkflowError(label+'の形式が不正です。')
    ids = [r.get('id') for r in rows]
    if (any(not isinstance(cid, str) for cid in ids) or len(ids)!=len(expected) or
            set(ids)!=set(expected) or len(set(ids))!=len(ids)):
        raise WorkflowError(label+'に未提出・担当外・重複IDがあります。')


def checked_record(record: dict):
    if not isinstance(record, dict):
        raise WorkflowError('項目・個別条件の形式が不正です。')
    if not isinstance(record.get('status'), str) or record['status'] not in audit.STATES:
        raise WorkflowError('未知の状態、SKIP、OUT_OF_SCOPEは入力できません。')
    # Even pending work must explain this particular control/criterion.
    audit.required_text(record, 'rationale', 8)


def merge(plan_path: Path) -> dict:
    plan = read_object(plan_path)
    unsigned = {k:v for k,v in plan.items() if k!='plan_id'}
    if plan.get('schema_version')!=1 or plan.get('plan_id')!=audit.sha(audit.canonical(unsigned)):
        raise WorkflowError('計画の形式またはhashが不正です。')
    if plan.get('bindings')!=bindings():
        raise WorkflowError('計画作成後に正本が変わりました。scopeを書換えず再計画してください。')
    catalog = definitions(plan['profile'])
    if (not isinstance(plan.get('assignments'), list) or
            plan['assignments']!=assignments(catalog, len(plan['assignments']))):
        raise WorkflowError('担当割当が正本と一致しません。')
    if (not isinstance(plan.get('inventory'), dict) or
            plan.get('scope_id')!=plan['inventory'].get('scope_id')):
        raise WorkflowError('計画のscopeが一致しません。')
    root = plan_path.resolve().parent
    repo = Path(plan['repo']).resolve()
    require_external(root, repo)
    output, ledger_path = root/'evidence.merged.json', root/'review-ledger.json'
    if any(p.exists() or p.is_symlink() for p in (output, ledger_path)):
        raise WorkflowError('既存の統合結果には上書きしません。')
    parent = read_object(root/'parent.json')
    for key, expected in (('schema_version',audit.EVIDENCE_SCHEMA),('profile',plan['profile']),('scope_id',plan['scope_id'])):
        if parent.get(key)!=expected:
            raise WorkflowError('親の証拠schema/profile/scopeが一致しません。')
    if parent.get('checks')!=[]:
        raise WorkflowError('親のchecksは空にし、担当workerの結果と混在させないでください。')
    expected_template = audit.template(plan['inventory'], audit.checks(), profile=plan['profile'])
    if (not isinstance(parent.get('coverage'), dict) or
            set(parent['coverage'])!=set(expected_template['coverage'])):
        raise WorkflowError('親のcoverageに未提出・未知の領域があります。')
    exact_ids(parent.get('gap_resolutions'), [g['id'] for g in expected_template['gap_resolutions']], 'gap補完')
    for record in [*parent['coverage'].values(), *parent['gap_resolutions']]:
        checked_record(record)
    by_id = {c['id']:c for c in catalog}
    submitted, owners, agents = {}, {}, []
    for shard in plan['assignments']:
        wid = shard['worker_id']
        fragment = read_object(root/(wid+'.json'))
        if any(fragment.get(k)!=parent[k] for k in ('schema_version','profile','scope_id')):
            raise WorkflowError('workerのschema/profile/scopeが一致しません。')
        audit.timestamp(fragment.get('created_at'))
        meta = fragment.get('coordination', {})
        if (not isinstance(meta, dict) or meta.get('worker_id')!=wid or
                meta.get('plan_id')!=plan['plan_id']):
            raise WorkflowError('worker/計画の対応が一致しません。')
        state = meta.get('execution_status')
        if state not in {'FINISHED','FAILED','UNAVAILABLE'}:
            raise WorkflowError('未返却・実行中のworkerがあります。失敗時も各IDの状態を記録してください。')
        if state in {'FINISHED','FAILED'}:
            audit.required_text(meta, 'agent_id')
        else:
            if meta.get('agent_id'):
                raise WorkflowError('未起動workerにagent_idを記入しないでください。')
        if state!='FINISHED':
            audit.required_text(meta, 'reason', 8)
        if fragment.get('coverage') or fragment.get('gap_resolutions'):
            raise WorkflowError('coverageとgapは親の担当です。')
        rows = fragment.get('checks')
        exact_ids(rows, shard['check_ids'], 'workerのchecks')
        for row in rows:
            cid = row['id']
            checked_record(row)
            if state=='UNAVAILABLE' and row['status'] not in {'NOT_RUN','BLOCKED','ERROR'}:
                raise WorkflowError('未起動workerの項目を検証済みへ変更できません。')
            if row['status']!='NOT_APPLICABLE':
                exact_ids(row.get('criteria_results', []), [c['id'] for c in by_id[cid].get('criteria', [])], cid+'の個別条件')
            for criterion in row.get('criteria_results', []):
                checked_record(criterion)
                if state=='UNAVAILABLE' and criterion['status'] not in {'NOT_RUN','BLOCKED','ERROR'}:
                    raise WorkflowError('未起動workerの個別条件を検証済みへ変更できません。')
            submitted[cid], owners[cid] = row, wid
        agents.append({k:meta.get(k) for k in ('worker_id','agent_id','execution_status','reason')})
    merged = copy.deepcopy(parent)
    merged['checks'] = [submitted[c['id']] for c in catalog]
    # Use the original engine to validate receipts, approvals, timestamps,
    # observations, criteria, coverage, and gaps. Relative artifact paths keep
    # the same trusted root throughout; no evidence hashes are rewritten.
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=root,
                                     prefix='.review-check-', suffix='.json', delete=False) as stream:
        candidate = Path(stream.name)
        json.dump(merged, stream, ensure_ascii=False)
    try:
        result = audit.assemble(plan['inventory'], audit.checks(), candidate, repo, profile=plan['profile'])
    finally:
        candidate.unlink()
    active = {c['id'] for c in catalog}
    ledger = {'schema_version':1, 'plan_id':plan['plan_id'], 'scope_id':plan['scope_id'],
              'profile':plan['profile'], 'submitted_count':len(submitted),
              'execution_claims':agents, 'parallel_execution':'HOST_RUNTIME_VERIFICATION_REQUIRED',
              'items':[{'id':r['id'], 'worker_id':owners[r['id']], 'status':r['status'],
                        'criteria':[{'id':c['id'],'status':c['status']} for c in r.get('criteria_results', [])]}
                       for r in result['checks'] if r['id'] in active],
              'skipped':[{'id':r['id'], 'status':r['status'], 'reason':r.get('rationale',''),
                          'approved_by':r.get('approved_by')}
                         for r in result['checks'] if r['status'] in {'OUT_OF_SCOPE','NOT_APPLICABLE'}],
              'pending_ids':[r['id'] for r in result['checks'] if r['id'] in active and (
                             r['status'] in {'NOT_RUN','REVIEW','BLOCKED','ERROR'} or
                             any(c['status'] in {'NOT_RUN','REVIEW','BLOCKED','ERROR'} for c in r.get('criteria_results', [])))]}
    write_new(output, merged)
    write_new(ledger_path, ledger)
    return ledger


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    plan = sub.add_parser('plan')
    plan.add_argument('--results', type=Path, required=True)
    plan.add_argument('--repo', type=Path, required=True)
    plan.add_argument('--out', type=Path, required=True)
    plan.add_argument('--workers', type=int, default=3)
    plan.add_argument('--profile', choices=('static','full'), default='static')
    reconcile = sub.add_parser('merge')
    reconcile.add_argument('--plan', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command=='plan':
            value = prepare(args.results, args.repo, args.out, args.workers, args.profile)
            print('PLANNED '+str(sum(len(s['check_ids']) for s in value['assignments']))+' controls; agents are launched by the host, not this CLI.')
        else:
            value = merge(args.plan)
            print('MERGED '+str(value['submitted_count'])+' controls; pending '+str(len(value['pending_ids']))+'. Run audit.py for the audit verdict.')
        return 0
    except (WorkflowError, OSError, ValueError, TypeError, KeyError):
        print('ERROR: review計画・担当ID・個別条件・証拠を確認してください。未完了を合格扱いしません。', file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
