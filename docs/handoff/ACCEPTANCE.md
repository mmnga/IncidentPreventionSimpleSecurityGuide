# 受け入れテスト — skill開発リポジトリ

## 0. 原則

テスト対象は**監査ツール自身と合成fixture**。本番の製品、実ユーザー/アカウント、外部サイトにテストトラフィックを送らない。提示されていない製品repoを監査したと主張しない。

## 1. 開発環境

- Python 3.10+、標準ライブラリでエンジンが実行できること。
- テストに追加依存が必要ならdev-onlyで明示し、監査対象には一切入れないこと。
- skillの正本は `skills/repository-security-audit/`。開発用テストはrepo直下の `tests/`。
- 将来Codex/Claude/Cursor向け配布物を生成する場合、正本と同じ実装・台帳を使うこと。配布物の再現手順を確認。

## 2. テストコマンド（repo直下から）

```bash
python3 -B -m unittest discover -s tests -p 'test_*.py' -q
python3 -B skills/repository-security-audit/scripts/audit.py --help
python3 -B skills/repository-security-audit/scripts/review_workflow.py --help
```

現在のテストは **275件**（従来266件＋合成アプリの対応表・形式・証拠誤用防止9件）。今後増やす場合は数値を更新する。ホスト別コピーは現在含まれていないため、存在しないコピーのテスト成功を報告しない。

## 3. 合成snapshotでのスモークテスト

```bash
AUDIT_TEST_DIR="$(mktemp -d)"
mkdir -p "$AUDIT_TEST_DIR/synthetic-snapshot"
printf '%s\n' '# synthetic fixture' > "$AUDIT_TEST_DIR/synthetic-snapshot/README.md"
python3 -B skills/repository-security-audit/scripts/audit.py \
  --profile static \
  --repo "$AUDIT_TEST_DIR/synthetic-snapshot" \
  --target-id 'synthetic@fixed-fixture' \
  --out "$AUDIT_TEST_DIR/report-001"
AUDIT_TEST_RC=$?
# evidenceなしなので AUDIT_TEST_RC=2（INCOMPLETE）が期待値。CIでは想定扱いにする。
test "$AUDIT_TEST_RC" -eq 2
python3 -B - "$AUDIT_TEST_DIR/report-001/results.json" <<'PYJSON'
import json,sys
r=json.load(open(sys.argv[1],encoding='utf-8'))
assert r['profile']=='static'
assert r['verdict']=='INCOMPLETE'
assert r['scope_check_count']==172
assert r['total_check_count']==220
assert r['counts']['OUT_OF_SCOPE']==48
assert r['full_audit']['all_clean'] is False
assert r['scope_passed'] is False
print('Static smoke assertions OK')
PYJSON
```

**注意**: 実行コマンドの終了コード2はツールの「実行不能」ではなく、証拠未完了でも返される。シェルが`set -e`なら一時的に解除して検査する。

## 4. 判定ゲート

- `NOT_RUN / REVIEW / BLOCKED / ERROR / WAIVED` が残ると `REVIEW PASSED` にしない。
- staticでは48項目を `OUT_OF_SCOPE` とし、原チェックを表示から削除しない。
- `full_audit.verdict=NOT_ASSESSED`, `full_audit.all_clean=false`。
- 親PASSでも静的個別条件 `/S2`・`/S3` の不足を許容しない。
- `schema_version=3`, `scope_id`, snapshot, hash, reviewer, 時刻、coverages、unresolved observation、gapを検査する。
- 合格表示は`REVIEW PASSED / STATIC ONLY`。JSONの旧`all_clean`は互換性を維持。

## 5. HTMLの品質

- `report.html`はオフラインで単独表示できる。CDN、フォント配信、外部スクリプト、追跡通信なし。
- 検出内容、ファイル名、根拠、修正案、HTML特殊文字を安全にescapeする。
- 220チェックの検索・カテゴリ絞り込み、IPA12テーマ、ARTEX8テーマ、確認候補と対象外の区別ができる。
- PC/モバイル幅で横はみ出しがなく、スクリーンリーダーに判定が伝わる。
- 主な確認方法で分類し、テスト定義のレビューと実行結果、IaCと実設定、監視定義と実ログ調査を混同しない。照合IDと全220項目は保持する。
- サマリー・全項目一覧・確認範囲/資料を切り替えられ、一覧と詳細が同じ220項目・同じ判定を示す。詳細を閉じても絞り込みを維持する。
- 集計では非該当・受容・対象外をPASSに含めず、個別条件のFAILを親の未完了で隠さない。JavaScriptなしでも一覧・全詳細を読める。
- 旧基準の保存結果を表示し直してもscope・証拠・判定を変更せず、追加条件での再監査未実施を表示する。
- 企業・組織別の被害事例や事例記事の題名・URLを含めない。非公開・公開指定なしの参考資料はHTMLに出さず、公開資料へのリンクが成立すること。
- 事例原資料はGit管理対象外の `private-case-studies/` に分離し、CLIが読み込まず、Web配信・skill配布に含めないこと。
- 静的PASSと実際の攻撃耐性を同一視しない。

## 6. セキュリティ否定テスト

以下の防御試験があること: repoルートへのスキル配置拒否、repo配下への出力拒否、既存出力への上書き拒否、symlink追跡しない、ファイル上限/gap、証拠のpath traversal・hash不一致・古い期限・旧scopeの拒否、レポートの秘密値秘匿、入力がユーザー指定の指示文でも実行しない。

## 7. リリース報告

差分と影響ID／通過テスト件数／未実行テスト／coverageの限界／実プロダクト未診断の断りを記録する。ZIPを生成するリリースではZIPのSHA256も記録する。`all clean`という表示文字列を復活させない。

## 8. 並列・項目別レビュー

- `plan` はstatic 172 IDと184個別条件を2以上の担当へ重複なく全件配分し、48 IDの固定対象外を保持する。fullは明示指定時だけ220 IDを配分する。
- `merge` は全担当ID・非該当以外の全個別条件・項目ごとの理由を照合する。未提出・重複・担当外・未知status・未返却workerを拒否する。根拠/承認なしの非該当や、別scope・古い証拠・hash不一致も従来ゲートで拒否する。
- 未起動workerはagent IDを空欄にし、担当の全項目と条件を理由付き未確認で返す。全worker未起動の合成例で、pendingが172 ID、固定対象外が48 ID、PASSが0、最終結果がINCOMPLETE/exit 2となること。
- 親が実ホスト上の実行・返却を確認する。単体テストの合成agent IDを実在のagentと扱わず、JSONの自己申告で実行・本人性・並列性を証明しない。2workerの限定4 IDテストは全172 IDの検証とは区別する。
- CLIはagent・対象コード・ネットワークを起動しない。既存220 ID、証拠契約、scope/freshness、最終判定のexit codeを変えない。

## 9. 自動返信・通知メール

- 既存220 ID、static 172/対象外48と従来の全個別条件を保持し、WEB-01/S2・WEB-09/S5とfull各MAIL-1を追加する。現行は静的184条件、full 127条件。
- 新条件の欠落・FAIL・BLOCKED・REVIEW等を親PASSで隠せない。新条件の非該当には根拠と承認を必要とし、既存条件を一括スキップしない。並列計画にも両条件を各1回含める。
- 9.1の台帳とエンジンのhashを正確に復元した合成scopeで、旧証拠が拒否されること。scopeだけを現行へ書き換えても、新条件の証拠欠落でINCOMPLETEとなること。
- 一次資料は明示的なpublicのRFCだけをHTMLへ掲載し、企業・組織別の事例を追加しない。メール用語の無検出、HTMLエスケープ、DKIM成功だけで内容の安全性を判定しない。
- 実送信・DNS照会・リプレイ・実クライアント表示は試さない。合成コードはデータとして読み、外部テンプレート・実署名設定等の未確認範囲を記録する。

## 10. 合成アプリと全項目の索引

- `examples/apps/` はWeb、API、Flutter（iOS/Android統合ソース）、IaC、通知、外部連携、AI、CI、運用モデルを含む架空データである。既存の保存レポートと区別する。
- `examples/coverage.json` の台帳SHA256、全220 ID、static対象172/対象外48、静的184/full 127個別条件が正本と一致し、欠落・重複がない。ソース参照とJSON pointerは実在ファイル・正しいIDに解決する。
- 22分野に220件の異なる個別不備ケースがある。ケースは静的レビュー用データで、攻撃や対象コードの実行を要求しない。
- 48実環境記録と127full条件モデルはNOT_RUN・実証拠なしを保つ。索引とモデルをschema 3の監査証拠として受け付けず、モデルの記載で自動PASSしない。
- 合成ソースはimportせず、Python AST、JSON、XML/plistをデータとして解析する。アプリ・SDK・コンテナ・依存・Terraformの起動やビルドの成否は別の未確認範囲として明記する。
- CLI smokeは `apps/` の別の不変・読み取り専用コピーで行い、HTML/JSON・INCOMPLETE/exit 2・STATIC ONLY・48対象外・PASS 0を確認する。ネットワーク・subprocess・対象コード実行・private事例読込を行わず、元ソース・snapshot・旧レポートが変わらないことを確認する。
