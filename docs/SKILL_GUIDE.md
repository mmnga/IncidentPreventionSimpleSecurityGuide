# Repository Security Audit v9 — skill利用ガイド

`skills/repository-security-audit/` を信頼済み領域に置き、[SKILL.md](../skills/repository-security-audit/SKILL.md)に従って使用します。Python 3.10以降、標準ライブラリのみです。
対象snapshot・証拠・出力先と監査実装を分離し、対象内のコード・hook・MCPを起動しません。

```bash
python /trusted/repository-security-audit/scripts/audit.py --profile static --repo /readonly/snapshot --target-id 'product@verified-snapshot' --out /private/audit/new-run
```

出力はreport.html、results.json、evidence.template.json。初回のINCOMPLETE/exit 2は通常です。
220 IDのうち静的対象172 ID（184個別条件）、48 IDはOUT_OF_SCOPE。75字句ルールが63 IDの候補を付けます。
全項目の完全自動判定ではありません。証拠がなければ合格せず、REVIEW PASSEDはSTATIC ONLYです。
ARTEXの実行、侵入テスト、防御成功の認証は実施しません。

[artex-response.md](../skills/repository-security-audit/references/artex-response.md)に観測と防御設計の区別、[artex-delta.json](../skills/repository-security-audit/references/artex-delta.json)に重複のない変更差分を記録しています。
[attack-path-template.json](../skills/repository-security-audit/references/attack-path-template.json)は手動経路レビューの補助台帳であり、経路の正当性をCLIが自動証明するものではありません。
[examples](../examples/README.md)は架空データです。独立スキルのインストールには不要です。
検証内容と限界は [validation](../validation/README.md)を参照してください。

メールを生成する場合は[自動返信・通知メールの確認手順](../skills/repository-security-audit/references/mail-notification-review.md)を使います。HTML/MIMEへの入力混入と、任意の文章やURLを公式通知として送れる問題を別々に確認します。未提供の外部テンプレート・配信設定は未確認で残し、メール非搭載を既存のWeb/API条件へ伝播させません。v9.2はscopeが変わるため、旧結果・証拠のscopeを書き換えて流用しないでください。

添付・メディア配信やサービス間認証がある場合は[ファイル配信・サービス間認証・封じ込めの確認](../skills/repository-security-audit/references/file-delivery-containment-review.md)を使います。ファイル取得から設定・鍵・利用者権限へ広がる経路、直接メール送信の権限、鍵交換の依存先、残存プログラムの調査と復旧を既存項目へ対応付けます。今回の補助手順は項目・条件・判定基準の変更を伴わず、実環境の失効・隔離・復旧結果は引き続き静的確認の対象外です。

## 並列レビュー

初期結果を得たら、親の実行枠を残し、ホストのサブエージェントを2以上並列で動かします。通常は3workerへ分野を分けます。各workerは全担当IDと全個別条件を一つずつ読み、実際に確認した経路・設定・証拠・限界を記録します。候補0件の項目も検証します。

```bash
python /trusted/repository-security-audit/scripts/review_workflow.py plan \
  --results /private/audit/new-run/results.json --repo /readonly/snapshot \
  --out /private/review/new-run --workers 3
```

生成されたassignmentと[worker依頼文](../skills/repository-security-audit/references/worker-task.md)をホスト上で各workerへ渡します。親はcoverage・gapを確認し、返却された全ID・全条件と実際の実行記録を照合します。

```bash
python /trusted/repository-security-audit/scripts/review_workflow.py merge \
  --plan /private/review/new-run/plan.json
python /trusted/repository-security-audit/scripts/audit.py --profile static \
  --repo /readonly/snapshot --target-id 'product@verified-snapshot' \
  --evidence /private/review/new-run/evidence.merged.json --out /private/audit/final-run
```

固定対象外48 IDと根拠・承認付き非該当だけをスキップとして扱い、資料不足・時間切れ・失敗は項目/条件ごとにNOT_RUN/BLOCKED等で残します。並列機能が使えなければ未実施を明記します。補助CLIの成功は監査合格や実際の並列実行の証明ではありません。詳細は[並列レビュー手順](../skills/repository-security-audit/references/parallel-review.md)を参照してください。

## レポートの読み方

- **サマリー**：不備・確認待ち・確認済み・対象外の件数、不備の修正先、確認方法別・分野別の内訳、次に進めることを確認します。件数から一覧へ移動できます。
- **全項目一覧**：220項目の判定・確認方法・要点を並べます。検索、判定、確認方法、分野で絞り込み、項目名から根拠・証拠・合格条件を開けます。詳細を閉じても絞り込みは維持します。狭い画面ではカード形式になります。
- **確認範囲・資料**：取得済みの範囲、不足資料、自動検出の候補、対応表、公式の技術資料、scopeや判定条件を確認します。

集計は親項目の判定です。個別条件にだけFAILがある場合も不備として明示し、親が未完了であることを併記します。確認方法の分類は実行済みの証拠ではありません。保存済み結果の表示更新では、元の判定・日時・scopeを維持し、旧基準の結果であることを表示します。

HTMLはオフラインで開けます。JavaScriptを使えない場合も全項目と詳細を本文から読めます。企業・組織別の被害事例は掲載しません。
