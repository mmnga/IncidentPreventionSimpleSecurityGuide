# 証拠契約 v8 — schema 3

監査CLIで生成したテンプレートを起点にする。信頼済みの、対象外のディレクトリに置く。
JSONの重複キー、未知/重複チェックID、未知/重複条件ID、未知coverage、scope/profile不一致は拒否する。

## profile

`schema_version: 3`、`profile: "static" | "full"`、`scope_id`、`created_at` が必要。
staticのchecksは固定172 IDのみ、各 `criteria_results` は対応する `/S1` 条件を含む。
fullは全220 IDと原定義の `/C1` 等を使う。全範囲では現在127個の個別強化条件がある。
親PASSで条件の欠落・FAIL・BLOCKED等を隠すことはできない。
未記入の項目はNOT_RUNのまま。OUT_OF_SCOPEは出力専用であり、入力に使わない。

## 項目の証拠

PASS、FAIL、NOT_APPLICABLE、WAIVEDには、status、reviewer、reviewed_at、rationale、redacted=trueと1〜30件のevidence artifactが必要。
各artifactは証拠ディレクトリ配下の安全な相対path、SHA256、8文字以上のsummaryで指定する。
絶対path、..、symlink、対象repo配下、空ファイル、10MB超、hash不一致は拒否する。
NOT_APPLICABLEはapproved_by、WAIVEDはapproved_byとexpires_atも必要。WAIVEDは期限内でも合格に寄与しない。
親の非該当で条件を覆う場合も、矛盾するPASS/FAIL/受容リスクを隠さない。

PASS/N/Aへ変える前に、当該項目のすべてのobservation IDについて `resolved_observations` に根拠を記入する。
見つからなかった、コメントに安全と書いてある、guardらしい関数名がある、というだけの判断はしない。
スキャナー出力だけで不十分ならファイル/行・呼出経路・設定識別子・手動確認根拠をartifactへ記録する。

## coverageとgap

staticの必須領域はsource_tree、history、dependencies、release_artifacts、threat_intel、static_configs。
fullはsource_tree、history、dependencies、release_artifacts、platform、runtime、security_tests、threat_intel。
source_treeとthreat_intelは非該当にできない。それ以外を非該当にする場合も証拠と承認が必要。
未取得履歴・未提供配布物は、必要な対象である限りN/AではなくBLOCKED/NOT_RUN。
全gapを追加静的検査または根拠・承認付き非該当で補完する。実環境中心48項目のOUT_OF_SCOPEをgap補完に利用しない。

証拠の日時はタイムゾーン付きで7日以内。脅威情報PASSには `as_of` が必要で24時間以内。
未来5分を超える証拠、古い証拠、別snapshot/版の証拠を拒否する。これは本スキル独自の期限方針。

## 出力と合格

`all_clean` と `verdict` は現在のprofileのみ。static合格でも全範囲未確認：

```json
{
  "profile": "static",
  "verdict": "REVIEW PASSED",
  "all_clean": true,
  "all_clean_scope": "STATIC_ONLY",
  "scope_check_count": 172,
  "total_check_count": 220,
  "full_audit": {"verdict": "NOT_ASSESSED", "all_clean": false}
}
```

これは出力形式の説明であり、実監査結果ではない。
IPA対応状況は信頼済み対応表と項目結果から計算する。入力にipa合格フラグを置いても採用しない。
staticでは実環境側はNOT_RUNのままであり、12テーマ全体の完了を主張しない。

## 信頼モデル

hashとIDの検証は、証拠内容の真実性・レビューの適切さ・確認者の本人性を証明しない。
信頼済みreview領域のアクセス制御と独立承認を別途設ける。合成fixtureは実証拠として受け入れない。
v5以前の証拠のschema値を機械的に書き換えて再利用しない。新しい条件・snapshotで再確認する。

## 並列レビューの証拠断片

`parallel-review.md` に従い、各workerはschema 3の担当checksだけを返す。coverageとgapは親が担当し、全てのartifactは同じreview rootから参照する。`review_workflow.py` は担当IDの完全一致、非該当以外の全個別条件の返却、各項目の根拠を照合し、従来エンジンで証拠を検証してから統合する。既存の `audit.py` の証拠形式・期限・状態・終了コードは変えない。

根拠付きの親N/Aが全個別条件を覆う既存ルールは維持する。それ以外は、未確認の条件もNOT_RUN等の行と具体的な理由を残す。スキップという新しい入力statusは作らない。ledgerは運用の照合資料であり、実際のホスト上の実行や証拠内容の真偽を自動証明するものではない。


## v8補遺 — ARTEX / AI支援攻撃への対策

全220/静的172/対象外48のID構成を維持。v8時点の静的個別条件は181。v8の追加/S2・/S3は親PASSとは別の証拠が必要。fullにも/AR8-*を追加。
scope IDにartex-mapping.jsonのhashを含め、旧証拠を黙って流用しない。ARTEXのインストール・起動・通信・攻撃はしない。
新しい検査方法・重複整理・Resultの意味はartex-response.mdを正とする。監査者の本人性・証拠内容の真実性や経路台帳の意味をCLIが証明するものではない。

## v9.1補遺 — 課金監視・通知判断

`control-improvements.md` と `control-update-v9.1.json` を参照。v9.1時点は静的182条件、full 125条件。追加条件も従来と同じ証拠ゲートを通し、欠落・FAIL・BLOCKEDを親PASSで隠さない。220 ID / 172 / 48、schema 3、期限・状態・終了コードは維持する。台帳/engineの変更でscopeが変わるため、旧scopeを書き換えて再利用せず、新しい範囲の証拠を取り直す。確認方法の表示分類は実施済み証拠の代わりにならない。

## v9.2補遺 — 自動返信・通知メール

`mail-notification-review.md` と `control-update-v9.2.json` を参照。WEB-01/S2とWEB-09/S5、fullの各MAIL-1を追加し、現行は静的184条件、full 127条件。新条件も独立した証拠を要求し、親PASSで欠落やFAILを隠さない。メール非搭載は新条件ごとの根拠・承認付き非該当とし、既存の出力制御やAPI濫用条件を省略しない。scopeの手動移植は禁止。実送信・DNS照会・リプレイや表示確認はCLIで行わない。
