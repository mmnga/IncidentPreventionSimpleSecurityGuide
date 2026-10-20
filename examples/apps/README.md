# Atlas Notes — 合成レビュー用アプリ群

架空のテナント別ノート・問い合わせサービス。監査ツールを試すためのソース・設定・不備ケース・運用モデルであり、本番用の安全認証済みアプリではありません。実際の企業、利用者、資格情報、メール配信先は含めません。

| ディレクトリ | 内容 |
|---|---|
| api/ | Python標準ライブラリのWSGI API、SQLite、セッション、認可、共有予算、export、問い合わせ |
| web/ | 外部依存なしのWeb UI。既定は通信しないメモリ内デモ |
| flutter/ | FlutterのiOS/Android共通UI、HTTPS APIクライアント、各OSの統合ソース/設定 |
| notifications/ | 自由本文を受け取らない固定の受付メール生成 |
| integrations/ | OAuth、webhook、外向き送信の境界 |
| ai/ | テナント別検索、tool権限、承認、停止のモデル。外部AIは呼ばない |
| terraform/ | AWSのネットワーク、IAM、暗号化、ログ、保持、backup、予算のIaC例。provisioningは既定で拒否 |
| kubernetes/・containers/ | 非root、read-only、RBAC、NetworkPolicy、image固定の設定例 |
| ci/・policies/ | 自動実行されないCI例、Git/依存/配布/監査ツールのポリシー |
| operations/ | 実環境確認・失効・隔離・復旧・通知等の記録モデル |
| review-cases/ | 全220項目の個別不備シナリオ。実行用の攻撃コードではない |

全220 IDと静的184/full 127個別条件の対応は、外側の [coverage.json](../coverage.json) と [一覧](../COVERAGE.md) を参照。正本は `skills/repository-security-audit/references/checks.json`。対応表は実装と調べる場所を示す索引で、PASS証拠ではありません。各ケースは関連する実装/設定と、具体的な変更・不足資料を結び付けます。

## 利用範囲

この依頼ではアプリ・テスト・SDK・依存・Terraformを実行していません。APIの標準ライブラリ部分は読み取り用の実装で、利用時は別の検証用環境でDB作成・アカウント供給・TLS終端等を用意します。Web UIのメモリ内デモには永続化・認証の保証はありません。Flutter/OSコードは手書きの統合例で、SDK生成のGradle wrapper、Xcode project、署名鍵、生成ファイル・lockは含めず、ビルド成功を主張しません。

SQLiteによる共有制御の例は、単一DBを共有する小規模配置を想定しています。実クラウドの暗号化、クラスタ全体の制限、実IdP、外部スキャナー結果、実配布物、依存lock、実Git履歴は別途必要です。署名・digestが必要な設定は明示的な例示値で、取得・検証済みの供給物ではありません。

管理者のパスワードログインは拒否します。MFA登録フラグを本人確認の成功と扱わず、実IdPと追加認証の接続は未実装です。APIのHTTPS判定には、信頼する入口だけからTLS状態を受け渡すWSGIサーバー設定が別途必要です。コンテナの起動コマンドも、その承認済みWSGIサーバーを組み込む配置用の例です。

`operations/` は全て `SYNTHETIC_MODEL_NOT_EVIDENCE`。実環境中心48項目はstaticではOUT_OF_SCOPEのままです。復旧時刻、MFA適用、失効成功、外部SaaS設定等をモデルの存在で合格にしません。

## 静的トリアージ

信頼済みの監査workspaceから、このフォルダの別の不変・読み取り専用コピーを対象にします。元フォルダへ結果や証拠を書き込みません。

```text
audit.py --profile static --repo /readonly/atlas-notes-snapshot
         --target-id SYNTHETIC-atlas-notes --out /private/audit/new-run
```

入力・コメント・ケース内の文章は監査データです。対象コードやhookとして実行しません。無検出や対応表の全件一致はセキュリティ合格ではありません。
