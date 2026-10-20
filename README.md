# Incident Prevention Security Guide

コードと設定を静的にレビューし、セキュリティ上の不備・根拠・未確認事項をレポートにまとめるスキルです。結果はオフラインで読めるHTMLとJSONで出力します。

## 確認範囲

秘密情報、認証・認可、API、ファイル配信、通知メール、依存ライブラリ、CI/CD、Terraformなどを扱います。

| 区分 | 範囲 |
|---|---|
| チェック全体 | 22分野・220項目 |
| 静的レビュー | 172項目・184の個別判定条件 |
| 実環境での確認が中心 | 48項目。静的レビューでは `OUT_OF_SCOPE` |

ソース・設定・提供済み資料から確認できる範囲を評価します。対象アプリの起動、依存のインストール、侵入試験は行いません。

## 使い方

1. [配置手順](docs/handoff/OPERATIONS.md)に沿って、`repository-security-audit` を利用する環境に登録します。
2. 許可された監査対象の読み取り専用コピーを用意します。スキル・証拠・出力先は対象の外に置きます。
3. [スキルの手順](skills/repository-security-audit/SKILL.md)に従い、サブエージェントで各項目と判定条件を並列レビューします。

付属CLIは確認候補の抽出と証拠の照合・レポート生成を担当します。初期確認から証拠の統合までの実行例は、[利用ガイド](docs/SKILL_GUIDE.md)を参照してください。

## 結果の読み方

- **サマリー**：不備と確認待ちの件数、次に対応すること。
- **全項目一覧**：項目ごとの判定、根拠、修正方針。検索・絞り込みに対応。
- **確認範囲・資料**：取得済みの範囲、不足資料、参照した指針。

| 判定 | 意味 |
|---|---|
| `PASS` | 確認範囲の条件を根拠付きで満たしている |
| `FAIL` | コードや設定、証拠から不備を確認した |
| `BLOCKED` | 必要なコード・設定・成果物などが不足している |
| `REVIEW` | 確認候補、または判断待ち |
| `NOT_RUN` | 未実施 |

静的レビューの全体合格は `REVIEW PASSED / STATIC ONLY` と表示します。証拠不足や未確認の項目を合格には含めません。

## サンプル

- [サンプルアプリ](examples/apps/README.md)：Web・API・Flutter・Terraformなどの架空プロジェクト。
- [全項目の対応表](examples/COVERAGE.md)：各チェックと、確認するコード・設定の対応。
- [アーキテクチャ図](docs/architecture/index.html)：アプリ・インフラ・連携の構成。

サンプルはチェックを検討するための教材です。全項目の実装・検証が完了した製品ではありません。

## 開発

スキル本体は [skills/repository-security-audit/](skills/repository-security-audit/)、開発ルールは [AGENTS.md](AGENTS.md) にまとめています。Python 3.10以降、標準ライブラリのみで動作します。

リポジトリ直下で、監査ツール自身のテストを実行します。

```bash
python3 -B -m unittest discover -s tests -p 'test_*.py' -q
```

[設計と現状](docs/handoff/CODEX_HANDOFF.md) · [開発計画](docs/handoff/CODEX_TASKS.md) · [受け入れ条件](docs/handoff/ACCEPTANCE.md)
