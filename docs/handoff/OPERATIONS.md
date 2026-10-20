# 運用者向け短い手順

## Codexで引き継ぐ場合

1. このrepoを**監査する製品リポジトリとは別の信頼済み作業領域**へ配置。
2. Codexでrepoを開き、`AGENTS.md`を確認。[CODEX_START_PROMPT.md](CODEX_START_PROMPT.md) の指示文を貼り付ける。
3. Codexがテスト結果と改善差分を提示したら、対象ファイルとチェックIDの変更差分、証拠ゲートの維持をレビュー。
4. 将来製品監査を行う場合のみ、別の不変・読み取り専用snapshotパスを明示して依頼する。

## skillの配置

正本はrepo直下の `skills/repository-security-audit/` です。このフォルダ全体でskillとして利用でき、開発用の `tests/`・`docs/`・`examples/` は単体インストールに不要です。継続開発ではrepo全体を使います。

開発ソースを `skills/` に置くだけではCodexのrepo skillとして自動登録されません。この信頼済み開発repo内で呼び出して試す場合は、repo直下で次のリンクを作れます。今回のディレクトリ整理では登録用リンクを作成していません。

```bash
mkdir -p .agents/skills
ln -s ../../skills/repository-security-audit .agents/skills/repository-security-audit
```

Codexは `.agents/skills/` のskillを探索し、skillフォルダのsymlinkもサポートします。個人用に配置する場合は `~/.agents/skills/repository-security-audit/` が利用できます。[公式ドキュメント](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills)

Claude Codeの配置先は `~/.claude/skills/repository-security-audit/`、Cursorの配置先は `~/.cursor/skills/repository-security-audit/` です。配布する場合は正本フォルダ全体を配置し、各コピーを別々に編集しないでください。

**スキルを未信頼の検査対象リポジトリ内に入れない**。監査対象は別の不変・読み取り専用snapshotとし、信頼済み監査ワークスペースや個人用skillとして利用します。

事例を含んでいた元の配布文書・過去の検証記録は、Git管理対象外の `private-case-studies/originals/` に保存しています。配布するskillには企業・組織別の事故説明や事例記事のURLを含めません。現在の検証記録は [validation](../../validation/README.md) を参照してください。再現可能な配布物生成は [CODEX_TASKS.md](CODEX_TASKS.md) のP0-2に残っています。

## 機能と品質の保証範囲

ユーザーに対しては「172個の静的レビュー対象のうち、75字句ルールで63 IDへ確認候補を付与できる」と表現する。全172項目自動判定・侵入耐性認証とは言わない。

skillは親がホストのサブエージェントを2以上並列に実行する。[並列レビュー手順](../../skills/repository-security-audit/references/parallel-review.md)に従い、全ID・全個別条件を配分して確認する。実際の稼働・返却をホストで確認した範囲だけ報告し、限定合成テストを全件監査や実プロダクトの結果と混同しない。ホスト機能が使えなければ並列未実施と未確認の各項目を残す。CLIからのagent起動は行わない。
