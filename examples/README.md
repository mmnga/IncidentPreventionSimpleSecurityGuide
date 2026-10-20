# 合成アプリ・チェック対応表・レポート例

## アプリ群

[apps/](apps/README.md) に、架空のテナント別ノート・問い合わせサービスを用意しています。

- Web、Python API、Flutterの共通UIとiOS/Androidの統合ソース・設定。
- 固定文面の受付メール、OAuth/webhook、AIの検索・tool権限境界。
- Terraform、コンテナ、Kubernetes、CI/CD、Git・依存・配布ポリシー。
- 全220項目の個別不備ケースと、実環境確認・失効・隔離・復旧等の未記入モデル。

[COVERAGE.md](COVERAGE.md) から全220 IDの確認先を一覧できます。[coverage.json](coverage.json) は正本台帳のhashと、静的184・full 127個別条件の参照を持つ機械可読の索引です。開発テストでID・条件・参照先の欠落と重複を検査します。

[アーキテクチャ図（10枚）](../docs/architecture/index.html)で、各アプリ・インフラ・連携・運用の構成を画像で読めます。参照コード、設定・ひな形、未接続・未実施を色分けし、実装上の関係と設計上の接続を区別しています。

この構成はチェックを検討するための教材です。全項目を実装済み・検証済み・PASSとしたものではありません。static対象外48項目は、運用モデルを置いてもOUT_OF_SCOPEのままです。SDK生成ファイル、実配布物、依存lock、実Git履歴、実環境の設定・実測結果は含めず、アプリの起動・ビルド・Terraform applyは実施していません。

## 過去のレポート例

2026-10-16のエンジンで生成した、別の架空snapshotの静的トリアージです。今回の `apps/` を監査した結果ではありません。判定はINCOMPLETE、実環境中心の48項目はOUT_OF_SCOPEです。実プロダクトの監査結果やPASS証拠ではありません。

- [report.html](report.html)：一般化した説明と公式技術資料を掲載する結果例。
- `results.json` / `evidence.template.json`：合成結果と未完成の証拠テンプレート。

事例を含んでいた旧例は内容を変えず、Git管理対象外の `private-case-studies/originals/examples/` へ移動しました。
