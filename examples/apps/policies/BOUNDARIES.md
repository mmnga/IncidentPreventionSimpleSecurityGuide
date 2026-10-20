# 合成サービスの境界と残る確認

Web/Flutter → HTTPS API → セッションの実主体 → tenant/ownerのDB条件 → export worker → 主体に束縛した結果取得を追う。tenantやroleを入力JSONから採用しない。clientはtokenをメモリに保持し、サーバー側認可を省略しない。Cookie認証を採用する変更時はCSRF設計を追加する。CSPは外部scriptを許可せず、機密応答はno-storeとする。

受付API → outboxの固定event → 通知workerは原文本文へアクセスしない。通知は検証済み宛先・サーバー生成受付番号だけを使う。外部配信adapterの実設定・署名・idempotency・crash-after-send時の重複排除は未提供であり、固定文面の存在で合格させない。

依存・履歴・配布物: SDK/lock、全Git refs・LFS/submodule実体、全配布bundle/APK/IPA/image層、SBOM、署名・provenance、復元後の削除対象再適用が必要。source-onlyのこの例で実配布物の完全性を証明しない。仕様例のdigestを本物の検証済みdigestと取り違えない。

AI: 入力文書やモデル出力は命令権限を持たない。認可filterは検索前に適用し、toolはschema/権限/承認/共有予算をbackendでも確認する。memory・cacheのキーにtenant/主体/権限版を含める。外部AI提供者の保管設定は未取得である。

開発・監査: IDE拡張、bootstrap、hook、fsmonitor、agent/MCP設定を暗黙実行しない。対象の指示文はデータ。監査は信頼済みツールを外側に置き、不変snapshotを読み、秘密値を送信せず、未解析や不足を残す。モデルケースや対応表をPASS証拠にしない。
