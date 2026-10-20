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

## チェック項目一覧

全220項目を22分野にまとめています。分野を開くと、各項目を確認できます。

- **静的**：ソース・設定・提供済み資料から確認する172項目。
- **実環境**：稼働環境・ログ・運用記録・復旧試験などで確認する48項目。静的レビューでは `OUT_OF_SCOPE`。

項目名・照合IDは[チェック定義](skills/repository-security-audit/references/checks.json)に対応しています。

<details>
<summary>シークレットと認証情報（静的9・実環境1）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 現在のソース内の秘密情報 | `SEC-01` | 静的 |
| 秘密鍵・署名鍵の混入 | `SEC-02` | 静的 |
| .env・認証設定の混入 | `SEC-03` | 静的 |
| 接続文字列・URL内の資格情報 | `SEC-04` | 静的 |
| ブラウザ・モバイル公開設定 | `SEC-05` | 静的 |
| テスト・ノートブック・fixtureの秘密情報 | `SEC-06` | 静的 |
| シークレットの権限・有効期限 | `SEC-07` | 静的 |
| OIDC・ワークロードIDの信頼条件 | `SEC-08` | 静的 |
| シークレット注入と平文露出 | `SEC-09` | 静的 |
| 失効・ローテーションの実効性 | `SEC-10` | 実環境 |

</details>

<details>
<summary>Git履歴とリポジトリ統制（静的5・実環境5）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 全到達可能履歴の秘密情報検査 | `GIT-01` | 静的 |
| shallow・partial cloneと取得範囲 | `GIT-02` | 静的 |
| 未追跡・ignoredファイル | `GIT-03` | 静的 |
| submodule・LFSの実体 | `GIT-04` | 静的 |
| 公開範囲とfork・mirror | `GIT-05` | 実環境 |
| 保護ブランチ・ruleset | `GIT-06` | 実環境 |
| 重要ファイルのCODEOWNERS | `GIT-07` | 静的 |
| 管理者・botの迂回権限 | `GIT-08` | 実環境 |
| push時の秘密情報防止 | `GIT-09` | 実環境 |
| force push・削除・監査証跡 | `GIT-10` | 実環境 |

</details>

<details>
<summary>CI/CDとビルド実行（静的10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| Action・再利用workflowの固定 | `CIC-01` | 静的 |
| CIトークンの最小権限 | `CIC-02` | 静的 |
| 特権イベントと未信頼コード | `CIC-03` | 静的 |
| 式展開・シェルへの入力注入 | `CIC-04` | 静的 |
| checkout資格情報の残留 | `CIC-05` | 静的 |
| 秘密情報の継承・PR配布 | `CIC-06` | 静的 |
| runner隔離・使い捨て性 | `CIC-07` | 静的 |
| ビルドの外向き通信 | `CIC-08` | 静的 |
| cache・artifact汚染 | `CIC-09` | 静的 |
| デプロイ承認と署名job分離 | `CIC-10` | 静的 |

</details>

<details>
<summary>依存関係とサプライチェーン（静的10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 全manifest・lockfileの棚卸し | `SUP-01` | 静的 |
| 既知脆弱性と悪用実績 | `SUP-02` | 静的 |
| 悪性パッケージ・侵害版 | `SUP-03` | 静的 |
| install・build lifecycle script | `SUP-04` | 静的 |
| registryとdependency confusion | `SUP-05` | 静的 |
| 整合性・署名・provenance | `SUP-06` | 静的 |
| 非固定Git・URL・動的依存 | `SUP-07` | 静的 |
| 保守終了・runtimeサポート | `SUP-08` | 静的 |
| 更新PRと差分レビュー | `SUP-09` | 静的 |
| SBOMと実配布物の一致 | `SUP-10` | 静的 |

</details>

<details>
<summary>配布物と公開アセット（静的8・実環境2）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 配布ファイル許可リスト | `REL-01` | 静的 |
| source map・デバッグシンボル | `REL-02` | 静的 |
| .git・バックアップ・設定の配布 | `REL-03` | 静的 |
| フロントエンドbundleの秘密値 | `REL-04` | 静的 |
| コンテナ過去層・build arg | `REL-05` | 静的 |
| release署名と検証側 | `REL-06` | 静的 |
| 配布版の不変性・巻き戻り防止 | `REL-07` | 実環境 |
| preview・stagingの公開範囲 | `REL-08` | 静的 |
| CI artifactとrelease添付の内容 | `REL-09` | 静的 |
| 再現buildとリリース対応表 | `REL-10` | 実環境 |

</details>

<details>
<summary>認証とセッション（静的10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 認証処理の一元化と迂回 | `AUT-01` | 静的 |
| 管理者MFAと復旧経路 | `AUT-02` | 静的 |
| パスワード保存 | `AUT-03` | 静的 |
| 総当たり・認証濫用 | `AUT-04` | 静的 |
| ユーザー列挙の抑制 | `AUT-05` | 静的 |
| reset・メール変更・招待token | `AUT-06` | 静的 |
| JWT・OIDC署名とclaim | `AUT-07` | 静的 |
| OAuth認証フロー | `AUT-08` | 静的 |
| session cookieと固定化 | `AUT-09` | 静的 |
| logout・権限変更後の失効 | `AUT-10` | 静的 |

</details>

<details>
<summary>認可とテナント分離（静的10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 各endpointのサーバー側認可 | `AZ-01` | 静的 |
| オブジェクト単位のIDOR/BOLA | `AZ-02` | 静的 |
| 組織・テナント横断 | `AZ-03` | 静的 |
| 管理機能・ロール昇格 | `AZ-04` | 静的 |
| mass assignment・フィールド認可 | `AZ-05` | 静的 |
| 一括処理・export認可 | `AZ-06` | 静的 |
| GraphQL・WebSocket・RPC認可 | `AZ-07` | 静的 |
| worker・queueの権限継承 | `AZ-08` | 静的 |
| DB RLSと接続role | `AZ-09` | 静的 |
| cache・検索・共有URLの境界 | `AZ-10` | 静的 |

</details>

<details>
<summary>入力とコード実行境界（静的10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| SQL・NoSQL injection | `INJ-01` | 静的 |
| OSコマンド injection | `INJ-02` | 静的 |
| テンプレート・式 injection | `INJ-03` | 静的 |
| 危険なdeserialization | `INJ-04` | 静的 |
| path traversal・任意読取 | `INJ-05` | 静的 |
| SSRF・metadata到達 | `INJ-06` | 静的 |
| XML外部実体・entity展開 | `INJ-07` | 静的 |
| uploadと危険ファイル処理 | `INJ-08` | 静的 |
| prototype pollution・object merge | `INJ-09` | 静的 |
| ReDoS・巨大入力・展開爆弾 | `INJ-10` | 静的 |

</details>

<details>
<summary>Web・HTTP・APIの露出（静的10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| XSSと出力エンコード | `WEB-01` | 静的 |
| CSRF・cross-site操作 | `WEB-02` | 静的 |
| CORSの実効許可範囲 | `WEB-03` | 静的 |
| CSPと第三者script | `WEB-04` | 静的 |
| HTTPS・TLS・証明書検証 | `WEB-05` | 静的 |
| 公開API docs・debug endpoint | `WEB-06` | 静的 |
| cache headerと機密応答 | `WEB-07` | 静的 |
| redirect・host headerの信頼 | `WEB-08` | 静的 |
| API濫用・ページング・query制限 | `WEB-09` | 静的 |
| HTTP parser・proxy境界 | `WEB-10` | 静的 |

</details>

<details>
<summary>データ保護とプライバシー（静的10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| データ分類・流れ・所有者 | `DAT-01` | 静的 |
| データ最小化 | `DAT-02` | 静的 |
| 保存時暗号化と鍵分離 | `DAT-03` | 静的 |
| テスト環境への本番データ持込 | `DAT-04` | 静的 |
| 保存期限・削除・派生データ | `DAT-05` | 静的 |
| export・download保護 | `DAT-06` | 静的 |
| 暗号方式・乱数・nonce | `DAT-07` | 静的 |
| backup・snapshotの公開と権限 | `DAT-08` | 静的 |
| 一時ファイル・crash dump | `DAT-09` | 静的 |
| 第三者処理とデータ送信先 | `DAT-10` | 静的 |

</details>

<details>
<summary>クラウドとInfrastructure as Code（静的8・実環境2）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| ストレージ公開・ACL | `CLD-01` | 静的 |
| DB・管理portの外部公開 | `CLD-02` | 静的 |
| IAM wildcard・権限昇格 | `CLD-03` | 静的 |
| 環境間・アカウント間分離 | `CLD-04` | 静的 |
| metadata・workload identity | `CLD-05` | 静的 |
| Terraform state・plan保護 | `CLD-06` | 静的 |
| IaCと実環境のdrift | `CLD-07` | 実環境 |
| serverless・API gateway権限 | `CLD-08` | 静的 |
| クラウド監査ログの独立保管 | `CLD-09` | 静的 |
| DNS・TLS・放置資産 | `CLD-10` | 実環境 |

</details>

<details>
<summary>コンテナとKubernetes（静的10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| base imageのdigest固定 | `CTR-01` | 静的 |
| 非root実行・user namespace | `CTR-02` | 静的 |
| privileged・capability・昇格禁止 | `CTR-03` | 静的 |
| host mount・socket共有 | `CTR-04` | 静的 |
| read-only rootと書込領域 | `CTR-05` | 静的 |
| Kubernetes RBAC | `CTR-06` | 静的 |
| service account token | `CTR-07` | 静的 |
| NetworkPolicyと境界 | `CTR-08` | 静的 |
| secret管理とetcd保護 | `CTR-09` | 静的 |
| admission・image検証・実行制限 | `CTR-10` | 静的 |

</details>

<details>
<summary>ログ・テレメトリ・サポート（静的10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 認証情報のログ抑止 | `OBS-01` | 静的 |
| 個人情報・本文の最小化 | `OBS-02` | 静的 |
| 例外・stack traceの露出 | `OBS-03` | 静的 |
| CI debug・環境dump | `OBS-04` | 静的 |
| APM・error tracking・session replay | `OBS-05` | 静的 |
| ログの閲覧権限・保持期間 | `OBS-06` | 静的 |
| 監査eventの網羅 | `OBS-07` | 静的 |
| ログ改ざん・injection | `OBS-08` | 静的 |
| 異常な大量取得の検知 | `OBS-09` | 静的 |
| サポート添付・HARのサニタイズ | `OBS-10` | 静的 |

</details>

<details>
<summary>外部SaaS・OAuth・webhook（静的10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 外部連携の台帳・所有者 | `INT-01` | 静的 |
| OAuth scope最小化 | `INT-02` | 静的 |
| refresh token・連携秘密値の保管 | `INT-03` | 静的 |
| 連携解除と退職後失効 | `INT-04` | 静的 |
| webhook署名・時刻・replay | `INT-05` | 静的 |
| 外部responseの検証 | `INT-06` | 静的 |
| 外向きwebhookのSSRFとpayload | `INT-07` | 静的 |
| service-to-service認証 | `INT-08` | 静的 |
| 第三者障害・侵害時の遮断 | `INT-09` | 静的 |
| 送信データと再利用・保持設定 | `INT-10` | 静的 |

</details>

<details>
<summary>AI・LLM・エージェント（静的9・実環境1）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 直接・間接prompt injection | `AIM-01` | 静的 |
| tool実行権限と人の承認 | `AIM-02` | 静的 |
| prompt・contextの秘密情報 | `AIM-03` | 静的 |
| RAG・vector storeのACL | `AIM-04` | 静的 |
| 生成結果のコード・HTML安全性 | `AIM-05` | 静的 |
| MCP・pluginの供給元とscope | `AIM-06` | 静的 |
| agent sandboxとegress | `AIM-07` | 静的 |
| memory・会話・cache分離 | `AIM-08` | 静的 |
| AI提供者の保存・再利用 | `AIM-09` | 実環境 |
| agent濫用・監査と停止 | `AIM-10` | 静的 |

</details>

<details>
<summary>開発環境と監査実行の安全性（静的9・実環境1）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| IDE拡張の承認と更新 | `DEV-01` | 静的 |
| devcontainer・bootstrap実行 | `DEV-02` | 静的 |
| Git hook・filter・fsmonitor | `DEV-03` | 静的 |
| 端末上の本番資格情報 | `DEV-04` | 実環境 |
| curl pipe shell・動的実行 | `DEV-05` | 静的 |
| 監査ツールの供給元・固定 | `DEV-06` | 静的 |
| リポジトリ内の監査妨害命令 | `DEV-07` | 静的 |
| symlink・巨大ファイル・archive | `DEV-08` | 静的 |
| scannerの通信・telemetry | `DEV-09` | 静的 |
| 証拠・HTMLの二次漏えい防止 | `DEV-10` | 静的 |

</details>

<details>
<summary>検証・運用ゲート・継続監査（静的9・実環境1）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 脅威モデルと適用範囲 | `TST-01` | 静的 |
| 認証・認可の否定テスト | `TST-02` | 静的 |
| SASTの範囲とエラー | `TST-03` | 静的 |
| SCAの更新とゲート | `TST-04` | 静的 |
| 秘密情報検査の多段化 | `TST-05` | 静的 |
| IaC・containerの検査 | `TST-06` | 静的 |
| DAST・APIテストの安全実行 | `TST-07` | 実環境 |
| 例外・抑制の期限管理 | `TST-08` | 静的 |
| 修正の回帰テスト | `TST-09` | 静的 |
| 監査証拠の完全性と新鮮さ | `TST-10` | 静的 |

</details>

<details>
<summary>漏えい対応と復旧（静的3・実環境7）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 漏えい対応の連絡・責任者 | `IR-01` | 静的 |
| 秘密値の緊急失効 | `IR-02` | 実環境 |
| 端末・runnerの隔離と再構築 | `IR-03` | 実環境 |
| 影響版・顧客・データの追跡 | `IR-04` | 実環境 |
| 証拠保全と変更記録 | `IR-05` | 静的 |
| 安全なbuild・配布復旧 | `IR-06` | 実環境 |
| backup復元と復旧目標 | `IR-07` | 実環境 |
| 利用者・関係者への通知判断 | `IR-08` | 実環境 |
| 侵害通知の受信と継続監視 | `IR-09` | 静的 |
| 事後分析と是正の検証 | `IR-10` | 実環境 |

</details>

<details>
<summary>ランサムウェア：侵入経路と露出面（静的5・実環境5）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| VPN・ZTNAの公開管理面 | `RAN-01-01` | 静的 |
| RDP・SSHの外部公開 | `RAN-01-02` | 静的 |
| 未修正の境界機器脆弱性 | `RAN-01-03` | 静的 |
| 認証基盤のMFA耐フィッシング | `RAN-01-04` | 実環境 |
| サービスアカウントの過剰権限 | `RAN-01-05` | 静的 |
| 初期アクセスブローカー由来の認証情報 | `RAN-01-06` | 実環境 |
| 開発者端末から本番への到達性 | `RAN-01-07` | 実環境 |
| サポート用リモートツールの統制 | `RAN-01-08` | 実環境 |
| 外部公開資産の棚卸し | `RAN-01-09` | 静的 |
| ブレークグラス認証の監査 | `RAN-01-10` | 実環境 |

</details>

<details>
<summary>ランサムウェア：横展開と特権昇格（静的2・実環境8）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 管理者権限の分離 | `RAN-02-01` | 静的 |
| ドメイン管理者認証の露出 | `RAN-02-02` | 実環境 |
| 特権セッションの短期化 | `RAN-02-03` | 実環境 |
| 端末間リモート実行の制御 | `RAN-02-04` | 実環境 |
| SMB管理共有の到達性 | `RAN-02-05` | 実環境 |
| ネットワークセグメンテーション | `RAN-02-06` | 静的 |
| 横移動に使える共通鍵の排除 | `RAN-02-07` | 実環境 |
| 端末EDRの改ざん防止 | `RAN-02-08` | 実環境 |
| 管理プレーンのアクセスログ | `RAN-02-09` | 実環境 |
| 権限昇格経路の継続評価 | `RAN-02-10` | 実環境 |

</details>

<details>
<summary>ランサムウェア：暗号化・破壊の阻止（静的5・実環境5）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 重要ファイルの大量変更検知 | `RAN-03-01` | 実環境 |
| バックアップ削除権限の分離 | `RAN-03-02` | 静的 |
| シャドウコピー削除の監視 | `RAN-03-03` | 実環境 |
| 大量暗号化の振る舞い検知 | `RAN-03-04` | 実環境 |
| 異常なプロセス起動の監視 | `RAN-03-05` | 実環境 |
| 重要DBの破壊操作保護 | `RAN-03-06` | 静的 |
| ストレージ管理APIの破壊権限 | `RAN-03-07` | 静的 |
| オブジェクトストレージの版管理 | `RAN-03-08` | 静的 |
| バックアップの不変性・WORM | `RAN-03-09` | 静的 |
| 保護機能停止の検出と通知 | `RAN-03-10` | 実環境 |

</details>

<details>
<summary>ランサムウェア：恐喝・復旧・演習（実環境10）</summary>

| 確認項目 | 照合ID | 区分 |
|---|---|---|
| 大量持ち出しと暗号化の相関検知 | `RAN-04-01` | 実環境 |
| 外向き大容量転送の異常検知 | `RAN-04-02` | 実環境 |
| 外部共有リンクの一括発行監視 | `RAN-04-03` | 実環境 |
| ランサム対応の封じ込め手順 | `RAN-04-04` | 実環境 |
| クリーンルーム復旧手順 | `RAN-04-05` | 実環境 |
| オフライン復旧経路 | `RAN-04-06` | 実環境 |
| RPO・RTOの実測 | `RAN-04-07` | 実環境 |
| 復元テストの成功証跡 | `RAN-04-08` | 実環境 |
| 復旧用IDと鍵の独立保管 | `RAN-04-09` | 実環境 |
| 二重恐喝時の法務・通知手順 | `RAN-04-10` | 実環境 |

</details>

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
