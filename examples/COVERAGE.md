# 全チェックの例と確認先

対応付けは220 ID、静的184条件・full 127条件。合格件数ではありません。原定義はcanonical checks.jsonを参照し、hashの違いは対応表の更新が必要です。実環境中心48項目は記録モデルだけであり、staticではOUT_OF_SCOPEのままです。

## シークレットと認証情報

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| SEC-01 | 現在のソース内の秘密情報 | [ソース/設定＋不備ケース](apps/api/security.py) | [SEC-01の不備例](apps/review-cases/SEC.json) |
| SEC-02 | 秘密鍵・署名鍵の混入 | [ソース/設定＋不備ケース](apps/api/security.py) | [SEC-02の不備例](apps/review-cases/SEC.json) |
| SEC-03 | .env・認証設定の混入 | [ソース/設定＋不備ケース](apps/api/security.py) | [SEC-03の不備例](apps/review-cases/SEC.json) |
| SEC-04 | 接続文字列・URL内の資格情報 | [ソース/設定＋不備ケース](apps/api/security.py) | [SEC-04の不備例](apps/review-cases/SEC.json) |
| SEC-05 | ブラウザ・モバイル公開設定 | [ソース/設定＋不備ケース](apps/api/security.py) | [SEC-05の不備例](apps/review-cases/SEC.json) |
| SEC-06 | テスト・ノートブック・fixtureの秘密情報 | [ソース/設定＋不備ケース](apps/api/security.py) | [SEC-06の不備例](apps/review-cases/SEC.json) |
| SEC-07 | シークレットの権限・有効期限 | [ソース/設定＋不備ケース](apps/api/security.py) | [SEC-07の不備例](apps/review-cases/SEC.json) |
| SEC-08 | OIDC・ワークロードIDの信頼条件 | [ソース/設定＋不備ケース](apps/api/security.py) | [SEC-08の不備例](apps/review-cases/SEC.json) |
| SEC-09 | シークレット注入と平文露出 | [ソース/設定＋不備ケース](apps/api/security.py) | [SEC-09の不備例](apps/review-cases/SEC.json) |
| SEC-10 | 失効・ローテーションの実効性 | [実環境の記録モデル・未実施](apps/api/security.py) | [SEC-10の不備例](apps/review-cases/SEC.json) |

## Git履歴とリポジトリ統制

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| GIT-01 | 全到達可能履歴の秘密情報検査 | [ソース/設定＋不備ケース](apps/policies/git-governance.json) | [GIT-01の不備例](apps/review-cases/GIT.json) |
| GIT-02 | shallow・partial cloneと取得範囲 | [ソース/設定＋不備ケース](apps/policies/git-governance.json) | [GIT-02の不備例](apps/review-cases/GIT.json) |
| GIT-03 | 未追跡・ignoredファイル | [ソース/設定＋不備ケース](apps/policies/git-governance.json) | [GIT-03の不備例](apps/review-cases/GIT.json) |
| GIT-04 | submodule・LFSの実体 | [ソース/設定＋不備ケース](apps/policies/git-governance.json) | [GIT-04の不備例](apps/review-cases/GIT.json) |
| GIT-05 | 公開範囲とfork・mirror | [実環境の記録モデル・未実施](apps/policies/git-governance.json) | [GIT-05の不備例](apps/review-cases/GIT.json) |
| GIT-06 | 保護ブランチ・ruleset | [実環境の記録モデル・未実施](apps/policies/git-governance.json) | [GIT-06の不備例](apps/review-cases/GIT.json) |
| GIT-07 | 重要ファイルのCODEOWNERS | [ソース/設定＋不備ケース](apps/policies/git-governance.json) | [GIT-07の不備例](apps/review-cases/GIT.json) |
| GIT-08 | 管理者・botの迂回権限 | [実環境の記録モデル・未実施](apps/policies/git-governance.json) | [GIT-08の不備例](apps/review-cases/GIT.json) |
| GIT-09 | push時の秘密情報防止 | [実環境の記録モデル・未実施](apps/policies/git-governance.json) | [GIT-09の不備例](apps/review-cases/GIT.json) |
| GIT-10 | force push・削除・監査証跡 | [実環境の記録モデル・未実施](apps/policies/git-governance.json) | [GIT-10の不備例](apps/review-cases/GIT.json) |

## CI/CDとビルド実行

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| CIC-01 | Action・再利用workflowの固定 | [ソース/設定＋不備ケース](apps/ci/review.workflow.yaml) | [CIC-01の不備例](apps/review-cases/CIC.json) |
| CIC-02 | CIトークンの最小権限 | [ソース/設定＋不備ケース](apps/ci/review.workflow.yaml) | [CIC-02の不備例](apps/review-cases/CIC.json) |
| CIC-03 | 特権イベントと未信頼コード | [ソース/設定＋不備ケース](apps/ci/review.workflow.yaml) | [CIC-03の不備例](apps/review-cases/CIC.json) |
| CIC-04 | 式展開・シェルへの入力注入 | [ソース/設定＋不備ケース](apps/ci/review.workflow.yaml) | [CIC-04の不備例](apps/review-cases/CIC.json) |
| CIC-05 | checkout資格情報の残留 | [ソース/設定＋不備ケース](apps/ci/review.workflow.yaml) | [CIC-05の不備例](apps/review-cases/CIC.json) |
| CIC-06 | 秘密情報の継承・PR配布 | [ソース/設定＋不備ケース](apps/ci/review.workflow.yaml) | [CIC-06の不備例](apps/review-cases/CIC.json) |
| CIC-07 | runner隔離・使い捨て性 | [ソース/設定＋不備ケース](apps/ci/review.workflow.yaml) | [CIC-07の不備例](apps/review-cases/CIC.json) |
| CIC-08 | ビルドの外向き通信 | [ソース/設定＋不備ケース](apps/ci/review.workflow.yaml) | [CIC-08の不備例](apps/review-cases/CIC.json) |
| CIC-09 | cache・artifact汚染 | [ソース/設定＋不備ケース](apps/ci/review.workflow.yaml) | [CIC-09の不備例](apps/review-cases/CIC.json) |
| CIC-10 | デプロイ承認と署名job分離 | [ソース/設定＋不備ケース](apps/ci/review.workflow.yaml) | [CIC-10の不備例](apps/review-cases/CIC.json) |

## 依存関係とサプライチェーン

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| SUP-01 | 全manifest・lockfileの棚卸し | [ソース/設定＋不備ケース](apps/policies/dependencies.json) | [SUP-01の不備例](apps/review-cases/SUP.json) |
| SUP-02 | 既知脆弱性と悪用実績 | [ソース/設定＋不備ケース](apps/policies/dependencies.json) | [SUP-02の不備例](apps/review-cases/SUP.json) |
| SUP-03 | 悪性パッケージ・侵害版 | [ソース/設定＋不備ケース](apps/policies/dependencies.json) | [SUP-03の不備例](apps/review-cases/SUP.json) |
| SUP-04 | install・build lifecycle script | [ソース/設定＋不備ケース](apps/policies/dependencies.json) | [SUP-04の不備例](apps/review-cases/SUP.json) |
| SUP-05 | registryとdependency confusion | [ソース/設定＋不備ケース](apps/policies/dependencies.json) | [SUP-05の不備例](apps/review-cases/SUP.json) |
| SUP-06 | 整合性・署名・provenance | [ソース/設定＋不備ケース](apps/policies/dependencies.json) | [SUP-06の不備例](apps/review-cases/SUP.json) |
| SUP-07 | 非固定Git・URL・動的依存 | [ソース/設定＋不備ケース](apps/policies/dependencies.json) | [SUP-07の不備例](apps/review-cases/SUP.json) |
| SUP-08 | 保守終了・runtimeサポート | [ソース/設定＋不備ケース](apps/policies/dependencies.json) | [SUP-08の不備例](apps/review-cases/SUP.json) |
| SUP-09 | 更新PRと差分レビュー | [ソース/設定＋不備ケース](apps/policies/dependencies.json) | [SUP-09の不備例](apps/review-cases/SUP.json) |
| SUP-10 | SBOMと実配布物の一致 | [ソース/設定＋不備ケース](apps/policies/dependencies.json) | [SUP-10の不備例](apps/review-cases/SUP.json) |

## 配布物と公開アセット

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| REL-01 | 配布ファイル許可リスト | [ソース/設定＋不備ケース](apps/policies/RELEASE.md) | [REL-01の不備例](apps/review-cases/REL.json) |
| REL-02 | source map・デバッグシンボル | [ソース/設定＋不備ケース](apps/policies/RELEASE.md) | [REL-02の不備例](apps/review-cases/REL.json) |
| REL-03 | .git・バックアップ・設定の配布 | [ソース/設定＋不備ケース](apps/policies/RELEASE.md) | [REL-03の不備例](apps/review-cases/REL.json) |
| REL-04 | フロントエンドbundleの秘密値 | [ソース/設定＋不備ケース](apps/policies/RELEASE.md) | [REL-04の不備例](apps/review-cases/REL.json) |
| REL-05 | コンテナ過去層・build arg | [ソース/設定＋不備ケース](apps/policies/RELEASE.md) | [REL-05の不備例](apps/review-cases/REL.json) |
| REL-06 | release署名と検証側 | [ソース/設定＋不備ケース](apps/policies/RELEASE.md) | [REL-06の不備例](apps/review-cases/REL.json) |
| REL-07 | 配布版の不変性・巻き戻り防止 | [実環境の記録モデル・未実施](apps/policies/RELEASE.md) | [REL-07の不備例](apps/review-cases/REL.json) |
| REL-08 | preview・stagingの公開範囲 | [ソース/設定＋不備ケース](apps/policies/RELEASE.md) | [REL-08の不備例](apps/review-cases/REL.json) |
| REL-09 | CI artifactとrelease添付の内容 | [ソース/設定＋不備ケース](apps/policies/RELEASE.md) | [REL-09の不備例](apps/review-cases/REL.json) |
| REL-10 | 再現buildとリリース対応表 | [実環境の記録モデル・未実施](apps/policies/RELEASE.md) | [REL-10の不備例](apps/review-cases/REL.json) |

## 認証とセッション

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| AUT-01 | 認証処理の一元化と迂回 | [ソース/設定＋不備ケース](apps/api/security.py) | [AUT-01の不備例](apps/review-cases/AUT.json) |
| AUT-02 | 管理者MFAと復旧経路 | [ソース/設定＋不備ケース](apps/api/security.py) | [AUT-02の不備例](apps/review-cases/AUT.json) |
| AUT-03 | パスワード保存 | [ソース/設定＋不備ケース](apps/api/security.py) | [AUT-03の不備例](apps/review-cases/AUT.json) |
| AUT-04 | 総当たり・認証濫用 | [ソース/設定＋不備ケース](apps/api/security.py) | [AUT-04の不備例](apps/review-cases/AUT.json) |
| AUT-05 | ユーザー列挙の抑制 | [ソース/設定＋不備ケース](apps/api/security.py) | [AUT-05の不備例](apps/review-cases/AUT.json) |
| AUT-06 | reset・メール変更・招待token | [ソース/設定＋不備ケース](apps/api/security.py) | [AUT-06の不備例](apps/review-cases/AUT.json) |
| AUT-07 | JWT・OIDC署名とclaim | [ソース/設定＋不備ケース](apps/api/security.py) | [AUT-07の不備例](apps/review-cases/AUT.json) |
| AUT-08 | OAuth認証フロー | [ソース/設定＋不備ケース](apps/api/security.py) | [AUT-08の不備例](apps/review-cases/AUT.json) |
| AUT-09 | session cookieと固定化 | [ソース/設定＋不備ケース](apps/api/security.py) | [AUT-09の不備例](apps/review-cases/AUT.json) |
| AUT-10 | logout・権限変更後の失効 | [ソース/設定＋不備ケース](apps/api/security.py) | [AUT-10の不備例](apps/review-cases/AUT.json) |

## 認可とテナント分離

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| AZ-01 | 各endpointのサーバー側認可 | [ソース/設定＋不備ケース](apps/api/app.py) | [AZ-01の不備例](apps/review-cases/AZ.json) |
| AZ-02 | オブジェクト単位のIDOR/BOLA | [ソース/設定＋不備ケース](apps/api/app.py) | [AZ-02の不備例](apps/review-cases/AZ.json) |
| AZ-03 | 組織・テナント横断 | [ソース/設定＋不備ケース](apps/api/app.py) | [AZ-03の不備例](apps/review-cases/AZ.json) |
| AZ-04 | 管理機能・ロール昇格 | [ソース/設定＋不備ケース](apps/api/app.py) | [AZ-04の不備例](apps/review-cases/AZ.json) |
| AZ-05 | mass assignment・フィールド認可 | [ソース/設定＋不備ケース](apps/api/app.py) | [AZ-05の不備例](apps/review-cases/AZ.json) |
| AZ-06 | 一括処理・export認可 | [ソース/設定＋不備ケース](apps/api/app.py) | [AZ-06の不備例](apps/review-cases/AZ.json) |
| AZ-07 | GraphQL・WebSocket・RPC認可 | [ソース/設定＋不備ケース](apps/api/app.py) | [AZ-07の不備例](apps/review-cases/AZ.json) |
| AZ-08 | worker・queueの権限継承 | [ソース/設定＋不備ケース](apps/api/app.py) | [AZ-08の不備例](apps/review-cases/AZ.json) |
| AZ-09 | DB RLSと接続role | [ソース/設定＋不備ケース](apps/api/app.py) | [AZ-09の不備例](apps/review-cases/AZ.json) |
| AZ-10 | cache・検索・共有URLの境界 | [ソース/設定＋不備ケース](apps/api/app.py) | [AZ-10の不備例](apps/review-cases/AZ.json) |

## 入力とコード実行境界

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| INJ-01 | SQL・NoSQL injection | [ソース/設定＋不備ケース](apps/api/security.py) | [INJ-01の不備例](apps/review-cases/INJ.json) |
| INJ-02 | OSコマンド injection | [ソース/設定＋不備ケース](apps/api/security.py) | [INJ-02の不備例](apps/review-cases/INJ.json) |
| INJ-03 | テンプレート・式 injection | [ソース/設定＋不備ケース](apps/api/security.py) | [INJ-03の不備例](apps/review-cases/INJ.json) |
| INJ-04 | 危険なdeserialization | [ソース/設定＋不備ケース](apps/api/security.py) | [INJ-04の不備例](apps/review-cases/INJ.json) |
| INJ-05 | path traversal・任意読取 | [ソース/設定＋不備ケース](apps/api/security.py) | [INJ-05の不備例](apps/review-cases/INJ.json) |
| INJ-06 | SSRF・metadata到達 | [ソース/設定＋不備ケース](apps/api/security.py) | [INJ-06の不備例](apps/review-cases/INJ.json) |
| INJ-07 | XML外部実体・entity展開 | [ソース/設定＋不備ケース](apps/api/security.py) | [INJ-07の不備例](apps/review-cases/INJ.json) |
| INJ-08 | uploadと危険ファイル処理 | [ソース/設定＋不備ケース](apps/api/security.py) | [INJ-08の不備例](apps/review-cases/INJ.json) |
| INJ-09 | prototype pollution・object merge | [ソース/設定＋不備ケース](apps/api/security.py) | [INJ-09の不備例](apps/review-cases/INJ.json) |
| INJ-10 | ReDoS・巨大入力・展開爆弾 | [ソース/設定＋不備ケース](apps/api/security.py) | [INJ-10の不備例](apps/review-cases/INJ.json) |

## Web・HTTP・APIの露出

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| WEB-01 | XSSと出力エンコード | [ソース/設定＋不備ケース](apps/api/app.py) | [WEB-01の不備例](apps/review-cases/WEB.json) |
| WEB-02 | CSRF・cross-site操作 | [ソース/設定＋不備ケース](apps/api/app.py) | [WEB-02の不備例](apps/review-cases/WEB.json) |
| WEB-03 | CORSの実効許可範囲 | [ソース/設定＋不備ケース](apps/api/app.py) | [WEB-03の不備例](apps/review-cases/WEB.json) |
| WEB-04 | CSPと第三者script | [ソース/設定＋不備ケース](apps/api/app.py) | [WEB-04の不備例](apps/review-cases/WEB.json) |
| WEB-05 | HTTPS・TLS・証明書検証 | [ソース/設定＋不備ケース](apps/api/app.py) | [WEB-05の不備例](apps/review-cases/WEB.json) |
| WEB-06 | 公開API docs・debug endpoint | [ソース/設定＋不備ケース](apps/api/app.py) | [WEB-06の不備例](apps/review-cases/WEB.json) |
| WEB-07 | cache headerと機密応答 | [ソース/設定＋不備ケース](apps/api/app.py) | [WEB-07の不備例](apps/review-cases/WEB.json) |
| WEB-08 | redirect・host headerの信頼 | [ソース/設定＋不備ケース](apps/api/app.py) | [WEB-08の不備例](apps/review-cases/WEB.json) |
| WEB-09 | API濫用・ページング・query制限 | [ソース/設定＋不備ケース](apps/api/app.py) | [WEB-09の不備例](apps/review-cases/WEB.json) |
| WEB-10 | HTTP parser・proxy境界 | [ソース/設定＋不備ケース](apps/api/app.py) | [WEB-10の不備例](apps/review-cases/WEB.json) |

## データ保護とプライバシー

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| DAT-01 | データ分類・流れ・所有者 | [ソース/設定＋不備ケース](apps/api/schema.sql) | [DAT-01の不備例](apps/review-cases/DAT.json) |
| DAT-02 | データ最小化 | [ソース/設定＋不備ケース](apps/api/schema.sql) | [DAT-02の不備例](apps/review-cases/DAT.json) |
| DAT-03 | 保存時暗号化と鍵分離 | [ソース/設定＋不備ケース](apps/api/schema.sql) | [DAT-03の不備例](apps/review-cases/DAT.json) |
| DAT-04 | テスト環境への本番データ持込 | [ソース/設定＋不備ケース](apps/api/schema.sql) | [DAT-04の不備例](apps/review-cases/DAT.json) |
| DAT-05 | 保存期限・削除・派生データ | [ソース/設定＋不備ケース](apps/api/schema.sql) | [DAT-05の不備例](apps/review-cases/DAT.json) |
| DAT-06 | export・download保護 | [ソース/設定＋不備ケース](apps/api/schema.sql) | [DAT-06の不備例](apps/review-cases/DAT.json) |
| DAT-07 | 暗号方式・乱数・nonce | [ソース/設定＋不備ケース](apps/api/schema.sql) | [DAT-07の不備例](apps/review-cases/DAT.json) |
| DAT-08 | backup・snapshotの公開と権限 | [ソース/設定＋不備ケース](apps/api/schema.sql) | [DAT-08の不備例](apps/review-cases/DAT.json) |
| DAT-09 | 一時ファイル・crash dump | [ソース/設定＋不備ケース](apps/api/schema.sql) | [DAT-09の不備例](apps/review-cases/DAT.json) |
| DAT-10 | 第三者処理とデータ送信先 | [ソース/設定＋不備ケース](apps/api/schema.sql) | [DAT-10の不備例](apps/review-cases/DAT.json) |

## クラウドとInfrastructure as Code

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| CLD-01 | ストレージ公開・ACL | [ソース/設定＋不備ケース](apps/terraform/network.tf) | [CLD-01の不備例](apps/review-cases/CLD.json) |
| CLD-02 | DB・管理portの外部公開 | [ソース/設定＋不備ケース](apps/terraform/network.tf) | [CLD-02の不備例](apps/review-cases/CLD.json) |
| CLD-03 | IAM wildcard・権限昇格 | [ソース/設定＋不備ケース](apps/terraform/network.tf) | [CLD-03の不備例](apps/review-cases/CLD.json) |
| CLD-04 | 環境間・アカウント間分離 | [ソース/設定＋不備ケース](apps/terraform/network.tf) | [CLD-04の不備例](apps/review-cases/CLD.json) |
| CLD-05 | metadata・workload identity | [ソース/設定＋不備ケース](apps/terraform/network.tf) | [CLD-05の不備例](apps/review-cases/CLD.json) |
| CLD-06 | Terraform state・plan保護 | [ソース/設定＋不備ケース](apps/terraform/network.tf) | [CLD-06の不備例](apps/review-cases/CLD.json) |
| CLD-07 | IaCと実環境のdrift | [実環境の記録モデル・未実施](apps/terraform/network.tf) | [CLD-07の不備例](apps/review-cases/CLD.json) |
| CLD-08 | serverless・API gateway権限 | [ソース/設定＋不備ケース](apps/terraform/network.tf) | [CLD-08の不備例](apps/review-cases/CLD.json) |
| CLD-09 | クラウド監査ログの独立保管 | [ソース/設定＋不備ケース](apps/terraform/network.tf) | [CLD-09の不備例](apps/review-cases/CLD.json) |
| CLD-10 | DNS・TLS・放置資産 | [実環境の記録モデル・未実施](apps/terraform/network.tf) | [CLD-10の不備例](apps/review-cases/CLD.json) |

## コンテナとKubernetes

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| CTR-01 | base imageのdigest固定 | [ソース/設定＋不備ケース](apps/containers/api.Dockerfile) | [CTR-01の不備例](apps/review-cases/CTR.json) |
| CTR-02 | 非root実行・user namespace | [ソース/設定＋不備ケース](apps/containers/api.Dockerfile) | [CTR-02の不備例](apps/review-cases/CTR.json) |
| CTR-03 | privileged・capability・昇格禁止 | [ソース/設定＋不備ケース](apps/containers/api.Dockerfile) | [CTR-03の不備例](apps/review-cases/CTR.json) |
| CTR-04 | host mount・socket共有 | [ソース/設定＋不備ケース](apps/containers/api.Dockerfile) | [CTR-04の不備例](apps/review-cases/CTR.json) |
| CTR-05 | read-only rootと書込領域 | [ソース/設定＋不備ケース](apps/containers/api.Dockerfile) | [CTR-05の不備例](apps/review-cases/CTR.json) |
| CTR-06 | Kubernetes RBAC | [ソース/設定＋不備ケース](apps/containers/api.Dockerfile) | [CTR-06の不備例](apps/review-cases/CTR.json) |
| CTR-07 | service account token | [ソース/設定＋不備ケース](apps/containers/api.Dockerfile) | [CTR-07の不備例](apps/review-cases/CTR.json) |
| CTR-08 | NetworkPolicyと境界 | [ソース/設定＋不備ケース](apps/containers/api.Dockerfile) | [CTR-08の不備例](apps/review-cases/CTR.json) |
| CTR-09 | secret管理とetcd保護 | [ソース/設定＋不備ケース](apps/containers/api.Dockerfile) | [CTR-09の不備例](apps/review-cases/CTR.json) |
| CTR-10 | admission・image検証・実行制限 | [ソース/設定＋不備ケース](apps/containers/api.Dockerfile) | [CTR-10の不備例](apps/review-cases/CTR.json) |

## ログ・テレメトリ・サポート

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| OBS-01 | 認証情報のログ抑止 | [ソース/設定＋不備ケース](apps/api/security.py) | [OBS-01の不備例](apps/review-cases/OBS.json) |
| OBS-02 | 個人情報・本文の最小化 | [ソース/設定＋不備ケース](apps/api/security.py) | [OBS-02の不備例](apps/review-cases/OBS.json) |
| OBS-03 | 例外・stack traceの露出 | [ソース/設定＋不備ケース](apps/api/security.py) | [OBS-03の不備例](apps/review-cases/OBS.json) |
| OBS-04 | CI debug・環境dump | [ソース/設定＋不備ケース](apps/api/security.py) | [OBS-04の不備例](apps/review-cases/OBS.json) |
| OBS-05 | APM・error tracking・session replay | [ソース/設定＋不備ケース](apps/api/security.py) | [OBS-05の不備例](apps/review-cases/OBS.json) |
| OBS-06 | ログの閲覧権限・保持期間 | [ソース/設定＋不備ケース](apps/api/security.py) | [OBS-06の不備例](apps/review-cases/OBS.json) |
| OBS-07 | 監査eventの網羅 | [ソース/設定＋不備ケース](apps/api/security.py) | [OBS-07の不備例](apps/review-cases/OBS.json) |
| OBS-08 | ログ改ざん・injection | [ソース/設定＋不備ケース](apps/api/security.py) | [OBS-08の不備例](apps/review-cases/OBS.json) |
| OBS-09 | 異常な大量取得の検知 | [ソース/設定＋不備ケース](apps/api/security.py) | [OBS-09の不備例](apps/review-cases/OBS.json) |
| OBS-10 | サポート添付・HARのサニタイズ | [ソース/設定＋不備ケース](apps/api/security.py) | [OBS-10の不備例](apps/review-cases/OBS.json) |

## 外部SaaS・OAuth・webhook

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| INT-01 | 外部連携の台帳・所有者 | [ソース/設定＋不備ケース](apps/integrations/boundaries.py) | [INT-01の不備例](apps/review-cases/INT.json) |
| INT-02 | OAuth scope最小化 | [ソース/設定＋不備ケース](apps/integrations/boundaries.py) | [INT-02の不備例](apps/review-cases/INT.json) |
| INT-03 | refresh token・連携秘密値の保管 | [ソース/設定＋不備ケース](apps/integrations/boundaries.py) | [INT-03の不備例](apps/review-cases/INT.json) |
| INT-04 | 連携解除と退職後失効 | [ソース/設定＋不備ケース](apps/integrations/boundaries.py) | [INT-04の不備例](apps/review-cases/INT.json) |
| INT-05 | webhook署名・時刻・replay | [ソース/設定＋不備ケース](apps/integrations/boundaries.py) | [INT-05の不備例](apps/review-cases/INT.json) |
| INT-06 | 外部responseの検証 | [ソース/設定＋不備ケース](apps/integrations/boundaries.py) | [INT-06の不備例](apps/review-cases/INT.json) |
| INT-07 | 外向きwebhookのSSRFとpayload | [ソース/設定＋不備ケース](apps/integrations/boundaries.py) | [INT-07の不備例](apps/review-cases/INT.json) |
| INT-08 | service-to-service認証 | [ソース/設定＋不備ケース](apps/integrations/boundaries.py) | [INT-08の不備例](apps/review-cases/INT.json) |
| INT-09 | 第三者障害・侵害時の遮断 | [ソース/設定＋不備ケース](apps/integrations/boundaries.py) | [INT-09の不備例](apps/review-cases/INT.json) |
| INT-10 | 送信データと再利用・保持設定 | [ソース/設定＋不備ケース](apps/integrations/boundaries.py) | [INT-10の不備例](apps/review-cases/INT.json) |

## AI・LLM・エージェント

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| AIM-01 | 直接・間接prompt injection | [ソース/設定＋不備ケース](apps/ai/policy.py) | [AIM-01の不備例](apps/review-cases/AIM.json) |
| AIM-02 | tool実行権限と人の承認 | [ソース/設定＋不備ケース](apps/ai/policy.py) | [AIM-02の不備例](apps/review-cases/AIM.json) |
| AIM-03 | prompt・contextの秘密情報 | [ソース/設定＋不備ケース](apps/ai/policy.py) | [AIM-03の不備例](apps/review-cases/AIM.json) |
| AIM-04 | RAG・vector storeのACL | [ソース/設定＋不備ケース](apps/ai/policy.py) | [AIM-04の不備例](apps/review-cases/AIM.json) |
| AIM-05 | 生成結果のコード・HTML安全性 | [ソース/設定＋不備ケース](apps/ai/policy.py) | [AIM-05の不備例](apps/review-cases/AIM.json) |
| AIM-06 | MCP・pluginの供給元とscope | [ソース/設定＋不備ケース](apps/ai/policy.py) | [AIM-06の不備例](apps/review-cases/AIM.json) |
| AIM-07 | agent sandboxとegress | [ソース/設定＋不備ケース](apps/ai/policy.py) | [AIM-07の不備例](apps/review-cases/AIM.json) |
| AIM-08 | memory・会話・cache分離 | [ソース/設定＋不備ケース](apps/ai/policy.py) | [AIM-08の不備例](apps/review-cases/AIM.json) |
| AIM-09 | AI提供者の保存・再利用 | [実環境の記録モデル・未実施](apps/ai/policy.py) | [AIM-09の不備例](apps/review-cases/AIM.json) |
| AIM-10 | agent濫用・監査と停止 | [ソース/設定＋不備ケース](apps/ai/policy.py) | [AIM-10の不備例](apps/review-cases/AIM.json) |

## 開発環境と監査実行の安全性

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| DEV-01 | IDE拡張の承認と更新 | [ソース/設定＋不備ケース](apps/policies/developer-environment.json) | [DEV-01の不備例](apps/review-cases/DEV.json) |
| DEV-02 | devcontainer・bootstrap実行 | [ソース/設定＋不備ケース](apps/policies/developer-environment.json) | [DEV-02の不備例](apps/review-cases/DEV.json) |
| DEV-03 | Git hook・filter・fsmonitor | [ソース/設定＋不備ケース](apps/policies/developer-environment.json) | [DEV-03の不備例](apps/review-cases/DEV.json) |
| DEV-04 | 端末上の本番資格情報 | [実環境の記録モデル・未実施](apps/policies/developer-environment.json) | [DEV-04の不備例](apps/review-cases/DEV.json) |
| DEV-05 | curl pipe shell・動的実行 | [ソース/設定＋不備ケース](apps/policies/developer-environment.json) | [DEV-05の不備例](apps/review-cases/DEV.json) |
| DEV-06 | 監査ツールの供給元・固定 | [ソース/設定＋不備ケース](apps/policies/developer-environment.json) | [DEV-06の不備例](apps/review-cases/DEV.json) |
| DEV-07 | リポジトリ内の監査妨害命令 | [ソース/設定＋不備ケース](apps/policies/developer-environment.json) | [DEV-07の不備例](apps/review-cases/DEV.json) |
| DEV-08 | symlink・巨大ファイル・archive | [ソース/設定＋不備ケース](apps/policies/developer-environment.json) | [DEV-08の不備例](apps/review-cases/DEV.json) |
| DEV-09 | scannerの通信・telemetry | [ソース/設定＋不備ケース](apps/policies/developer-environment.json) | [DEV-09の不備例](apps/review-cases/DEV.json) |
| DEV-10 | 証拠・HTMLの二次漏えい防止 | [ソース/設定＋不備ケース](apps/policies/developer-environment.json) | [DEV-10の不備例](apps/review-cases/DEV.json) |

## 検証・運用ゲート・継続監査

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| TST-01 | 脅威モデルと適用範囲 | [ソース/設定＋不備ケース](apps/policies/testing.json) | [TST-01の不備例](apps/review-cases/TST.json) |
| TST-02 | 認証・認可の否定テスト | [ソース/設定＋不備ケース](apps/policies/testing.json) | [TST-02の不備例](apps/review-cases/TST.json) |
| TST-03 | SASTの範囲とエラー | [ソース/設定＋不備ケース](apps/policies/testing.json) | [TST-03の不備例](apps/review-cases/TST.json) |
| TST-04 | SCAの更新とゲート | [ソース/設定＋不備ケース](apps/policies/testing.json) | [TST-04の不備例](apps/review-cases/TST.json) |
| TST-05 | 秘密情報検査の多段化 | [ソース/設定＋不備ケース](apps/policies/testing.json) | [TST-05の不備例](apps/review-cases/TST.json) |
| TST-06 | IaC・containerの検査 | [ソース/設定＋不備ケース](apps/policies/testing.json) | [TST-06の不備例](apps/review-cases/TST.json) |
| TST-07 | DAST・APIテストの安全実行 | [実環境の記録モデル・未実施](apps/policies/testing.json) | [TST-07の不備例](apps/review-cases/TST.json) |
| TST-08 | 例外・抑制の期限管理 | [ソース/設定＋不備ケース](apps/policies/testing.json) | [TST-08の不備例](apps/review-cases/TST.json) |
| TST-09 | 修正の回帰テスト | [ソース/設定＋不備ケース](apps/policies/testing.json) | [TST-09の不備例](apps/review-cases/TST.json) |
| TST-10 | 監査証拠の完全性と新鮮さ | [ソース/設定＋不備ケース](apps/policies/testing.json) | [TST-10の不備例](apps/review-cases/TST.json) |

## 漏えい対応と復旧

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| IR-01 | 漏えい対応の連絡・責任者 | [ソース/設定＋不備ケース](apps/operations/incident-response.md) | [IR-01の不備例](apps/review-cases/IR.json) |
| IR-02 | 秘密値の緊急失効 | [実環境の記録モデル・未実施](apps/operations/incident-response.md) | [IR-02の不備例](apps/review-cases/IR.json) |
| IR-03 | 端末・runnerの隔離と再構築 | [実環境の記録モデル・未実施](apps/operations/incident-response.md) | [IR-03の不備例](apps/review-cases/IR.json) |
| IR-04 | 影響版・顧客・データの追跡 | [実環境の記録モデル・未実施](apps/operations/incident-response.md) | [IR-04の不備例](apps/review-cases/IR.json) |
| IR-05 | 証拠保全と変更記録 | [ソース/設定＋不備ケース](apps/operations/incident-response.md) | [IR-05の不備例](apps/review-cases/IR.json) |
| IR-06 | 安全なbuild・配布復旧 | [実環境の記録モデル・未実施](apps/operations/incident-response.md) | [IR-06の不備例](apps/review-cases/IR.json) |
| IR-07 | backup復元と復旧目標 | [実環境の記録モデル・未実施](apps/operations/incident-response.md) | [IR-07の不備例](apps/review-cases/IR.json) |
| IR-08 | 利用者・関係者への通知判断 | [実環境の記録モデル・未実施](apps/operations/incident-response.md) | [IR-08の不備例](apps/review-cases/IR.json) |
| IR-09 | 侵害通知の受信と継続監視 | [ソース/設定＋不備ケース](apps/operations/incident-response.md) | [IR-09の不備例](apps/review-cases/IR.json) |
| IR-10 | 事後分析と是正の検証 | [実環境の記録モデル・未実施](apps/operations/incident-response.md) | [IR-10の不備例](apps/review-cases/IR.json) |

## ランサムウェア：侵入経路と露出面

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| RAN-01-01 | VPN・ZTNAの公開管理面 | [ソース/設定＋不備ケース](apps/operations/network-and-privilege.json) | [RAN-01-01の不備例](apps/review-cases/RAN1.json) |
| RAN-01-02 | RDP・SSHの外部公開 | [ソース/設定＋不備ケース](apps/operations/network-and-privilege.json) | [RAN-01-02の不備例](apps/review-cases/RAN1.json) |
| RAN-01-03 | 未修正の境界機器脆弱性 | [ソース/設定＋不備ケース](apps/operations/network-and-privilege.json) | [RAN-01-03の不備例](apps/review-cases/RAN1.json) |
| RAN-01-04 | 認証基盤のMFA耐フィッシング | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-01-04の不備例](apps/review-cases/RAN1.json) |
| RAN-01-05 | サービスアカウントの過剰権限 | [ソース/設定＋不備ケース](apps/operations/network-and-privilege.json) | [RAN-01-05の不備例](apps/review-cases/RAN1.json) |
| RAN-01-06 | 初期アクセスブローカー由来の認証情報 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-01-06の不備例](apps/review-cases/RAN1.json) |
| RAN-01-07 | 開発者端末から本番への到達性 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-01-07の不備例](apps/review-cases/RAN1.json) |
| RAN-01-08 | サポート用リモートツールの統制 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-01-08の不備例](apps/review-cases/RAN1.json) |
| RAN-01-09 | 外部公開資産の棚卸し | [ソース/設定＋不備ケース](apps/operations/network-and-privilege.json) | [RAN-01-09の不備例](apps/review-cases/RAN1.json) |
| RAN-01-10 | ブレークグラス認証の監査 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-01-10の不備例](apps/review-cases/RAN1.json) |

## ランサムウェア：横展開と特権昇格

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| RAN-02-01 | 管理者権限の分離 | [ソース/設定＋不備ケース](apps/operations/network-and-privilege.json) | [RAN-02-01の不備例](apps/review-cases/RAN2.json) |
| RAN-02-02 | ドメイン管理者認証の露出 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-02-02の不備例](apps/review-cases/RAN2.json) |
| RAN-02-03 | 特権セッションの短期化 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-02-03の不備例](apps/review-cases/RAN2.json) |
| RAN-02-04 | 端末間リモート実行の制御 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-02-04の不備例](apps/review-cases/RAN2.json) |
| RAN-02-05 | SMB管理共有の到達性 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-02-05の不備例](apps/review-cases/RAN2.json) |
| RAN-02-06 | ネットワークセグメンテーション | [ソース/設定＋不備ケース](apps/operations/network-and-privilege.json) | [RAN-02-06の不備例](apps/review-cases/RAN2.json) |
| RAN-02-07 | 横移動に使える共通鍵の排除 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-02-07の不備例](apps/review-cases/RAN2.json) |
| RAN-02-08 | 端末EDRの改ざん防止 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-02-08の不備例](apps/review-cases/RAN2.json) |
| RAN-02-09 | 管理プレーンのアクセスログ | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-02-09の不備例](apps/review-cases/RAN2.json) |
| RAN-02-10 | 権限昇格経路の継続評価 | [実環境の記録モデル・未実施](apps/operations/network-and-privilege.json) | [RAN-02-10の不備例](apps/review-cases/RAN2.json) |

## ランサムウェア：暗号化・破壊の阻止

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| RAN-03-01 | 重要ファイルの大量変更検知 | [実環境の記録モデル・未実施](apps/terraform/data.tf) | [RAN-03-01の不備例](apps/review-cases/RAN3.json) |
| RAN-03-02 | バックアップ削除権限の分離 | [ソース/設定＋不備ケース](apps/terraform/data.tf) | [RAN-03-02の不備例](apps/review-cases/RAN3.json) |
| RAN-03-03 | シャドウコピー削除の監視 | [実環境の記録モデル・未実施](apps/terraform/data.tf) | [RAN-03-03の不備例](apps/review-cases/RAN3.json) |
| RAN-03-04 | 大量暗号化の振る舞い検知 | [実環境の記録モデル・未実施](apps/terraform/data.tf) | [RAN-03-04の不備例](apps/review-cases/RAN3.json) |
| RAN-03-05 | 異常なプロセス起動の監視 | [実環境の記録モデル・未実施](apps/terraform/data.tf) | [RAN-03-05の不備例](apps/review-cases/RAN3.json) |
| RAN-03-06 | 重要DBの破壊操作保護 | [ソース/設定＋不備ケース](apps/terraform/data.tf) | [RAN-03-06の不備例](apps/review-cases/RAN3.json) |
| RAN-03-07 | ストレージ管理APIの破壊権限 | [ソース/設定＋不備ケース](apps/terraform/data.tf) | [RAN-03-07の不備例](apps/review-cases/RAN3.json) |
| RAN-03-08 | オブジェクトストレージの版管理 | [ソース/設定＋不備ケース](apps/terraform/data.tf) | [RAN-03-08の不備例](apps/review-cases/RAN3.json) |
| RAN-03-09 | バックアップの不変性・WORM | [ソース/設定＋不備ケース](apps/terraform/data.tf) | [RAN-03-09の不備例](apps/review-cases/RAN3.json) |
| RAN-03-10 | 保護機能停止の検出と通知 | [実環境の記録モデル・未実施](apps/terraform/data.tf) | [RAN-03-10の不備例](apps/review-cases/RAN3.json) |

## ランサムウェア：恐喝・復旧・演習

| 照合ID | 確認項目 | 材料 | 個別ケース |
|---|---|---|---|
| RAN-04-01 | 大量持ち出しと暗号化の相関検知 | [実環境の記録モデル・未実施](apps/operations/recovery-plan.json) | [RAN-04-01の不備例](apps/review-cases/RAN4.json) |
| RAN-04-02 | 外向き大容量転送の異常検知 | [実環境の記録モデル・未実施](apps/operations/recovery-plan.json) | [RAN-04-02の不備例](apps/review-cases/RAN4.json) |
| RAN-04-03 | 外部共有リンクの一括発行監視 | [実環境の記録モデル・未実施](apps/operations/recovery-plan.json) | [RAN-04-03の不備例](apps/review-cases/RAN4.json) |
| RAN-04-04 | ランサム対応の封じ込め手順 | [実環境の記録モデル・未実施](apps/operations/recovery-plan.json) | [RAN-04-04の不備例](apps/review-cases/RAN4.json) |
| RAN-04-05 | クリーンルーム復旧手順 | [実環境の記録モデル・未実施](apps/operations/recovery-plan.json) | [RAN-04-05の不備例](apps/review-cases/RAN4.json) |
| RAN-04-06 | オフライン復旧経路 | [実環境の記録モデル・未実施](apps/operations/recovery-plan.json) | [RAN-04-06の不備例](apps/review-cases/RAN4.json) |
| RAN-04-07 | RPO・RTOの実測 | [実環境の記録モデル・未実施](apps/operations/recovery-plan.json) | [RAN-04-07の不備例](apps/review-cases/RAN4.json) |
| RAN-04-08 | 復元テストの成功証跡 | [実環境の記録モデル・未実施](apps/operations/recovery-plan.json) | [RAN-04-08の不備例](apps/review-cases/RAN4.json) |
| RAN-04-09 | 復旧用IDと鍵の独立保管 | [実環境の記録モデル・未実施](apps/operations/recovery-plan.json) | [RAN-04-09の不備例](apps/review-cases/RAN4.json) |
| RAN-04-10 | 二重恐喝時の法務・通知手順 | [実環境の記録モデル・未実施](apps/operations/recovery-plan.json) | [RAN-04-10の不備例](apps/review-cases/RAN4.json) |

