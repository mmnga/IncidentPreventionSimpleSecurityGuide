# Flutter iOS / Android 統合ソース

ノート一覧・作成・問い合わせの共通UIと、実API向けのHTTPSクライアントを含みます。既定はDemoGatewayで、外部通信・アカウント・永続tokenを使いません。HttpClientはOSの証明書検証を使い、任意URL・HTTP・リダイレクトへtokenを渡しません。UIで隠すことを認可の代わりにせず、APIで再認可します。

AndroidManifest/ネットワーク設定/Kotlin Activity/Gradleのapp設定と、iOSのAppDelegate/Info.plist/entitlementsを同梱しています。SDK生成のホストプロジェクト・Gradle wrapper・Xcode project・生成登録ファイル・依存lock・署名資産は未提供です。完全なビルド済みプロジェクトではありません。別の合成作業コピーで利用するFlutter SDKからAndroid/iOSホストを生成し、これらの設定を統合してから各OSで検証する必要があります。この依頼では生成・依存取得・ビルド・実機検証をしていません。

署名鍵、releaseビルド、配布物、SDK/依存のサポート状態、OS別の表示・完全性検証は未確認です。Flutterアプリがあることを、逆解析への耐性やバックエンドの安全性の証拠にしません。

仕様参照: [Flutter Android](https://docs.flutter.dev/deployment/android)、[Flutter iOS](https://docs.flutter.dev/deployment/ios)。掲載コードは合成サービス用の独自例で、生成済みテンプレートの複製ではありません。
