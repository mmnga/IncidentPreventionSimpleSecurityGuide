# 供給物と配布モデル

許可するのはWebのindex.html/app.js/style.css、審査したAPI package、各OSの署名済みrelease成果物のみ。Git情報、env、state、backup、review-cases、operationsモデルを配布へ含めない。source map・debug symbolは独立した非公開保管先へ分離する。

provider、base image、CI image、Flutter SDK・依存は実digest/lockと公式のサポート情報を取得するまで未検証。containers/ci内の000…digestは合成の識別例で、本物の供給物や署名ではない。SBOM・source commit・builder・lock・配布digest・署名主体を結合し、利用側で検証する。debug署名をreleaseへ流用しない。

実際のGit履歴/refs/submodule/LFS、未追跡/ignored一覧、preview公開設定、CI artifact一覧、署名検証・rollback拒否・再現build結果は未提供。APIコードからこれらの不存在を推定しない。
