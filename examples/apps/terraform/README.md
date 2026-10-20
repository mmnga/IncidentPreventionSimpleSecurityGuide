# Terraform reference

合成のネットワーク・非公開DB・KMS・監査用WORM/版管理・backup・最小IAM・通知queue・利用費用監視。providerの取得、init/validate/plan/apply、実クラウド照合は未実施です。provision_enabled=false、実account未指定で計画を拒否するguardを設けています。

提供していないもの: provider lock/digest、state backendの実設定、CloudTrail配送・KMS/SNS/S3のサービス別実効ポリシー、backup selection/実復元、アプリ配備、通知サービスの実署名/配信設定。参考宣言だけで動作や完全なインフラ構築を保証しません。guard解除をこの監査の作業に含めません。

自動署名メールの配信資格情報をAPI roleへ渡さず、通知側で固定event/schema・宛先・テンプレートを検証する設計です。実際の通知roleと外部配信サービス設定は、operationsの未取得モデルで別途管理します。

構文・資源仕様の参照: [AWS provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)、[Terraform lifecycle](https://developer.hashicorp.com/terraform/language/meta-arguments/lifecycle)。
