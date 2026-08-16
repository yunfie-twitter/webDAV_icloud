# iCloud Encrypted WebDAV Gateway

WebDAVクライアントには平文の仮想ファイルシステムを見せ、iCloud Driveにはランダム名の暗号化チャンク・暗号化manifest・鍵capsuleだけを保存するゲートウェイです。入口はFTPではなくWebDAVです。

> **注意:** `icloudpy` はApple公式SDKではありません。Apple側の仕様変更、認証失効、レート制限で停止する可能性があります。本ソフト単独を唯一のバックアップにしないでください。

## 構成

```text
WebDAV client
  │ Tailscale / WireGuard
  ▼
Tailscale sidecar（TCP 443 raw forward、Funnel無効）
  │ TLS 1.3 + mTLSをそのまま転送
  ▼
Caddy ── HTTP (Docker edge network only) ── Gateway
                                             ├── PostgreSQL（正本）
                                             ├── Valkey（補助）
                                             ├── Host Key Broker
                                             │     └── TPM/CNG/HSM
                                             └── icloudpy ── iCloud
```

ホストへ公開する`ports`はありません。Tailscaleの443番だけがtailnet内で受け、`TS_SERVE_CONFIG`のraw TCP forwardによりCaddyのTLS 1.3 + mTLSへ渡します。Funnelは構成しません。PostgreSQLとValkeyもDocker internal networkだけです。

Tailscale identityは`tailscale-state` volumeへ永続化し、`TS_AUTH_ONCE=true`を使います。OAuth client secretには`?ephemeral=false`を付け、OAuth clientで許可したtagを`TS_EXTRA_ARGS=--advertise-tags=tag:...`へ渡します。Serve設定はfsnotifyのため`tailscale-config`directory全体をread-only mountします。

## iCloud上の形式

```text
.icloud-ftp-vault/
├── objects/      # AES-256-GCM暗号化チャンク（ランダムID）
├── manifests/    # 暗号化された各ファイル版の構成
├── keys/         # OS非依存WrappedKeyEnvelope + Recovery wrap
└── metadata/     # 将来の暗号化metadata snapshot予約領域
```

- 平文は最大4〜16 MiBの1チャンクだけメモリに保持し、ディスクへ保存しません。
- PUT中にSHA-256とSHA-512を計算します。同一checksumなら新versionを作りません。
- 変更時は既存と同じチャンクを再利用し、変わったチャンクだけ新規保存します。暗号化チャンクはランダムDEKを使うため、決定論的な「収束暗号」は使いません。
- ファイル名、仮想path、checksum、chunk配列は暗号化manifest内とPostgreSQLにあります。iCloudからは読めません。
- GETは暗号チャンクだけを一時取得し、認証・checksum検証後にWebDAVへ流します。復号済みファイルを恒久保存しません。

各DEKは二重にラップされます。

1. **Primary wrap:** Host Key BrokerのTPM/CNG/HSM KEK
2. **Recovery wrap:** FIPS 203 ML-KEM-768/1024（任意でX25519とのhybrid）

Primary KEK bytesはGatewayコンテナへ渡しません。Recovery secretも通常サーバーへ保存しません。

## 状態と競合制御

PostgreSQLが唯一の正本です。アップロード状態は次の順で記録されます。

```text
PENDING → UPLOADING → VERIFYING → ACTIVE
                         └──────→ FAILED
```

iCloudへmanifest・chunk・key capsuleをアップロードし、`stat`で存在確認した後だけ、PostgreSQL transactionで`current_manifest`を切り替えます。同時更新は`SELECT ... FOR UPDATE`と期待した旧manifest IDの照合で拒否されます。

Valkeyは正本ではありません。

- `lock:file:<path>`相当の120秒TTL lease（自動更新）
- 5分窓のupload/delete/move counter
- 1000変更、または十分な母数で削除率20%以上ならsafe mode
- safe mode中はDELETE・上書きMOVE・GCを停止

Valkey/AOFが停止しても、PostgreSQLの競合検査は残ります。

iCloud Webで暗号objectが直接削除された場合は、60秒間隔のreconcileで連続2回欠落を確認してからWebDAV namespaceをtombstone化します。一度だけ空の一覧を返すiCloud側の瞬断は削除として確定しません。

## Retentionと日次GC

既定値は次の通りです。世代数には現行版を含みます。

| 現行ファイルサイズ | 保持世代 |
|---|---:|
| 100 MiB未満 | 10 |
| 100 MiB〜1 GiB | 5 |
| 1 GiB超 | 3 |

GCは、期限切れ履歴→サイズ別世代超過→削除済みpathの履歴→容量上限時の最古履歴→未参照manifest/chunkの順に処理します。現行版は容量上限のためには削除しません。DBにないiCloud objectにも24時間の猶予を置き、uploadとGCの競合を防ぎます。更新時刻を検証できない未知objectは自動削除しません。safe modeとread-only recovery modeではGCを実行しません。

## Key Broker

外向きAPIとEnvelopeは全OS共通です。

```text
POST /v1/keys/wrap
POST /v1/keys/unwrap
POST /v1/sign
POST /v1/attest
GET  /v1/health
```

`/v1/health`は`tpm`、`pcr_sealing`、`attestation`、`hardware_kek`などを返します。

- **Linux / Tier 1:** Unix socket。`LinuxTpmRsaProvider`はTPM内の非export RSA鍵でRSA-OAEP-SHA256 wrap/unwrapを行い、起動時に期待した公開鍵とpersistent handleを照合します。現実装のwrap鍵はsign/attestを兼用しません。
- **Linux unseal互換:** TPM-sealed AES KEKをBroker memoryへ展開します。完全な非export方式ではないことをcapabilityで明示します。
- **Windows / Tier 2:** localhost TLS 1.3 + mTLS。`providers/windows-cng`の.NET helperがMicrosoft Platform Crypto Provider上の非export RSA鍵を使用します。PCR sealingと完全なattestationは未対応です。
- **HSM:** OS別helperを`HsmProvider`へ接続できます。
- **Software:** 開発・隔離復旧専用。明示的な危険フラグなしでは起動しません。

LinuxではDockerへ`/dev/tpmrm0`を渡しません。Host BrokerのsocketだけをGateway専用GIDでbind mountします。
wrap/unwrap/sign/attestには、既定で同時8処理・毎分600要求のBroker側制限と、鍵materialを含めないJSON監査logを適用します。

Windows Docker Desktopでは、BrokerをWindows hostの`127.0.0.1:9443`で起動し、サーバー証明書のSANに`host.docker.internal`を含めます。Gateway専用client証明書を用意して次のoverrideを使います。

```powershell
docker compose -f compose.yaml -f compose.windows.yaml up -d --build
```

Windows overrideはUnix socket mountを除去し、`https://host.docker.internal:9443`だけへmTLS接続します。到達できないDocker Desktop版ではGatewayもWindows nativeで起動してください。平文TCPへのfallbackはありません。

## 初期化

Linux reference platformでは対話setupを推奨します。Docker、OpenSSL、起動済みHost Key Brokerを用意し、Tailscale管理画面で`auth_keys` scopeと専用tagだけを許可したOAuth clientを作成してください。

```bash
sh setup.sh
```

setupは次を対話実行します。

- Apple ID/passwordとSMSまたはtrusted-device認証
- Tailscale OAuth client secret、tag、追加の`tailscale up`引数
- OAuth secretへの`?ephemeral=false`付与
- 個人名・地名を含まないrandom hostname
- PostgreSQL/WebDAV passwordのrandom生成
- mTLS server/client PKI生成
- ML-KEM Recovery Secretの一度だけの表示
- `.env`をmode 600で保存し、希望時だけstack起動

hostnameはtailnet管理者から見えます。Tailscaleの公開CA証明書を取得する完全なDNS名はcertificate-transparency logへ現れ得るため、氏名、住所、組織内機密名を使わないでください。TailscaleはTCP 443をraw転送し、Caddyが公開サーバー証明書とprivate client CAによるmTLSを終端します。

`scripts/setup-mtls.sh`だけを単独で使うこともできます。

```bash
sh scripts/setup-mtls.sh --hostname icloud-gw-a1b2c3d4 --output ./pki
```

`pki/runtime`だけがCaddyへmountされます。`pki/client`をWebDAVクライアントへ安全に移し、`pki/offline`のCA秘密鍵は追加発行後にサーバーから外してください。既存PKIは上書きしません。

手動構築する場合はPython 3.12以上を推奨します。

```bash
python -m pip install -e ".[test]"
```

Linux Host Key Brokerを先に起動します。TPM鍵の作成・PCR policyは組織のTPM手順に従い、期待公開鍵を別途固定してください。`tpm2-tools`のRSA-OAEP対応とpersistent handle検証を利用します。

```bash
icloud-keybroker \
  --provider linux-tpm \
  --tpm-context 0x81000001 \
  --tpm-public-key /etc/icloud-keybroker/primary-kek.pem \
  --socket /run/icloud-keybroker/keybroker.sock
```

Recovery public bundleを生成します。

```bash
icloud-webdav encryption-init \
  --config /data/icloud-webdav.toml \
  --recovery-public-file /data/.state/recovery-public.json
```

コマンドが表示する32-byte Recovery Secretは一度だけair-gapped環境へ移し、独立して監査された秘密分散製品・手順で3-of-5に分割してください。このプロジェクトは秘密分散を自作していません。Trezorの`python-shamir-mnemonic`自身もreference implementationでside-channel hardeningなしと警告しているため、本番秘密をGateway内で自動分割する依存には採用していません。

iCloud認証（SMSまたはtrusted device）を保存します。

```bash
icloud-webdav auth --config /data/icloud-webdav.toml --auth-method sms
```

`.env`にApple ID、WebDAV専用パスワード、PostgreSQLパスワード、Host Broker socket、Tailscale OAuth secret/tag/hostnameを設定し、mTLS PKIを作成してから起動します。

```bash
docker compose config
docker compose up -d --build
```

CaddyはTailscaleの公開HTTPS証明書を自動取得・更新します。MagicDNS名で接続するWebDAVクライアントへ設定する私設PKIは`pki/client/client.pem`と`client-key.pem`だけです。Basic認証はTailscale + mTLSの内側でのみ使います。

### Tailscale IPv4で直接接続する

公開CAはTailscaleの`100.64.0.0/10`アドレスに証明書を発行しないため、IPアクセスには既存のprivate Server CAでIP SAN付き証明書を追加発行します。MagicDNS経路は公開証明書のまま併存し、mTLS要件も変わりません。

追加発行時だけ`pki/offline/server-ca-key.pem`をオフライン保管先から戻して実行します。

```bash
sh scripts/enable-ip-access.sh --ip 100.111.60.44
```

`.env`の空の設定を次の値へ変更します。

```dotenv
TS_IP_ADDRESS=100.111.60.44
```

構文検証後、Caddyだけを再作成します。

```bash
docker compose config --quiet
docker compose up -d --force-recreate caddy
docker compose logs --tail=100 caddy
```

IP接続クライアントは、サーバー証明書検証用として`pki/client/server-ca.pem`も信頼する必要があります。AndroidではCA証明書としてインストールし、FolderSyncの「自己署名証明書を許可」は無効のままにします。発行後は`pki/offline`を直ちにオフライン保管へ戻してください。

接続先は`https://100.111.60.44/`です。MagicDNS接続では`server-ca.pem`を指定する必要はありません。

### 仮SFTP互換レイヤー

`sftp` Compose profileは、rcloneのSFTP VFSを内部WebDAVへ接続する暫定アダプターです。SFTPの操作は必ずGatewayを通るため、iCloudへ平文ファイルを直接保存せず、既存の暗号化CAS、PostgreSQL transaction、Valkey lock、version retentionを共有します。外部ポートはTailscale TCP `2222`だけで、SSH公開鍵認証のみを許可します。

Android用クライアント鍵を作成します。秘密鍵のpassphraseは空にしないでください。

```bash
mkdir -p .state/sftp-client
ssh-keygen -t ed25519 -a 100 \
  -C icloud-webdav-android \
  -f .state/sftp-client/android-sftp-key

sh scripts/setup-sftp.sh \
  --authorized-key .state/sftp-client/android-sftp-key.pub
```

既存環境では`tailscale-config/serve.json`を次の内容へ更新します。新規`setup.sh`はこの設定を自動生成します。

```json
{
  "TCP": {
    "443": {
      "TCPForward": "127.0.0.1:443"
    },
    "2222": {
      "TCPForward": "127.0.0.1:2022"
    }
  }
}
```

Tailscaleを再読込し、明示的にSFTP profileを起動します。

```bash
docker compose restart tailscale
docker compose --profile sftp up -d sftp
docker compose logs --tail=100 sftp
```

接続テスト:

```bash
sftp -P 2222 \
  -i .state/sftp-client/android-sftp-key \
  icloud@100.111.60.44
```

FolderSyncではSFTP、server `100.111.60.44`、port `2222`、user `icloud`、private key `android-sftp-key`、作成時のkey passphraseを設定し、初回に表示されるhost key fingerprintを`setup-sftp.sh`の出力と照合します。

この暫定版はrandom-write互換性のため、closeされるまでのアップロード平文を`/cache`のサイズ制限付きtmpfsへ保持します。既定上限は`SFTP_CACHE_SIZE=1G`です。最大同時アップロードより大きく設定し、ホストのswapは無効化または暗号化してください。chmod/chown、symlink、mtime保存は対象外です。恒久版ではGateway native SFTP実装へ置き換える予定です。

## WebDAV操作

- `PROPFIND`: 仮想directory・metadata・ETag
- `GET` / `HEAD`: 復号stream、単一Range対応
- `PUT`: checksum比較、差分chunk、version commit
- `DELETE`: tombstone化。safe mode中は拒否
- `MOVE`: PostgreSQL上のnamespace変更。暗号本体の再暗号化なし
- `MKCOL`: 仮想directory作成

`/Photos`は暗号化仮想directoryとして作成できますが、Appleの「iCloud写真」ライブラリAPIではありません。

## 災害復旧

詳細な手順は[docs/RECOVERY.md](docs/RECOVERY.md)を参照してください。`--recovery-mode`では`GET/HEAD/PROPFIND/OPTIONS`だけが許可され、PUT/DELETE/MOVE/MKCOL/GCは拒否されます。

TPM/HSM交換時はGatewayを停止し、まず旧Envelopeを残す検証段階を実行します。

```bash
icloud-webdav rewrap-keys --config /data/icloud-webdav.toml
# 新Brokerだけで復号試験・二名承認後
icloud-webdav rewrap-keys --config /data/icloud-webdav.toml --finalize
```

PostgreSQL backupはiCloud・Primary KEKとは別の鍵と障害ドメインへ毎日暗号化保存してください。3か月ごとに空DBへのrestoreとランダム100ファイルのchecksum検証まで実施します。
`scripts/backup-postgres.sh`と`scripts/restore-postgres.sh`は、専用age recipient/identityを使うLinux向け雛形です。復元先DBは必ず空にしてください。

## テスト

```bash
pytest
```

テストにはWebDAV実通信、checksum no-op、AES-GCM改ざん検知、Primary Broker喪失後のRecovery unwrapが含まれます。TPM/CNG/PostgreSQL/Valkeyの実機統合試験は対象ホスト上で別途必要です。

## セキュリティ資料

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [RFC 4918 WebDAV](https://www.rfc-editor.org/rfc/rfc4918)
- [Tailscale Docker configuration parameters](https://tailscale.com/docs/features/containers/docker/docker-params)
- [Tailscale OAuth clients](https://tailscale.com/docs/features/oauth-clients)
