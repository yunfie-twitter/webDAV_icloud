# Disaster Recovery Runbook

## Preconditions

- Recovery Secret shares、PostgreSQL encrypted backup、iCloud credentials、mTLS PKIを同じ障害ドメインへ置かない。
- Backup encryption keyはPrimary KEK・Recovery Secretと独立させる。
- 復旧作業は隔離networkと監査記録の下で二名以上が実施する。

## Total server / TPM loss

1. 新しい隔離サーバーへGateway、PostgreSQL、Valkeyを構築する。
2. PostgreSQL backupを空DBへrestoreする。iCloudへの書込権限はまだ有効にしない。
3. 3-of-5のRecovery Secretをair-gapped手順で復元する。
4. `icloud-webdav serve --recovery-mode`を対話起動する。
5. `OPTIONS/PROPFIND/GET/HEAD`だけが許可されることを確認する。
6. manifest chain、chunk authentication、SHA-256/SHA-512を検証する。
7. 少なくともランダム100ファイルを最後までGETし、PostgreSQL checksumと照合する。
8. 新しいTPM/HSM KEKを生成し、公開ID・capabilities・attestationを記録する。
9. Gatewayを停止したまま、`icloud-webdav rewrap-keys`で全DEKに新primary envelopeを追加し、直後にunwrap検証する。暗号化chunk本体は変更しない。
10. 新Brokerだけで同じ復号テストを繰り返す。この段階では旧primary envelopeも残る。
11. 承認後に`icloud-webdav rewrap-keys --finalize`を実行し、全capsuleが検証済みであることを確認して旧primary envelopeを除去する。
12. 書込みを解禁する。
13. Recovery Secretを再封印し、使用記録と関係者を監査logへ残す。

> 再wrapは途中再開可能で、追加した新Envelopeを実際にunwrapできたcapsuleだけを`VERIFIED`にします。`--finalize`は全live capsuleの検証が揃うまで失敗します。サービスを停止し、二名承認の下で二段階実行してください。手作業でcapsuleを書き換えないでください。

## Quarterly restore drill

1. 本番から隔離した空のPostgreSQLを作る。
2. encrypted backupをrestoreする。
3. Recovery Secretを承認済み手順で一時復元する。
4. read-only recovery modeでランダム100ファイルを復号する。
5. 全checksumを照合する。
6. Recovery Secret materialを破棄し、process/container/temporary mediaを廃棄またはzeroizeする。
7. 成否、所要時間、欠けていた手順、次回是正項目を記録する。
