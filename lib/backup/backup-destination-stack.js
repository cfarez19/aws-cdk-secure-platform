const { Stack, Duration, RemovalPolicy } = require('aws-cdk-lib');
const backup = require('aws-cdk-lib/aws-backup');
const kms = require('aws-cdk-lib/aws-kms');

class BackupDestinationStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const { environment, empCodigo } = props;
    const prefix = `${environment}-${empCodigo}`;

    const vaultKey = new kms.Key(this, 'BackupVaultKeyOregon', {
      alias: `alias/${prefix}-backup-vault-oregon-key`,
      description: `KMS key for AWS Backup vault in us-west-2 (Oregon)`,
      enableKeyRotation: true,
      rotationPeriod: Duration.days(90),
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.vault = new backup.BackupVault(this, 'BackupVaultOregon', {
      backupVaultName: `${prefix}-backup-vault-oregon`,
      encryptionKey: vaultKey,
      removalPolicy: RemovalPolicy.RETAIN,
    });
  }
}

module.exports = { BackupDestinationStack };
