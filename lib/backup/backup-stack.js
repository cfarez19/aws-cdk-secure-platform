const { Stack, Duration, RemovalPolicy } = require('aws-cdk-lib');
const backup = require('aws-cdk-lib/aws-backup');
const events = require('aws-cdk-lib/aws-events');
const kms = require('aws-cdk-lib/aws-kms');

class BackupStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const { environment, empCodigo, dbCluster } = props;
    const prefix = `${environment}-${empCodigo}`;

    // Importa el vault de Oregon como IBackupVault — requerido por copyActions
    const oregonVault = backup.BackupVault.fromBackupVaultArn(
      this, 'OregonVault',
      `arn:aws:backup:us-west-2:${this.account}:backup-vault:${prefix}-backup-vault-oregon`
    );

    const vaultKey = new kms.Key(this, 'BackupVaultKey', {
      alias: `alias/${prefix}-backup-vault-key`,
      description: `KMS key for AWS Backup vault in ${environment}`,
      enableKeyRotation: true,
      rotationPeriod: Duration.days(90),
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const vault = new backup.BackupVault(this, 'BackupVault', {
      backupVaultName: `${prefix}-backup-vault`,
      encryptionKey: vaultKey,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const plan = new backup.BackupPlan(this, 'BackupPlan', {
      backupPlanName: `${prefix}-backup-plan`,
      backupVault: vault,
      backupPlanRules: [
        // Diario — 11:30 PM Guayaquil (04:30 UTC), retención 4 semanas
        new backup.BackupPlanRule({
          ruleName: 'DailyBackups',
          backupVault: vault,
          scheduleExpression: events.Schedule.cron({ minute: '30', hour: '4' }),
          deleteAfter: Duration.days(28),
          startWindow: Duration.hours(1),
          completionWindow: Duration.hours(3),
          copyActions: [{
            destinationBackupVault: oregonVault,
            deleteAfter: Duration.days(28),
          }],
        }),

        // Semanal sábado — 11:30 PM Guayaquil = domingo 04:30 UTC, retención 8 semanas
        new backup.BackupPlanRule({
          ruleName: 'WeeklyBackups',
          backupVault: vault,
          scheduleExpression: events.Schedule.cron({ minute: '30', hour: '4', weekDay: 'SUN' }),
          deleteAfter: Duration.days(56),
          startWindow: Duration.hours(1),
          completionWindow: Duration.hours(3),
          copyActions: [{
            destinationBackupVault: oregonVault,
            deleteAfter: Duration.days(56),
          }],
        }),

        // Mensual día 1 — 11:30 PM Guayaquil = día 2 04:30 UTC, retención 5 años
        new backup.BackupPlanRule({
          ruleName: 'MonthlyBackups',
          backupVault: vault,
          scheduleExpression: events.Schedule.cron({ minute: '30', hour: '4', day: '2', month: '*' }),
          deleteAfter: Duration.days(1825),
          startWindow: Duration.hours(1),
          completionWindow: Duration.hours(3),
          copyActions: [{
            destinationBackupVault: oregonVault,
            deleteAfter: Duration.days(1825),
          }],
        }),
      ],
    });

    // Selecciona el cluster DocumentDB como recurso a respaldar
    // aws-docdb DatabaseCluster no expone clusterArn; se construye manualmente
    const clusterArn = `arn:aws:rds:${this.region}:${this.account}:cluster:${dbCluster.clusterIdentifier}`;
    plan.addSelection('DocDbSelection', {
      selectionName: `${prefix}-docdb-selection`,
      resources: [
        backup.BackupResource.fromArn(clusterArn),
      ],
    });
  }
}

module.exports = { BackupStack };
