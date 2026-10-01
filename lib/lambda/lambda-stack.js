const { Stack, Duration, CfnOutput } = require('aws-cdk-lib');
const lambda = require('aws-cdk-lib/aws-lambda');
const secretsmanager = require('aws-cdk-lib/aws-secretsmanager');
const events = require('aws-cdk-lib/aws-events');
const targets = require('aws-cdk-lib/aws-events-targets');
const ec2 = require('aws-cdk-lib/aws-ec2');
const iam = require('aws-cdk-lib/aws-iam');

class LambdaStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const { environment, empCodigo, vpcEnvironments, dbCluster, dbLambdaSecret, dbKmsKey } = props;
    const prefix = `${environment}-${empCodigo}`;

    // ── Security Group para funciones Lambda ──────────────────────────
    this.lambdaSG = new ec2.SecurityGroup(this, 'LambdaSG', {
      vpc: vpcEnvironments,
      description: 'Security group for Lambda functions - DocumentDB access',
      allowAllOutbound: true,
    });

    // ── Secrets Manager — credenciales del proveedor de firma electrónica ───────────────────────
    // Importado por nombre — CDK nunca crea ni sobreescribe el valor.
    // Llenar/editar manualmente en AWS Console: username, password, endpoint, providerBaseUrl
    const esignSecret = secretsmanager.Secret.fromSecretNameV2(
      this, 'EsignProviderSecret', `${prefix}-esign-provider-credentials`
    );

    // ── Lambda signature-api ─────────────────────────────────────────────
    this.signatureApi = new lambda.Function(this, 'SignatureApi', {
      functionName: `${prefix}-signature-api`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => ({ statusCode: 200 });'),
      memorySize: 512,
      timeout: Duration.seconds(60),
      vpc: vpcEnvironments,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [this.lambdaSG],
      environment: {
        SECRET_ARN:              esignSecret.secretArn,
        DOCDB_SECRET_ARN:        dbLambdaSecret.secretArn,
        DOCDB_ENDPOINT:          dbCluster.clusterEndpoint.hostname,
        DOCDB_PORT:              dbCluster.clusterEndpoint.port.toString(),
        MONGODB_DB_NAME:         '',
        ESIGN_BYPASS_ENABLED:    'false',
        ESIGN_BYPASS_URL:        '',
      },
    });

    esignSecret.grantRead(this.signatureApi);
    this.signatureApi.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
      resources: [dbLambdaSecret.secretArn],
    }));
    this.signatureApi.addToRolePolicy(new iam.PolicyStatement({
      actions: ['kms:Decrypt'],
      resources: [dbKmsKey.keyArn],
    }));

    // ── Lambda signature-cleanup ─────────────────────────────────────────
    this.signatureCleanup = new lambda.Function(this, 'SignatureCleanup', {
      functionName: `${prefix}-signature-cleanup`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline('exports.handler = async () => ({ statusCode: 200 });'),
      memorySize: 256,
      timeout: Duration.seconds(120),
      vpc: vpcEnvironments,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [this.lambdaSG],
      environment: {
        SECRET_ARN:              esignSecret.secretArn,
        DOCDB_SECRET_ARN:        dbLambdaSecret.secretArn,
        DOCDB_ENDPOINT:          dbCluster.clusterEndpoint.hostname,
        DOCDB_PORT:              dbCluster.clusterEndpoint.port.toString(),
        MONGODB_DB_NAME:         '',
        ESIGN_BYPASS_ENABLED:    'false',
        ESIGN_BYPASS_URL:        '',
      },
    });

    esignSecret.grantRead(this.signatureCleanup);
    this.signatureCleanup.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
      resources: [dbLambdaSecret.secretArn],
    }));
    this.signatureCleanup.addToRolePolicy(new iam.PolicyStatement({
      actions: ['kms:Decrypt'],
      resources: [dbKmsKey.keyArn],
    }));

    // ── EventBridge — cron cada 15 días ───────────────────────────────
    const cleanupRule = new events.Rule(this, 'SignatureCleanupSchedule', {
      ruleName: `${prefix}-signature-cleanup-schedule`,
      description: 'Ejecuta signature-cleanup cada 15 días',
      schedule: events.Schedule.rate(Duration.days(15)),
    });

    cleanupRule.addTarget(new targets.LambdaFunction(this.signatureCleanup));

    // ── Outputs ───────────────────────────────────────────────────────
    new CfnOutput(this, 'SignatureApiArn', {
      exportName: `${prefix}-signature-api-arn`,
      value: this.signatureApi.functionArn,
    });

    new CfnOutput(this, 'SignatureCleanupArn', {
      exportName: `${prefix}-signature-cleanup-arn`,
      value: this.signatureCleanup.functionArn,
    });

    new CfnOutput(this, 'EsignSecretArn', {
      exportName: `${prefix}-esign-secret-arn`,
      value: esignSecret.secretArn,
    });
  }
}

module.exports = { LambdaStack };
