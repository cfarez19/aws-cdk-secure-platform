/**
 * Wires every stack together. Kept separate from bin/ so tests can build
 * the same platform the CLI deploys.
 */
const { vpcEnvironments } = require('./vpc/vpc-stack');
const { vpcDataBase } = require('./vpc/vpc-database-stack');
const { vpcPeering } = require('./vpc/peering_connection_stack');
const { databaseDocumentDB } = require('./database/database-documentdb-stack');
const { CertificateManager } = require('./certificateManager/certificate-manager-stack');
const { EcsFargateStack } = require('./environments/ecs-fargate-stack');
const { WafStack } = require('./waf/waf-stack');
const { S3DestinationStack } = require('./buckets/s3-destination-stack');
const { S3Buckets } = require('./buckets/s3-buckets-stack');
const { ApiGatewayStack } = require('./api-gateway/api-gateway-stack');
const { LambdaStack } = require('./lambda/lambda-stack');
const { CloudTrailStack } = require('./cloudtrail/cloudtrail-stack');
const { BackupDestinationStack } = require('./backup/backup-destination-stack');
const { BackupStack } = require('./backup/backup-stack');

function buildPlatform(app, c, { account, apiHeaderSecret }) {
  const env = { account, region: c.region };
  const drEnv = { account, region: c.drRegion || 'us-west-2' };
  const prefix = `${c.environment}-${c.clientCode}`;
  const base = { empCodigo: c.clientCode, environment: c.environment };
  const stacks = {};

  // ── Certificate & DNS ────────────────────────────────────────
  stacks.certificate = new CertificateManager(app, `${prefix}-certificate`, { env, domain: c.domain });

  // ── Networking: app VPC + isolated DB VPC + peering ──────────
  stacks.vpcEnv = new vpcEnvironments(app, `${prefix}-vpcEnv`, { ...base, cidrVPCEnvironments: c.cidrEnvironments, env });
  stacks.vpcDb = new vpcDataBase(app, `${prefix}-vpcDb`, { ...base, cidrVPCDataBase: c.cidrDatabase, env });
  stacks.peering = new vpcPeering(app, `${prefix}-peering`, {
    ...base, vpcEnvironments: stacks.vpcEnv.VpcEnvironments, vpcDatabase: stacks.vpcDb.vpcDataBase, env,
  });

  // ── Data: DocumentDB with KMS + rotated secrets ──────────────
  const db = c.database || {};
  stacks.database = new databaseDocumentDB(app, `${prefix}-docdbDatabase`, {
    ...base,
    envDescription: c.description || c.environment,
    vpcDatabase: stacks.vpcDb.vpcDataBase,
    vpcEnvironments: stacks.vpcEnv.VpcEnvironments,
    parameterGroupFamily: db.parameterGroupFamily || 'docdb5.0',
    parameterFamily: db.parameterFamily || 'docdb50',
    cidrVPCEnvironments: c.cidrEnvironments,
    cidrVPCDataBase: c.cidrDatabase,
    dbUsername: db.username || `${c.clientCode}Admin`,
    dbInstances: db.instances || 1,
    engineDb: db.engineVersion || '5.0.0',
    env,
  });

  // ── Compute: ECS Fargate behind public + internal ALBs ───────
  stacks.ecs = new EcsFargateStack(app, `${prefix}-EcsStack`, {
    ...base,
    env,
    envDescription: c.description || c.environment,
    vpcEnvironments: stacks.vpcEnv.VpcEnvironments,
    certificateArn: c.certificateArn,
    domain: c.domain,
    dbCluster: stacks.database.databaseDocumentDB,
    ecsUserSecret: stacks.database.ecsUserSecret,
    dbKmsKey: stacks.database.kmsKey,
    services: c.services,
  });

  // ── Edge security: WAF for CloudFront, public ALB and internal ALB
  stacks.waf = new WafStack(app, `${prefix}-WafStack`, {
    ...base,
    env,
    domain: c.domain,
    allowedHosts: c.allowedHosts || [`.${c.domain}`],
    allowedIps: c.allowedIps || [],
    publicAlbArn: stacks.ecs.publicAlb.loadBalancerArn,
    internalAlbArn: stacks.ecs.internalAlb.loadBalancerArn,
  });

  // ── Storage: buckets + cross-region replication to Glacier ───
  stacks.s3Destination = new S3DestinationStack(app, `${prefix}-S3DestinationStack`, { ...base, env: drEnv });
  const r = c.replication;
  stacks.s3 = new S3Buckets(app, `${prefix}-S3Buckets`, {
    ...base,
    env,
    publicBucketName: `${prefix}-assets`,
    staticBucketName: `${prefix}-static-web`,
    privateBucketName: `${prefix}-documents`,
    ecsTaskRoles: Object.values(stacks.ecs.taskRoles),
    domain: c.domain,
    certificateArn: c.certificateArn,
    staticSubdomain: c.staticSubdomain || 'www',
    webAclId: stacks.waf.cloudFrontWafArn,
    // Replication needs the destination KMS key ARNs (outputs of S3DestinationStack).
    // Leave "replication" out of the config on the first deploy.
    replicationBuckets: r ? {
      publicBucketArn: `arn:aws:s3:::${prefix}-assets-replica`,
      staticBucketArn: `arn:aws:s3:::${prefix}-static-web-replica`,
      privateBucketArn: `arn:aws:s3:::${prefix}-documents-replica`,
      publicDestKmsKeyArn: r.publicDestKmsKeyArn,
      staticDestKmsKeyArn: r.staticDestKmsKeyArn,
      privateDestKmsKeyArn: r.privateDestKmsKeyArn,
    } : undefined,
  });

  // ── API: CloudFront → HTTP API (Lambda authorizer) → VPC Link → internal ALB
  stacks.api = new ApiGatewayStack(app, `${prefix}-ApiGatewayStack`, {
    ...base,
    env,
    vpcEnvironments: stacks.vpcEnv.VpcEnvironments,
    internalListener: stacks.ecs.internalListener,
    hostedZone: stacks.certificate.hostedZone,
    certificateArn: c.certificateArn,
    apiSubdomain: c.apiSubdomain || 'api',
    middlewareSubdomain: c.middlewareSubdomain,
    webAclId: stacks.waf.middlewareCloudFrontWafArn,
    domain: c.domain,
    headerSecret: apiHeaderSecret,
  });

  // ── Serverless jobs ──────────────────────────────────────────
  stacks.lambda = new LambdaStack(app, `${prefix}-LambdaStack`, {
    ...base,
    env,
    vpcEnvironments: stacks.vpcEnv.VpcEnvironments,
    dbCluster: stacks.database.databaseDocumentDB,
    dbLambdaSecret: stacks.database.lambdaUserSecret,
    dbKmsKey: stacks.database.kmsKey,
  });

  // ── Audit: CloudTrail with S3 + Lambda data events ───────────
  stacks.cloudtrail = new CloudTrailStack(app, `${prefix}-CloudTrailStack`, {
    ...base,
    env,
    s3Buckets: [stacks.s3.publicBucket, stacks.s3.staticBucket, stacks.s3.privateBucket],
    lambdaFunctions: [stacks.lambda.signatureApi, stacks.lambda.signatureCleanup],
  });

  // ── Backup: daily / weekly / monthly + copy to DR region ─────
  stacks.backupDestination = new BackupDestinationStack(app, `${prefix}-BackupDestinationStack`, { ...base, env: drEnv });
  stacks.backup = new BackupStack(app, `${prefix}-BackupStack`, { ...base, env, dbCluster: stacks.database.databaseDocumentDB });
  stacks.backup.addStackDependency(stacks.backupDestination);

  return stacks;
}

module.exports = { buildPlatform };
