const { Stack, RemovalPolicy, Duration, CfnOutput } = require('aws-cdk-lib');
const s3 = require('aws-cdk-lib/aws-s3');
const kms = require('aws-cdk-lib/aws-kms');

class S3DestinationStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const { environment, empCodigo } = props;
    const prefix = `${environment}-${empCodigo}`;

    const makeKey = (name) => new kms.Key(this, `KmsKey-${name}`, {
      alias: `alias/${prefix}-${name}-replica-key`,
      description: `KMS key for ${name} replica bucket in us-west-2`,
      enableKeyRotation: true,
      rotationPeriod: Duration.days(90),
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const assetsKey  = makeKey('assets');
    const staticKey  = makeKey('static-web');
    const docsKey    = makeKey('documents');

    const makeBucket = (name, key) => new s3.Bucket(this, `Dest-${name}`, {
      bucketName: `${prefix}-${name}-replica`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: key,
      versioned: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.publicBucket  = makeBucket('assets', assetsKey);
    this.staticBucket  = makeBucket('static-web', staticKey);
    this.privateBucket = makeBucket('documents', docsKey);

    // Exporta los ARNs de las llaves — necesarios para el replication role en us-east-1
    new CfnOutput(this, 'AssetsKeyArn',  { value: assetsKey.keyArn,  exportName: `${prefix}-assets-replica-key-arn` });
    new CfnOutput(this, 'StaticKeyArn',  { value: staticKey.keyArn,  exportName: `${prefix}-static-replica-key-arn` });
    new CfnOutput(this, 'DocsKeyArn',    { value: docsKey.keyArn,    exportName: `${prefix}-documents-replica-key-arn` });

    new CfnOutput(this, 'PublicReplicaArn',  { value: this.publicBucket.bucketArn,  exportName: `${prefix}-assets-replica-arn` });
    new CfnOutput(this, 'StaticReplicaArn',  { value: this.staticBucket.bucketArn,  exportName: `${prefix}-static-replica-arn` });
    new CfnOutput(this, 'PrivateReplicaArn', { value: this.privateBucket.bucketArn, exportName: `${prefix}-documents-replica-arn` });
  }
}

module.exports = { S3DestinationStack };
