const { Stack, Duration, RemovalPolicy } = require('aws-cdk-lib');
const cloudtrail = require('aws-cdk-lib/aws-cloudtrail');
const s3 = require('aws-cdk-lib/aws-s3');
const kms = require('aws-cdk-lib/aws-kms');
const logs = require('aws-cdk-lib/aws-logs');

class CloudTrailStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const { environment, empCodigo, s3Buckets = [], lambdaFunctions = [] } = props;
    const prefix = `${environment}-${empCodigo}`;

    const kmsKey = new kms.Key(this, 'TrailKey', {
      alias: `alias/${prefix}-cloudtrail-key`,
      enableKeyRotation: true,
      rotationPeriod: Duration.days(90),
      description: `KMS key for CloudTrail logs in ${environment}`,
    });

    // Bucket para almacenar los trail logs — retención 2 años con Glacier después de 90 días
    const logsBucket = new s3.Bucket(this, 'TrailBucket', {
      bucketName: `${prefix}-cloudtrail-logs`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: kmsKey,
      versioned: false,
      removalPolicy: RemovalPolicy.RETAIN,
      lifecycleRules: [
        {
          transitions: [{
            storageClass: s3.StorageClass.GLACIER,
            transitionAfter: Duration.days(90),
          }],
          expiration: Duration.days(730),
        },
      ],
    });

    // Log group para búsquedas en CloudWatch Insights
    const logGroup = new logs.LogGroup(this, 'TrailLogGroup', {
      logGroupName: `/cloudtrail/${prefix}`,
      retention: logs.RetentionDays.TWO_YEARS,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const trail = new cloudtrail.Trail(this, 'Trail', {
      trailName: `${prefix}-trail`,
      bucket: logsBucket,
      encryptionKey: kmsKey,
      sendToCloudWatchLogs: true,
      cloudWatchLogGroup: logGroup,
      managementEvents: cloudtrail.ReadWriteType.ALL,
      includeGlobalServiceEvents: true,
      isMultiRegionTrail: false,
    });

    // Eventos de datos S3 — lectura y escritura en los buckets del proyecto
    if (s3Buckets.length > 0) {
      trail.addS3EventSelector(
        s3Buckets.map(bucket => ({ bucket })),
        { readWriteType: cloudtrail.ReadWriteType.ALL, includeManagementEvents: false }
      );
    }

    // Eventos de invocación Lambda
    if (lambdaFunctions.length > 0) {
      trail.addLambdaEventSelector(lambdaFunctions);
    }
  }
}

module.exports = { CloudTrailStack };
