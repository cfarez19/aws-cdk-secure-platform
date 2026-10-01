const { Stack, RemovalPolicy, CfnOutput, Duration } = require('aws-cdk-lib');
const s3 = require('aws-cdk-lib/aws-s3');
const kms = require('aws-cdk-lib/aws-kms');
const iam = require('aws-cdk-lib/aws-iam');
const acm = require('aws-cdk-lib/aws-certificatemanager');
const cloudfront = require('aws-cdk-lib/aws-cloudfront');
const origins = require('aws-cdk-lib/aws-cloudfront-origins');


class S3Buckets extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const {
      environment,
      empCodigo,
      publicBucketName,
      staticBucketName,
      privateBucketName,
      domain,
      certificateArn,
      staticSubdomain,
      webAclId,
    } = props;

    const certificate = acm.Certificate.fromCertificateArn(this, 'Certificate', certificateArn);

    const prefix = `${environment}-${empCodigo}`;

    // ── IAM Role — Roles Anywhere + ECS Task Role ─────────────
    const principals = [
      new iam.ServicePrincipal('rolesanywhere.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:PrincipalTag/x509Subject/OU': 'Innovation' },
        },
      }),
    ];

    const ecsRoles = props.ecsTaskRoles ?? [];
    for (const role of ecsRoles) {
      principals.push(new iam.ArnPrincipal(role.roleArn));
    }

    const s3AccessRole = new iam.Role(this, 'S3AccessRole', {
      roleName: `RoleS3Access-${environment}`,
      assumedBy: new iam.CompositePrincipal(...principals),
      description: `S3 access role for ${prefix} - Roles Anywhere + ECS`,
    });

    // Acciones que puede hacer sobre todos los buckets del ambiente
    s3AccessRole.addToPolicy(new iam.PolicyStatement({
      actions: ['sts:TagSession', 'sts:SetSourceIdentity'],
      resources: ['*'],
    }));

    // ── KMS Keys (solo para buckets privados) ─────────────────
    const staticKey = new kms.Key(this, 'KmsKeyStatic', {
      alias: `alias/${prefix}-static-bucket-key`,
      description: `KMS key for static bucket in ${environment}`,
      enableKeyRotation: true,
      rotationPeriod: Duration.days(90),
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const privateKey = new kms.Key(this, 'KmsKeyPrivate', {
      alias: `alias/${prefix}-private-bucket-key`,
      description: `KMS key for private bucket in ${environment}`,
      enableKeyRotation: true,
      rotationPeriod: Duration.days(90),
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Permitir que el rol de acceso use las llaves KMS
    staticKey.grantEncryptDecrypt(s3AccessRole);
    privateKey.grantEncryptDecrypt(s3AccessRole);

    // ── Bucket Público — assets, imágenes ─────────────────────
    // Usa SSE-S3 (no KMS) porque los objetos deben ser accesibles
    // de forma anónima por URL — KMS requiere credenciales AWS para
    // descifrar y no funciona con acceso público anónimo.
    this.publicBucket = new s3.Bucket(this, 'PublicBucket', {
      bucketName: publicBucketName,
      blockPublicAccess: new s3.BlockPublicAccess({
        blockPublicAcls: false,
        ignorePublicAcls: false,
        blockPublicPolicy: false,
        restrictPublicBuckets: false,
      }),
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: true,
      removalPolicy: RemovalPolicy.RETAIN,
      cors: [
        {
          allowedOrigins: ['*'],
          allowedMethods: [s3.HttpMethods.GET, s3.HttpMethods.HEAD],
          allowedHeaders: ['*'],
          maxAge: 3000,
        },
      ],
    });

    // Bucket policy — lectura pública anónima + acceso completo al rol
    this.publicBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'PublicReadGetObject',
      effect: iam.Effect.ALLOW,
      principals: [new iam.AnyPrincipal()],
      actions: ['s3:GetObject'],
      resources: [this.publicBucket.arnForObjects('*')],
    }));

    this.publicBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'RoleListBucket',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal(s3AccessRole.roleArn)],
      actions: ['s3:ListBucket'],
      resources: [this.publicBucket.bucketArn],
    }));

    this.publicBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'RoleObjectAccess',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal(s3AccessRole.roleArn)],
      actions: ['s3:GetObject', 's3:PutObject', 's3:RestoreObject', 's3:ReplicateObject'],
      resources: [this.publicBucket.arnForObjects('*')],
    }));

    // ── Bucket Estático — privado + CloudFront ─────────────────
    this.staticBucket = new s3.Bucket(this, 'StaticBucket', {
      bucketName: staticBucketName,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: staticKey,
      versioned: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.staticBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'RoleListBucket',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal(s3AccessRole.roleArn)],
      actions: ['s3:ListBucket'],
      resources: [this.staticBucket.bucketArn],
    }));

    this.staticBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'RoleObjectAccess',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal(s3AccessRole.roleArn)],
      actions: ['s3:GetObject', 's3:PutObject', 's3:RestoreObject', 's3:ReplicateObject'],
      resources: [this.staticBucket.arnForObjects('*')],
    }));

    // CloudFront con OAC → bucket estático privado
    const oac = new cloudfront.S3OriginAccessControl(this, 'StaticOAC', {
      originAccessControlName: `${prefix}-static-oac`,
      signing: cloudfront.Signing.SIGV4_ALWAYS,
    });

    const staticFqdn = `${staticSubdomain}.${domain}`;

    this.staticDistribution = new cloudfront.Distribution(this, 'StaticDistribution', {
      comment: `${prefix} static environment`,
      domainNames: [staticFqdn],
      certificate,
      ...(webAclId ? { webAclId } : {}),
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(this.staticBucket, {
          originAccessControl: oac,
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
      },
      defaultRootObject: 'index.html',
      errorResponses: [
        { httpStatus: 403, responseHttpStatus: 200, responsePagePath: '/index.html' },
        { httpStatus: 404, responseHttpStatus: 200, responsePagePath: '/index.html' },
      ],
    });

    // Permitir que CloudFront lea el bucket estático (OAC requiere esta policy)
    this.staticBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'CloudFrontOACAccess',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('cloudfront.amazonaws.com')],
      actions: ['s3:GetObject'],
      resources: [this.staticBucket.arnForObjects('*')],
      conditions: {
        StringEquals: {
          'AWS:SourceArn': `arn:aws:cloudfront::${this.account}:distribution/${this.staticDistribution.distributionId}`,
        },
      },
    }));

    // ── Bucket Privado — datos de clientes ────────────────────
    this.privateBucket = new s3.Bucket(this, 'PrivateBucket', {
      bucketName: privateBucketName,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: privateKey,
      versioned: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.privateBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'RoleListBucket',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal(s3AccessRole.roleArn)],
      actions: ['s3:ListBucket'],
      resources: [this.privateBucket.bucketArn],
    }));

    this.privateBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'RoleObjectAccess',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal(s3AccessRole.roleArn)],
      actions: ['s3:GetObject', 's3:PutObject', 's3:RestoreObject', 's3:ReplicateObject'],
      resources: [this.privateBucket.arnForObjects('*')],
    }));

    // ── Outputs ───────────────────────────────────────────────
    new CfnOutput(this, 'PublicBucketName', {
      exportName: `${prefix}-public-bucket`,
      value: this.publicBucket.bucketName,
    });

    new CfnOutput(this, 'StaticBucketName', {
      exportName: `${prefix}-static-bucket`,
      value: this.staticBucket.bucketName,
    });

    new CfnOutput(this, 'PrivateBucketName', {
      exportName: `${prefix}-private-bucket`,
      value: this.privateBucket.bucketName,
    });

    new CfnOutput(this, 'StaticCloudfrontDomain', {
      exportName: `${prefix}-static-cf-domain`,
      value: staticFqdn,
    });

    new CfnOutput(this, 'S3AccessRoleArn', {
      exportName: `${prefix}-s3-access-role-arn`,
      value: s3AccessRole.roleArn,
    });

    // ── Replicación Cross-Region → Oregon (Glacier + KMS) ────────
    if (props.replicationBuckets) {
      const {
        publicBucketArn, staticBucketArn, privateBucketArn,
        publicDestKmsKeyArn, staticDestKmsKeyArn, privateDestKmsKeyArn,
      } = props.replicationBuckets;

      const replicationRole = new iam.Role(this, 'ReplicationRole', {
        roleName: `${prefix}-s3-replication-role`,
        assumedBy: new iam.ServicePrincipal('s3.amazonaws.com'),
      });

      replicationRole.addToPolicy(new iam.PolicyStatement({
        actions: ['s3:GetReplicationConfiguration', 's3:ListBucket'],
        resources: [
          this.publicBucket.bucketArn,
          this.staticBucket.bucketArn,
          this.privateBucket.bucketArn,
        ],
      }));

      replicationRole.addToPolicy(new iam.PolicyStatement({
        actions: [
          's3:GetObjectVersionForReplication',
          's3:GetObjectVersionAcl',
          's3:GetObjectVersionTagging',
        ],
        resources: [
          this.publicBucket.arnForObjects('*'),
          this.staticBucket.arnForObjects('*'),
          this.privateBucket.arnForObjects('*'),
        ],
      }));

      replicationRole.addToPolicy(new iam.PolicyStatement({
        actions: ['s3:ReplicateObject', 's3:ReplicateDelete', 's3:ReplicateTags'],
        resources: [`${publicBucketArn}/*`, `${staticBucketArn}/*`, `${privateBucketArn}/*`],
      }));

      // Decrypt en llaves KMS de origen (static y private)
      replicationRole.addToPolicy(new iam.PolicyStatement({
        actions: ['kms:Decrypt'],
        resources: [staticKey.keyArn, privateKey.keyArn],
      }));

      // Encrypt en llaves KMS de destino (Oregon) — requerido para cifrar las réplicas
      replicationRole.addToPolicy(new iam.PolicyStatement({
        actions: ['kms:Encrypt', 'kms:GenerateDataKey'],
        resources: [publicDestKmsKeyArn, staticDestKmsKeyArn, privateDestKmsKeyArn],
      }));

      // public: origen SSE-S3 → destino KMS
      // Disabled = replica todos los objetos (no solo KMS); S3 exige el campo si hay encryptionConfiguration
      this.publicBucket.node.defaultChild.replicationConfiguration = {
        role: replicationRole.roleArn,
        rules: [{
          id: 'ReplicateToOregonGlacier',
          status: 'Enabled',
          sourceSelectionCriteria: {
            sseKmsEncryptedObjects: { status: 'Disabled' },
          },
          destination: {
            bucket: publicBucketArn,
            storageClass: 'GLACIER',
            encryptionConfiguration: { replicaKmsKeyId: publicDestKmsKeyArn },
          },
        }],
      };

      // static y private: origen KMS → destino KMS (requiere sourceSelectionCriteria)
      for (const [sourceBucket, destArn, destKeyArn] of [
        [this.staticBucket,  staticBucketArn,  staticDestKmsKeyArn],
        [this.privateBucket, privateBucketArn, privateDestKmsKeyArn],
      ]) {
        sourceBucket.node.defaultChild.replicationConfiguration = {
          role: replicationRole.roleArn,
          rules: [{
            id: 'ReplicateToOregonGlacier',
            status: 'Enabled',
            sourceSelectionCriteria: {
              sseKmsEncryptedObjects: { status: 'Enabled' },
            },
            destination: {
              bucket: destArn,
              storageClass: 'GLACIER',
              encryptionConfiguration: { replicaKmsKeyId: destKeyArn },
            },
          }],
        };
      }
    }
  }
}

module.exports = { S3Buckets };
