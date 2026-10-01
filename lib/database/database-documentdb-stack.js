const { Stack, Duration, RemovalPolicy } = require('aws-cdk-lib');
const documentDB = require('aws-cdk-lib/aws-docdb');
const ec2 = require('aws-cdk-lib/aws-ec2');
const kms = require('aws-cdk-lib/aws-kms');
const iam = require('aws-cdk-lib/aws-iam');
const secretsmanager = require('aws-cdk-lib/aws-secretsmanager');
const logs = require('aws-cdk-lib/aws-logs',)

class databaseDocumentDB extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const prefix = `${props.environment}-${props.empCodigo}`;
    const enviromentDesc = `${props.envDescription}`;
    const vpcDatabase = props.vpcDatabase;
    const vpcEnvironments = props.vpcEnvironments;

    // Security group para las rotation Lambdas (en vpcEnvironments con acceso a NAT)
    this.rotationSG = new ec2.SecurityGroup(this, 'RotationLambdaSG', {
        vpc: vpcEnvironments,
        description: 'Security group for Secrets Manager rotation Lambda functions',
        allowAllOutbound: true,
    });

    /*Create parameter group*/
    this.parameterGroup = new documentDB.ClusterParameterGroup(this, 'parameterGroup', {
        family: props.parameterGroupFamily,
        dbClusterParameterGroupName: `${prefix}-parameterGroup-${props.parameterFamily}`,
        description: `This is a ParameterGroup in the ${enviromentDesc} environment.`,
        parameters: {
            audit_logs: 'all',
            profiler: 'enabled'
        }
    });

    /** Create subnetgroup */

    this.subnetGroup = new documentDB.CfnDBSubnetGroup(this, 'subentgroupDB', {
        dbSubnetGroupDescription: `This is a Subnet Group for DocumentDB in the ${enviromentDesc} environment`,
        dbSubnetGroupName: `${prefix}-subnetgroup`,
        subnetIds: vpcDatabase.isolatedSubnets.map(subnet => subnet.subnetId)
    });

    /**Create a security group */
    this.securityGroup = new ec2.SecurityGroup(this, 'DataBaseSG',{
        vpc: vpcDatabase,
        description: `This is a security group for database in the ${enviromentDesc} environment. Allows inbound access only from VPC environemnts`,
        allowAllOutbound: true,

    })

    this.securityGroup.addIngressRule(
        ec2.Peer.ipv4(props.cidrVPCEnvironments), 
        ec2.Port.tcp(27017), 
        'Allow trafic from vpc enviroments'
    );
    
    this.securityGroup.addIngressRule(
        ec2.Peer.ipv4(props.cidrVPCDataBase), 
        ec2.Port.tcp(27017), 
        'Allow trafic from vpc database'
    );
    
    /* Create KMS key policy */
    this.keyPolicy = new iam.PolicyDocument({
        statements: [
            new iam.PolicyStatement({
                sid: 'AllowRootAccountFullAccess',
                effect: iam.Effect.ALLOW,
                principals: [new iam.AccountRootPrincipal()],
                actions: ['kms:*'],
                resources: ['*'],
            }),
            new iam.PolicyStatement({
                sid: 'AllowDocumentDBUseKey',
                effect: iam.Effect.ALLOW,
                principals: [new iam.ServicePrincipal('rds.amazonaws.com')],
                actions: [
                        'kms:Encrypt',
                        'kms:Decrypt',
                        'kms:ReEncrypt*',
                        'kms:GenerateDataKey*',
                        'kms:DescribeKey'
                ],
                resources: ['*'],
            }),
        ],
    });

    /* Create KMS key for encryption at rest */
    this.kmsKey = new kms.Key(this, 'kmsKeyDatabase', {
        alias: `alias/${prefix}-docdb-key`,
        keySpec: kms.KeySpec.SYMMETRIC_DEFAULT,
        keyUsage: kms.KeyUsage.ENCRYPT_DECRYPT,
        enableKeyRotation: true,
        rotationPeriod: Duration.days(90),
        policy: this.keyPolicy,
        description: `KMS key for DocumentDB encryption at rest in the ${enviromentDesc} environment.`,
    });

    /* Store database credentials in Secrets Manager */
    this.dbSecret = new secretsmanager.Secret(this, 'docdbSecret', {
        secretName: `${prefix}-docdb-root-credentials`,
        description: `Master credentials for DocumentDB in the ${enviromentDesc} environment`,
        encryptionKey: this.kmsKey,
        generateSecretString: {
            secretStringTemplate: JSON.stringify({ username: props.dbUsername }),
            generateStringKey: 'password',
            excludePunctuation: true,
            passwordLength: 32,
        },
        removalPolicy: RemovalPolicy.RETAIN,
    });

    this.dbSecret.addRotationSchedule('SecretRotation', {
        hostedRotation: secretsmanager.HostedRotation.mongoDbSingleUser({
            functionName: `${prefix}-docdb-root-rotation`,
            excludeCharacters: '"@/:\'\\',
            vpc: vpcEnvironments,
            vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [this.rotationSG],
        }),
        automaticallyAfter: Duration.days(30),
    });

    /* Create DocumentDB cluster */
    this.databaseDocumentDB = new documentDB.DatabaseCluster(this, 'databaseDocumentDB', {
        masterUser: {
            username: this.dbSecret.secretValueFromJson('username').unsafeUnwrap(),
            password: this.dbSecret.secretValueFromJson('password'),
        },
        engineVersion: props.engineDb,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        instances: props.dbInstances ?? 1,
        vpc: vpcDatabase,
        vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
        securityGroup: this.securityGroup,
        parameterGroup: this.parameterGroup,
        storageEncrypted: true,
        kmsKey: this.kmsKey,
        dbClusterName: `${prefix}-docdb-cluster`,
        deletionProtection: true,
        backup: {
            retention: Duration.days(7)
        },
        exportAuditLogsToCloudWatch: true,
        exportProfilerLogsToCloudWatch: true,
        cloudWatchLogsRetention: logs.RetentionDays.TWO_YEARS,
        enablePerformanceInsights: true
    });

    /* Create app user secret for Lambda functions (non-root) */
    this.lambdaUserSecret = new documentDB.DatabaseSecret(this, 'LambdaUserSecret', {
        username: `${prefix}-lambda-user`,
        masterSecret: this.dbSecret,
        encryptionKey: this.kmsKey,
        secretName: `${prefix}-docdb-lambda-credentials`,
    });

    /* Rotation for Lambda app user — also creates the user on first rotation */
    this.lambdaUserSecret.addRotationSchedule('LambdaUserRotation', {
        hostedRotation: secretsmanager.HostedRotation.mongoDbMultiUser({
            functionName: `${prefix}-docdb-rotation`,
            masterSecret: this.dbSecret,
            excludeCharacters: '"@/:\'\\',
            vpc: vpcEnvironments,
            vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [this.rotationSG],
        }),
        automaticallyAfter: Duration.days(30),
    });

    /* Create app user secret for ECS services (non-root) */
    this.ecsUserSecret = new documentDB.DatabaseSecret(this, 'EcsUserSecret', {
        username: `${prefix}-ecs-user`,
        masterSecret: this.dbSecret,
        encryptionKey: this.kmsKey,
        secretName: `${prefix}-docdb-ecs-credentials`,
    });

    /* Rotation for ECS app user — creates the user on first rotation */
    this.ecsUserSecret.addRotationSchedule('EcsUserRotation', {
        hostedRotation: secretsmanager.HostedRotation.mongoDbMultiUser({
            functionName: `${prefix}-docdb-ecs-rotation`,
            masterSecret: this.dbSecret,
            excludeCharacters: '"@/:\'\\',
            vpc: vpcEnvironments,
            vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [this.rotationSG],
        }),
        automaticallyAfter: Duration.days(30),
    });


  }
}

module.exports = { databaseDocumentDB };