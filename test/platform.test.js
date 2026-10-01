const cdk = require('aws-cdk-lib');
const { Template, Match } = require('aws-cdk-lib/assertions');
const { loadConfig } = require('../lib/config');
const { buildPlatform } = require('../lib/platform');

const ACCOUNT = '111122223333';
const config = loadConfig('example');

function build() {
  const app = new cdk.App({
    context: {
      // Fake Route 53 lookup so the test runs offline
      [`hosted-zone:account=${ACCOUNT}:domainName=${config.domain}:region=${config.region}`]: {
        Id: '/hostedzone/Z0000000000000EXAMPLE', Name: `${config.domain}.`,
      },
    },
  });
  return buildPlatform(app, config, { account: ACCOUNT, apiHeaderSecret: 'test-secret' });
}

const stacks = build();
const t = (s) => Template.fromStack(s);

test('builds every stack of the platform', () => {
  expect(Object.keys(stacks)).toHaveLength(14);
});

test('app VPC and database VPC are peered', () => {
  t(stacks.peering).resourceCountIs('AWS::EC2::VPCPeeringConnection', 1);
});

test('DocumentDB is encrypted with a customer-managed KMS key', () => {
  t(stacks.database).hasResourceProperties('AWS::DocDB::DBCluster', {
    StorageEncrypted: true,
    KmsKeyId: Match.anyValue(),
  });
});

test('database secrets rotate automatically', () => {
  t(stacks.database).resourceCountIs('AWS::SecretsManager::RotationSchedule', 3);
});

test('one ECS service per configured service, with Container Insights', () => {
  const ecs = t(stacks.ecs);
  ecs.resourceCountIs('AWS::ECS::Service', config.services.length);
  ecs.hasResourceProperties('AWS::ECS::Cluster', {
    ClusterSettings: [{ Name: 'containerInsights', Value: 'enabled' }],
  });
});

test('WAF protects CloudFront, both ALBs and the API', () => {
  t(stacks.waf).resourceCountIs('AWS::WAFv2::WebACL', 4);
});

test('backups copy to the DR region', () => {
  t(stacks.backup).hasResourceProperties('AWS::Backup::BackupPlan', {
    BackupPlan: { BackupPlanRule: Match.arrayWith([Match.objectLike({ CopyActions: Match.anyValue() })]) },
  });
});
