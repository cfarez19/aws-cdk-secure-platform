const { Stack, Tags } = require('aws-cdk-lib');
const ec2 = require('aws-cdk-lib/aws-ec2')

class vpcEnvironments extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const prefix = `${props.environment}-${props.empCodigo}`;

    this.VpcEnvironments = new ec2.Vpc(this, `${prefix}-vpc`,{
        ipAddresses: ec2.IpAddresses.cidr(props.cidrVPCEnvironments),
        maxAzs:      2,    
        vpcName: `${prefix}-vpc`,
        natGateways: 1,
        subnetConfiguration: [
        {
          name:       `${prefix}-public`,
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask:   20,
        },
        {
          name:       `${prefix}-private`,
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask:   20,
        },
        {
          name:       `${prefix}-intra`,
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask:   20,
        },
      ],

    });

    // ── TAGS SUBNETS Y ROUTE TABLES ──────────────────────────
    this.VpcEnvironments.publicSubnets.forEach((subnet, i) => {
      const letra = ['a', 'b', 'c'][i];

      // tag directo a la subnet
      Tags.of(subnet).add('Name', `${prefix}-subnet-public-${letra}`);

      // busca la route table hija y le pone su propio tag
      const rt = subnet.node.findChild('RouteTable');
      Tags.of(rt).add('Name', `${prefix}-rt-public-${letra}`, {
        priority: 300,  // prioridad mas alta gana sobre el tag heredado
      });
    });

    this.VpcEnvironments.privateSubnets.forEach((subnet, i) => {
      const letra = ['a', 'b', 'c'][i];

      Tags.of(subnet).add('Name', `${prefix}-subnet-private-${letra}`);

      const rt = subnet.node.findChild('RouteTable');
      Tags.of(rt).add('Name', `${prefix}-rt-private-${letra}`, {
        priority: 300,
      });
    });

    this.VpcEnvironments.isolatedSubnets.forEach((subnet, i) => {
      const letra = ['a', 'b', 'c'][i];

      Tags.of(subnet).add('Name', `${prefix}-subnet-intra-${letra}`);

      const rt = subnet.node.findChild('RouteTable');
      Tags.of(rt).add('Name', `${prefix}-rt-intra-${letra}`, {
        priority: 300,
      });
    });

    // ── TAG IGW ───────────────────────────────────────────────
    const igw = this.VpcEnvironments.node.findChild('IGW');
    Tags.of(igw).add('Name', `${prefix}-igw`);

    // ── TAG NAT ───────────────────────────────────────────────
    this.VpcEnvironments.publicSubnets.forEach(subnet => {
      subnet.node.children.forEach(child => {
        if (child instanceof ec2.CfnNatGateway) {
          Tags.of(child).add('Name', `${prefix}-nat`);
        }
      });
    });

    // ── S3 Gateway Endpoint — tráfico S3 sin salir a internet ─
    this.VpcEnvironments.addGatewayEndpoint('S3Endpoint', {
      service: ec2.GatewayVpcEndpointAwsService.S3,
      subnets: [
        { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
        { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      ],
    });
  }
}

module.exports = { vpcEnvironments };