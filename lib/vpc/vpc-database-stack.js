const { Stack, Tags } = require('aws-cdk-lib');
const ec2 = require('aws-cdk-lib/aws-ec2');

class vpcDataBase extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const prefix = `${props.environment}-${props.empCodigo}`;

    this.vpcDataBase = new ec2.Vpc(this, `${prefix}-vpc-database`,{
        ipAddresses: ec2.IpAddresses.cidr(props.cidrVPCDataBase),
        maxAzs:      2,  
        natGateways: 0,  
        vpcName: `${prefix}-vpc-database`,
        subnetConfiguration: [
        {
          name:       `${prefix}-intra`,
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask:   20,
        }
      ],

    });

    // ── TAGS SUBNETS Y ROUTE TABLES ──────────────────────────    
        this.vpcDataBase.isolatedSubnets.forEach((subnet, i) => {
          const letra = ['a', 'b', 'c'][i];
    
          Tags.of(subnet).add('Name', `${prefix}-subnet-database-intra-${letra}`);
    
          const rt = subnet.node.findChild('RouteTable');
          Tags.of(rt).add('Name', `${prefix}-rt-database-intra-${letra}`, {
            priority: 300,
          });
        });
    
    
  }
}

module.exports = { vpcDataBase };