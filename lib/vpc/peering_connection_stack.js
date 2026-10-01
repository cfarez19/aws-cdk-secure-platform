const { Stack, Tags } = require('aws-cdk-lib');
const ec2 = require('aws-cdk-lib/aws-ec2');

class vpcPeering extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const prefix = `${props.environment}-${props.empCodigo}`;
    const vpcEnvironments = props.vpcEnvironments;
    const vpcDatabase = props.vpcDatabase;

    this.vpcPeeringConn = new ec2.CfnVPCPeeringConnection(this, 'peeringConnection',{
        peerVpcId: vpcEnvironments.vpcId,
        vpcId: vpcDatabase.vpcId,
        tags: [{ key: 'Name', value: `${prefix}-peering`}]

    });

    vpcEnvironments.privateSubnets.forEach((subnet, i) => {
        new ec2.CfnRoute(this, `RouteEnvToDb${i}`, {
            routeTableId:            subnet.routeTable.routeTableId,
            destinationCidrBlock:    vpcDatabase.vpcCidrBlock,
            vpcPeeringConnectionId:  this.vpcPeeringConn.ref,
        });
    });

    vpcDatabase.isolatedSubnets.forEach((subnet, i) => {
        new ec2.CfnRoute(this, `RouteDbtoEnv${i}`, {
            routeTableId:            subnet.routeTable.routeTableId,
            destinationCidrBlock:    vpcEnvironments.vpcCidrBlock,
            vpcPeeringConnectionId:  this.vpcPeeringConn.ref,
        })
    })


    
  }
}

module.exports = { vpcPeering };