const { Stack, Duration, CfnOutput } = require('aws-cdk-lib');
const apigwv2 = require('aws-cdk-lib/aws-apigatewayv2');
const apigwv2Integrations = require('aws-cdk-lib/aws-apigatewayv2-integrations');
const apigwv2Authorizers = require('aws-cdk-lib/aws-apigatewayv2-authorizers');
const acm = require('aws-cdk-lib/aws-certificatemanager');
const cloudfront = require('aws-cdk-lib/aws-cloudfront');
const origins = require('aws-cdk-lib/aws-cloudfront-origins');
const ec2 = require('aws-cdk-lib/aws-ec2');
const lambda = require('aws-cdk-lib/aws-lambda');
const route53 = require('aws-cdk-lib/aws-route53');
const route53Targets = require('aws-cdk-lib/aws-route53-targets');

class ApiGatewayStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const { environment, empCodigo, vpcEnvironments, internalListener, hostedZone, certificateArn, webAclId, domain, headerSecret, apiSubdomain, middlewareSubdomain } = props;
    const certificate = acm.Certificate.fromCertificateArn(this, 'Certificate', certificateArn);
    const prefix         = `${environment}-${empCodigo}`;
    const subdomain      = apiSubdomain;
    const middlewareHost = middlewareSubdomain
      ? `${middlewareSubdomain}.${domain}`
      : `${prefix}-middleware.${domain}`;

    // ── Security Group para el VPC Link ───────────────────────
    const vpcLinkSG = new ec2.SecurityGroup(this, 'VpcLinkSG', {
      vpc: vpcEnvironments,
      description: 'Security group for API Gateway VPC Link',
      allowAllOutbound: true,
    });

    // ── VPC Link — puente entre API Gateway y el internal ALB ─
    const vpcLink = new apigwv2.VpcLink(this, 'VpcLink', {
      vpc: vpcEnvironments,
      vpcLinkName: `${prefix}-vpclink`,
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [vpcLinkSG],
    });

    // ── Integración con el internal ALB (HTTPS) ───────────────
    const integration = new apigwv2Integrations.HttpAlbIntegration('MiddlewareIntegration', internalListener, {
      vpcLink,
      secureServerName: middlewareHost,
      parameterMapping: new apigwv2.ParameterMapping()
        .overwriteHeader('host', apigwv2.MappingValue.custom(middlewareHost)),
    });

    // ── Lambda authorizer — valida header x-origin-verify ─────
    // WAF v2 no soporta HTTP API v2; se usa Lambda authorizer.
    const authorizerFn = new lambda.Function(this, 'HeaderAuthorizerFn', {
      functionName: `${prefix}-api-authorizer`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
exports.handler = async (event) => {
  const headers = event.headers || {};
  const value = headers['x-origin-verify'] || headers['X-Origin-Verify'];
  if (value === process.env.HEADER_SECRET) {
    return { isAuthorized: true };
  }
  return { isAuthorized: false };
};
      `),
      environment: { HEADER_SECRET: headerSecret },
    });

    const authorizer = new apigwv2Authorizers.HttpLambdaAuthorizer('HeaderAuthorizer', authorizerFn, {
      authorizerName: `${prefix}-header-authorizer`,
      responseTypes: [apigwv2Authorizers.HttpLambdaResponseType.SIMPLE],
      identitySource: ['$request.header.x-origin-verify'],
    });

    // ── HTTP API con CORS para preflights OPTIONS ─────────────
    // Se usa $default stage para evitar que el prefijo del stage (/live)
    // se incluya en el path enviado al middleware via VPC Link.
    this.httpApi = new apigwv2.HttpApi(this, 'HttpApi', {
      apiName: `${prefix}-api`,
      corsPreflight: {
        allowOrigins: ['*'],
        allowMethods: [apigwv2.CorsHttpMethod.ANY],
        allowHeaders: ['*'],
        maxAge: Duration.seconds(86400),
      },
    });

    // ── Ruta — reenvía todo al middleware con authorizer ──────
    this.httpApi.addRoutes({
      path: '/{proxy+}',
      methods: [apigwv2.HttpMethod.ANY],
      integration,
      authorizer,
    });

    // ── CloudFront delante del API Gateway ────────────────────
    // El browser llama a dev-acme-api.example.com
    // CloudFront agrega x-origin-verify en cada request al origin.
    // El authorizer valida el header → solo CloudFront puede pasar.
    // Sin originPath — $default stage no usa prefijo en la URL
    const apiCfOrigin = new origins.HttpOrigin(
      `${this.httpApi.apiId}.execute-api.${this.region}.amazonaws.com`,
      {
        customHeaders: { 'x-origin-verify': headerSecret },
        protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
      }
    );

    const apiDistribution = new cloudfront.Distribution(this, 'ApiDistribution', {
      comment: `${prefix} API proxy`,
      domainNames: [`${subdomain}.${domain}`],
      certificate,
      ...(webAclId ? { webAclId } : {}),
      defaultBehavior: {
        origin: apiCfOrigin,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
      },
    });

    // ── Route 53 → CloudFront (no al API Gateway directamente) ─
    new route53.ARecord(this, 'ApiRecord', {
      zone: hostedZone,
      recordName: subdomain,
      target: route53.RecordTarget.fromAlias(
        new route53Targets.CloudFrontTarget(apiDistribution)
      ),
    });

    new CfnOutput(this, 'ApiUrl', {
      exportName: `${prefix}-api-url`,
      value: `https://${subdomain}.${domain}`,
      description: 'URL del API Gateway via CloudFront',
    });
  }
}

module.exports = { ApiGatewayStack };
