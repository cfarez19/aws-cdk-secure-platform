const { Stack, CfnOutput, RemovalPolicy, Duration } = require('aws-cdk-lib');
const wafv2 = require('aws-cdk-lib/aws-wafv2');
const s3 = require('aws-cdk-lib/aws-s3');
const iam = require('aws-cdk-lib/aws-iam');

/**
 * Props:
 *   environment     string    — prefijo del ambiente
 *   empCodigo       string    — código del cliente
 *   domain          string    — dominio base (fallback si no se pasa allowedHosts)
 *   allowedHosts    string[]  — lista de sufijos de host permitidos
 *                               (ej: [".example.com", ".app.example.com"])
 *   allowedIps      string[]  — CIDRs permitidos en los 3 WAFs (ej: ["1.2.3.4/32"])
 *   publicAlbArn    string?   — ARN del ALB público para asociar automáticamente
 *   internalAlbArn  string?   — ARN del ALB interno para asociar automáticamente
 *
 * IMPORTANTE: el WAF de CloudFront (scope CLOUDFRONT) debe estar en us-east-1.
 *
 * Expone:
 *   cloudFrontWafArn — pasar como webAclId en S3Buckets y ApiGatewayStack
 */
class WafStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const { environment, empCodigo, domain, allowedHosts = [domain], allowedIps = [], publicAlbArn, internalAlbArn } = props;
    const prefix = `${environment}-${empCodigo}`;

    // ── Helpers ────────────────────────────────────────────────
    const vis = (metricName) => ({
      sampledRequestsEnabled: true,
      cloudWatchMetricsEnabled: true,
      metricName,
    });

    const byteMatch = (searchString, fieldToMatch, positionalConstraint, type = 'NONE') => ({
      byteMatchStatement: {
        searchString,
        fieldToMatch,
        textTransformations: [{ priority: 0, type }],
        positionalConstraint,
      },
    });

    const pathStatements = (paths) => paths.map(p =>
      byteMatch(p, { uriPath: {} }, 'CONTAINS')
    );

    // Genera un statement OR con todos los hosts permitidos (o uno solo si la lista tiene 1 elemento)
    const hostMatchStatement = (hosts) =>
      hosts.length === 1
        ? byteMatch(hosts[0], { singleHeader: { Name: 'host' } }, 'ENDS_WITH', 'LOWERCASE')
        : { orStatement: { statements: hosts.map(h => byteMatch(h, { singleHeader: { Name: 'host' } }, 'ENDS_WITH', 'LOWERCASE')) } };

    // ── Constantes ─────────────────────────────────────────────
    const BLOCKED_COUNTRIES = [
      'AF','AL','BA','BG','BI','CF','CO','CG','CD','HR','CU','ET','HK',
      'IR','IQ','KP','KR','XK','LB','LY','MK','ML','ME','MM','NI',
      'RO','RU','RS','SI','SO','ZA','SS','SD','SY','UA','VE','YE','ZW','CN',
    ];

    const BLOCKED_PATHS_1 = [
      '/composer','/tatus','/status','/console','/git','/.git',
      '/bower','/init','/config/','/developers','/logs','/robots.txt',
      '/wp-admin','/wp-login','/cgi-bin','/debug','/telescope',
    ];

    const BLOCKED_PATHS_2 = ['.md','package.json','.env','.git','.log','.cfm'];

    // ── IP Sets de LISTA BLANCA ────────────────────────────────
    // REGIONAL: usado por Public ALB WAF e Internal ALB WAF
    const allowedIpSetRegional = new wafv2.CfnIPSet(this, 'AllowedIpSetRegional', {
      name: `${prefix}-allowed-ips`,
      scope: 'REGIONAL',
      ipAddressVersion: 'IPV4',
      addresses: allowedIps,
    });

    // CLOUDFRONT: mismo listado pero en scope CLOUDFRONT
    const allowedIpSetCloudFront = new wafv2.CfnIPSet(this, 'AllowedIpSetCloudFront', {
      name: `${prefix}-cf-allowed-ips`,
      scope: 'CLOUDFRONT',
      ipAddressVersion: 'IPV4',
      addresses: allowedIps,
    });

    // IP Set existente CLOUDFRONT (bloqueo)
    const cfBlockIpSet = new wafv2.CfnIPSet(this, 'CfBlockIpSet', {
      name: `${prefix}-cf-block-ips`,
      scope: 'CLOUDFRONT',
      ipAddressVersion: 'IPV4',
      addresses: [],
    });

    // ── Regla de lista blanca (prioridad 0 en los 3 WAFs) ──────
    // Bloquea cualquier petición cuya IP NO esté en la lista blanca.
    // Todas las demás reglas se desplazan +1.
    const allowListRuleCloudFront = {
      name: 'AllowListedIpsOnly',
      priority: 0,
      statement: {
        notStatement: {
          statement: {
            ipSetReferenceStatement: { arn: allowedIpSetCloudFront.attrArn },
          },
        },
      },
      visibilityConfig: vis('AllowListedIpsOnly'),
      action: { block: {} },
    };

    const allowListRuleRegional = {
      name: 'AllowListedIpsOnly',
      priority: 0,
      statement: {
        notStatement: {
          statement: {
            ipSetReferenceStatement: { arn: allowedIpSetRegional.attrArn },
          },
        },
      },
      visibilityConfig: vis('AllowListedIpsOnly'),
      action: { block: {} },
    };

    // ══════════════════════════════════════════════════════════════
    // 1. WAF CLOUDFRONT
    //    scope: CLOUDFRONT — debe estar en us-east-1
    // ══════════════════════════════════════════════════════════════
    const cloudFrontWaf = new wafv2.CfnWebACL(this, 'CloudFrontWaf', {
      name: `${prefix}-waf-cloudfront`,
      scope: 'CLOUDFRONT',
      defaultAction: { allow: {} },
      visibilityConfig: vis(`${prefix}-waf-cloudfront`),
      rules: [
        // 0. Lista blanca de IPs — bloquea todo lo que NO esté en la lista
        allowListRuleCloudFront,
        // Reglas existentes desplazadas en +1
        {
          name: 'AntiDDoSBlanketRule',
          priority: 1,
          statement: {
            rateBasedStatement: { limit: 500, aggregateKeyType: 'IP', evaluationWindowSec: 300 },
          },
          visibilityConfig: vis('AntiDDoSBlanketRule'),
          action: { block: {} },
        },
        {
          name: 'AWS-AWSManagedRulesBotControlRuleSet',
          priority: 2,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesBotControlRuleSet',
              managedRuleGroupConfigs: [
                { awsManagedRulesBotControlRuleSet: { inspectionLevel: 'COMMON' } },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesBotControlRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesAdminProtectionRuleSet',
          priority: 3,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesAdminProtectionRuleSet' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesAdminProtectionRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesAmazonIpReputationList',
          priority: 4,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesAmazonIpReputationList',
              excludedRules: [
                { name: 'AWSManagedIPDDoSList' },
                { name: 'AWSManagedIPReputationList' },
                { name: 'AWSManagedReconnaissanceList' },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesAmazonIpReputationList'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesAnonymousIpList',
          priority: 5,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesAnonymousIpList',
              excludedRules: [{ name: 'AnonymousIPList' }, { name: 'HostingProviderIPList' }],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesAnonymousIpList'),
          overrideAction: { none: {} },
        },
        {
          name: 'SizeURI',
          priority: 6,
          statement: {
            sizeConstraintStatement: {
              fieldToMatch: { uriPath: {} },
              comparisonOperator: 'GE',
              size: 1024,
              textTransformations: [{ priority: 0, type: 'NONE' }],
            },
          },
          visibilityConfig: vis('URISize'),
          action: { allow: {} },
        },
        {
          name: 'SizeBODY',
          priority: 7,
          statement: {
            sizeConstraintStatement: {
              fieldToMatch: { body: { oversizeHandling: 'CONTINUE' } },
              comparisonOperator: 'GE',
              size: 1024,
              textTransformations: [{ priority: 0, type: 'NONE' }],
            },
          },
          visibilityConfig: vis('SizeBODY'),
          action: { allow: {} },
        },
        {
          name: 'AWS-AWSManagedRulesCommonRuleSet',
          priority: 8,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesCommonRuleSet',
              excludedRules: [
                { name: 'CrossSiteScripting_BODY' }, { name: 'CrossSiteScripting_COOKIE' },
                { name: 'CrossSiteScripting_QUERYARGUMENTS' }, { name: 'CrossSiteScripting_URIPATH' },
                { name: 'EC2MetaDataSSRF_BODY' }, { name: 'EC2MetaDataSSRF_COOKIE' },
                { name: 'EC2MetaDataSSRF_QUERYARGUMENTS' }, { name: 'EC2MetaDataSSRF_URIPATH' },
                { name: 'GenericLFI_BODY' }, { name: 'GenericLFI_QUERYARGUMENTS' }, { name: 'GenericLFI_URIPATH' },
                { name: 'GenericRFI_BODY' }, { name: 'GenericRFI_QUERYARGUMENTS' }, { name: 'GenericRFI_URIPATH' },
                { name: 'NoUserAgent_HEADER' }, { name: 'RestrictedExtensions_QUERYARGUMENTS' },
                { name: 'RestrictedExtensions_URIPATH' }, { name: 'SizeRestrictions_BODY' },
                { name: 'SizeRestrictions_Cookie_HEADER' }, { name: 'SizeRestrictions_QUERYSTRING' },
                { name: 'SizeRestrictions_URIPATH' }, { name: 'UserAgent_BadBots_HEADER' },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesCommonRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesKnownBadInputsRuleSet',
          priority: 9,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesKnownBadInputsRuleSet',
              excludedRules: [
                { name: 'ExploitablePaths_URIPATH' }, { name: 'Host_localhost_HEADER' },
                { name: 'JavaDeserializationRCE_BODY' }, { name: 'JavaDeserializationRCE_HEADER' },
                { name: 'JavaDeserializationRCE_QUERYSTRING' }, { name: 'JavaDeserializationRCE_URIPATH' },
                { name: 'Log4JRCE' }, { name: 'PROPFIND_METHOD' },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesKnownBadInputsRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesLinuxRuleSet',
          priority: 10,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesLinuxRuleSet',
              excludedRules: [{ name: 'LFI_COOKIE' }, { name: 'LFI_QUERYSTRING' }, { name: 'LFI_URIPATH' }],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesLinuxRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesPHPRuleSet',
          priority: 11,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesPHPRuleSet',
              excludedRules: [
                { name: 'PHPHighRiskMethodsVariables_BODY' },
                { name: 'PHPHighRiskMethodsVariables_QUERYARGUMENTS' },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesPHPRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesSQLiRuleSet',
          priority: 12,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesSQLiRuleSet',
              excludedRules: [
                { name: 'SQLiExtendedPatterns_QUERYARGUMENTS' }, { name: 'SQLi_BODY' },
                { name: 'SQLi_COOKIE' }, { name: 'SQLi_QUERYARGUMENTS' }, { name: 'SQLi_URIPATH' },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesSQLiRuleSet'),
          overrideAction: { none: {} },
        },
      ],
    });

    this.cloudFrontWafArn = cloudFrontWaf.attrArn;

    new CfnOutput(this, 'CloudFrontWafArn', {
      exportName: `${prefix}-cf-waf-arn`,
      value: cloudFrontWaf.attrArn,
      description: 'WAF ARN para asociar en distribuciones CloudFront (webAclId)',
    });

    // ══════════════════════════════════════════════════════════════
    // 1b. WAF CLOUDFRONT MIDDLEWARE  — mismas reglas sin allowedIps
    //     scope: CLOUDFRONT — debe estar en us-east-1
    // ══════════════════════════════════════════════════════════════
    const middlewareCloudFrontWaf = new wafv2.CfnWebACL(this, 'MiddlewareCloudFrontWaf', {
      name: `${prefix}-waf-middleware-cloudfront`,
      scope: 'CLOUDFRONT',
      defaultAction: { allow: {} },
      visibilityConfig: vis(`${prefix}-waf-middleware-cloudfront`),
      rules: [
        {
          name: 'AntiDDoSBlanketRule',
          priority: 1,
          statement: {
            rateBasedStatement: { limit: 500, aggregateKeyType: 'IP', evaluationWindowSec: 300 },
          },
          visibilityConfig: vis('AntiDDoSBlanketRule'),
          action: { block: {} },
        },
        {
          name: 'AWS-AWSManagedRulesBotControlRuleSet',
          priority: 2,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesBotControlRuleSet',
              managedRuleGroupConfigs: [
                { awsManagedRulesBotControlRuleSet: { inspectionLevel: 'COMMON' } },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesBotControlRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesAdminProtectionRuleSet',
          priority: 3,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesAdminProtectionRuleSet' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesAdminProtectionRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesAmazonIpReputationList',
          priority: 4,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesAmazonIpReputationList',
              excludedRules: [
                { name: 'AWSManagedIPDDoSList' },
                { name: 'AWSManagedIPReputationList' },
                { name: 'AWSManagedReconnaissanceList' },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesAmazonIpReputationList'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesAnonymousIpList',
          priority: 5,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesAnonymousIpList',
              excludedRules: [{ name: 'AnonymousIPList' }, { name: 'HostingProviderIPList' }],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesAnonymousIpList'),
          overrideAction: { none: {} },
        },
        {
          name: 'SizeURI',
          priority: 6,
          statement: {
            sizeConstraintStatement: {
              fieldToMatch: { uriPath: {} },
              comparisonOperator: 'GE',
              size: 1024,
              textTransformations: [{ priority: 0, type: 'NONE' }],
            },
          },
          visibilityConfig: vis('URISize'),
          action: { allow: {} },
        },
        {
          name: 'SizeBODY',
          priority: 7,
          statement: {
            sizeConstraintStatement: {
              fieldToMatch: { body: { oversizeHandling: 'CONTINUE' } },
              comparisonOperator: 'GE',
              size: 1024,
              textTransformations: [{ priority: 0, type: 'NONE' }],
            },
          },
          visibilityConfig: vis('SizeBODY'),
          action: { allow: {} },
        },
        {
          name: 'AWS-AWSManagedRulesCommonRuleSet',
          priority: 8,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesCommonRuleSet',
              excludedRules: [
                { name: 'CrossSiteScripting_BODY' }, { name: 'CrossSiteScripting_COOKIE' },
                { name: 'CrossSiteScripting_QUERYARGUMENTS' }, { name: 'CrossSiteScripting_URIPATH' },
                { name: 'EC2MetaDataSSRF_BODY' }, { name: 'EC2MetaDataSSRF_COOKIE' },
                { name: 'EC2MetaDataSSRF_QUERYARGUMENTS' }, { name: 'EC2MetaDataSSRF_URIPATH' },
                { name: 'GenericLFI_BODY' }, { name: 'GenericLFI_QUERYARGUMENTS' }, { name: 'GenericLFI_URIPATH' },
                { name: 'GenericRFI_BODY' }, { name: 'GenericRFI_QUERYARGUMENTS' }, { name: 'GenericRFI_URIPATH' },
                { name: 'NoUserAgent_HEADER' }, { name: 'RestrictedExtensions_QUERYARGUMENTS' },
                { name: 'RestrictedExtensions_URIPATH' }, { name: 'SizeRestrictions_BODY' },
                { name: 'SizeRestrictions_Cookie_HEADER' }, { name: 'SizeRestrictions_QUERYSTRING' },
                { name: 'SizeRestrictions_URIPATH' }, { name: 'UserAgent_BadBots_HEADER' },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesCommonRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesKnownBadInputsRuleSet',
          priority: 9,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesKnownBadInputsRuleSet',
              excludedRules: [
                { name: 'ExploitablePaths_URIPATH' }, { name: 'Host_localhost_HEADER' },
                { name: 'JavaDeserializationRCE_BODY' }, { name: 'JavaDeserializationRCE_HEADER' },
                { name: 'JavaDeserializationRCE_QUERYSTRING' }, { name: 'JavaDeserializationRCE_URIPATH' },
                { name: 'Log4JRCE' }, { name: 'PROPFIND_METHOD' },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesKnownBadInputsRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesLinuxRuleSet',
          priority: 10,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesLinuxRuleSet',
              excludedRules: [{ name: 'LFI_COOKIE' }, { name: 'LFI_QUERYSTRING' }, { name: 'LFI_URIPATH' }],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesLinuxRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesPHPRuleSet',
          priority: 11,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesPHPRuleSet',
              excludedRules: [
                { name: 'PHPHighRiskMethodsVariables_BODY' },
                { name: 'PHPHighRiskMethodsVariables_QUERYARGUMENTS' },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesPHPRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesSQLiRuleSet',
          priority: 12,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesSQLiRuleSet',
              excludedRules: [
                { name: 'SQLiExtendedPatterns_QUERYARGUMENTS' }, { name: 'SQLi_BODY' },
                { name: 'SQLi_COOKIE' }, { name: 'SQLi_QUERYARGUMENTS' }, { name: 'SQLi_URIPATH' },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesSQLiRuleSet'),
          overrideAction: { none: {} },
        },
      ],
    });

    this.middlewareCloudFrontWafArn = middlewareCloudFrontWaf.attrArn;

    new CfnOutput(this, 'MiddlewareCloudFrontWafArn', {
      exportName: `${prefix}-middleware-cf-waf-arn`,
      value: middlewareCloudFrontWaf.attrArn,
      description: 'WAF ARN para el CloudFront del middleware (sin restricción de IPs)',
    });

    // ══════════════════════════════════════════════════════════════
    // 2. WAF PUBLIC ALB
    //    scope: REGIONAL — para el ALB público (backoffice/frontend)
    // ══════════════════════════════════════════════════════════════
    const publicAlbWaf = new wafv2.CfnWebACL(this, 'PublicAlbWaf', {
      name: `${prefix}-waf-public-alb`,
      scope: 'REGIONAL',
      defaultAction: { allow: {} },
      visibilityConfig: vis(`${prefix}-waf-public-alb`),
      rules: [
        // 0. Lista blanca de IPs
        allowListRuleRegional,
        {
          name: 'AntiDDoSBlanketRule',
          priority: 2,
          statement: {
            rateBasedStatement: { limit: 500, aggregateKeyType: 'IP', evaluationWindowSec: 300 },
          },
          visibilityConfig: vis('AntiDDoSBlanketRule'),
          action: { block: {} },
        },
        {
          name: 'AntiDDoSURISpecificLogin',
          priority: 3,
          statement: {
            rateBasedStatement: {
              limit: 150,
              aggregateKeyType: 'IP',
              evaluationWindowSec: 300,
              scopeDownStatement: byteMatch('/login', { uriPath: {} }, 'STARTS_WITH'),
            },
          },
          visibilityConfig: vis('AntiDDoSURISpecificLogin'),
          action: { block: {} },
        },
        {
          name: 'AntiDDoSXForwarded',
          priority: 4,
          statement: {
            rateBasedStatement: {
              limit: 100,
              aggregateKeyType: 'FORWARDED_IP',
              evaluationWindowSec: 300,
              forwardedIpConfig: { headerName: 'X-Forwarded-For', fallbackBehavior: 'MATCH' },
            },
          },
          visibilityConfig: vis('AntiDDoSXForwarded'),
          action: { block: {} },
        },
        {
          name: 'Block-non-valid-hosts',
          priority: 5,
          statement: {
            notStatement: {
              statement: hostMatchStatement(allowedHosts),
            },
          },
          visibilityConfig: vis('block-non-valid-hosts'),
          action: { block: {} },
        },
        {
          name: 'BloquearArchivosConfiguracion',
          priority: 6,
          statement: { orStatement: { statements: pathStatements(BLOCKED_PATHS_1) } },
          visibilityConfig: vis('BloquearArchivosConfiguracion'),
          action: { block: {} },
        },
        {
          name: 'BloquearArchivosConfiguracion2',
          priority: 7,
          statement: { orStatement: { statements: pathStatements(BLOCKED_PATHS_2) } },
          visibilityConfig: vis('BloquearArchivosConfiguracion2'),
          action: { block: {} },
        },
        {
          name: 'AWS-AWSManagedRulesBotControlRuleSet',
          priority: 8,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesBotControlRuleSet',
              managedRuleGroupConfigs: [
                { awsManagedRulesBotControlRuleSet: { inspectionLevel: 'COMMON' } },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesBotControlRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesAmazonIpReputationList',
          priority: 9,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesAmazonIpReputationList',
              ruleActionOverrides: [{ name: 'AWSManagedIPDDoSList', actionToUse: { block: {} } }],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesAmazonIpReputationList'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesAnonymousIpList',
          priority: 10,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesAnonymousIpList' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesAnonymousIpList'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesCommonRuleSet',
          priority: 11,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesCommonRuleSet',
              ruleActionOverrides: [
                { name: 'NoUserAgent_HEADER', actionToUse: { count: {} } },
                { name: 'SizeRestrictions_Cookie_HEADER', actionToUse: { count: {} } },
                { name: 'SizeRestrictions_BODY', actionToUse: { count: {} } },
                { name: 'SizeRestrictions_URIPATH', actionToUse: { count: {} } },
                { name: 'SizeRestrictions_QUERYSTRING', actionToUse: { count: {} } },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesCommonRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesKnownBadInputsRuleSet',
          priority: 12,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesKnownBadInputsRuleSet' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesKnownBadInputsRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesLinuxRuleSet',
          priority: 13,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesLinuxRuleSet' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesLinuxRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesPHPRuleSet',
          priority: 14,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesPHPRuleSet' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesPHPRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesSQLiRuleSet',
          priority: 15,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesSQLiRuleSet' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesSQLiRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'BloquearPaises',
          priority: 16,
          statement: {
            geoMatchStatement: {
              countryCodes: BLOCKED_COUNTRIES,
              forwardedIpConfig: { headerName: 'X-Forwarded-For', fallbackBehavior: 'MATCH' },
            },
          },
          visibilityConfig: vis('BloquearPaises'),
          action: { block: {} },
        },
        {
          name: 'Allow-valid-hosts',
          priority: 17,
          statement: hostMatchStatement(allowedHosts),
          visibilityConfig: vis('allow-valid-hosts'),
          action: { allow: {} },
        },
      ],
    });

    if (publicAlbArn) {
      new wafv2.CfnWebACLAssociation(this, 'PublicAlbWafAssociation', {
        resourceArn: publicAlbArn,
        webAclArn: publicAlbWaf.attrArn,
      });
    }

    new CfnOutput(this, 'PublicAlbWafArn', {
      exportName: `${prefix}-public-alb-waf-arn`,
      value: publicAlbWaf.attrArn,
    });

    // ══════════════════════════════════════════════════════════════
    // 3. WAF INTERNAL ALB
    //    scope: REGIONAL — para el ALB interno (middleware)
    // ══════════════════════════════════════════════════════════════
    const internalAlbWaf = new wafv2.CfnWebACL(this, 'InternalAlbWaf', {
      name: `${prefix}-waf-internal-alb`,
      scope: 'REGIONAL',
      defaultAction: { allow: {} },
      visibilityConfig: vis(`${prefix}-waf-internal-alb`),
      rules: [
        {
          name: 'BloquearPaises',
          priority: 1,
          statement: {
            geoMatchStatement: {
              countryCodes: BLOCKED_COUNTRIES,
              forwardedIpConfig: { headerName: 'X-Forwarded-For', fallbackBehavior: 'MATCH' },
            },
          },
          visibilityConfig: vis('BloquearPaises'),
          action: { block: {} },
        },
        {
          name: 'PermitirURIEnvioMail',
          priority: 2,
          statement: byteMatch('api/mail/send', { uriPath: {} }, 'CONTAINS'),
          visibilityConfig: vis('PermitirURIEnvioMail'),
          action: { allow: {} },
        },
        {
          name: 'PermitirURIDocumentoPublico',
          priority: 3,
          statement: byteMatch(
            'public/document-pdf',
            { singleQueryArgument: { Name: 'r' } },
            'CONTAINS'
          ),
          visibilityConfig: vis('PermitirURIDocumentoPublico'),
          action: { allow: {} },
        },
        {
          name: 'AntiDDoSBlanketRule',
          priority: 4,
          statement: {
            rateBasedStatement: { limit: 500, aggregateKeyType: 'IP', evaluationWindowSec: 300 },
          },
          visibilityConfig: vis('AntiDDoSBlanketRule'),
          action: { block: {} },
        },
        {
          name: 'Block-non-valid-hosts',
          priority: 5,
          statement: {
            notStatement: {
              statement: hostMatchStatement(allowedHosts),
            },
          },
          visibilityConfig: vis('block-non-valid-hosts'),
          action: { block: {} },
        },
        {
          name: 'SQLiRuleSetWithExclusion',
          priority: 8,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesSQLiRuleSet',
              excludedRules: [{ name: 'SQLi_BODY' }],
              scopeDownStatement: {
                notStatement: {
                  statement: byteMatch('/public/document-pdf', { uriPath: {} }, 'CONTAINS'),
                },
              },
            },
          },
          visibilityConfig: vis('SQLiRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'BloquearArchivosConfiguracion',
          priority: 9,
          statement: { orStatement: { statements: pathStatements(BLOCKED_PATHS_1) } },
          visibilityConfig: vis('BloquearArchivosConfiguracion'),
          action: { block: {} },
        },
        {
          name: 'BloquearArchivosConfiguracion2',
          priority: 10,
          statement: { orStatement: { statements: pathStatements(BLOCKED_PATHS_2) } },
          visibilityConfig: vis('BloquearArchivosConfiguracion2'),
          action: { block: {} },
        },
        {
          name: 'AWS-AWSManagedRulesAmazonIpReputationList',
          priority: 11,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesAmazonIpReputationList',
              ruleActionOverrides: [{ name: 'AWSManagedIPDDoSList', actionToUse: { block: {} } }],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesAmazonIpReputationList'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesAnonymousIpList',
          priority: 12,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesAnonymousIpList',
              ruleActionOverrides: [{ name: 'HostingProviderIPList', actionToUse: { count: {} } }],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesAnonymousIpList'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesCommonRuleSet',
          priority: 13,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesCommonRuleSet',
              ruleActionOverrides: [
                { name: 'NoUserAgent_HEADER', actionToUse: { count: {} } },
                { name: 'SizeRestrictions_Cookie_HEADER', actionToUse: { count: {} } },
                { name: 'SizeRestrictions_BODY', actionToUse: { count: {} } },
                { name: 'SizeRestrictions_URIPATH', actionToUse: { count: {} } },
                { name: 'SizeRestrictions_QUERYSTRING', actionToUse: { count: {} } },
                { name: 'CrossSiteScripting_BODY', actionToUse: { count: {} } },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesCommonRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesKnownBadInputsRuleSet',
          priority: 14,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesKnownBadInputsRuleSet' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesKnownBadInputsRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesLinuxRuleSet',
          priority: 15,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesLinuxRuleSet' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesLinuxRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesPHPRuleSet',
          priority: 16,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesPHPRuleSet' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesPHPRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'AWS-AWSManagedRulesSQLiRuleSet',
          priority: 17,
          statement: {
            managedRuleGroupStatement: { vendorName: 'AWS', name: 'AWSManagedRulesSQLiRuleSet' },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesSQLiRuleSet'),
          overrideAction: { none: {} },
        },
        {
          name: 'allow-frontend-index',
          priority: 18,
          statement: {
            orStatement: {
              statements: [
                byteMatch('/frontend/web/index.php', { uriPath: {} }, 'STARTS_WITH'),
                byteMatch('frontend/web/', { uriPath: {} }, 'STARTS_WITH'),
              ],
            },
          },
          visibilityConfig: vis('allow-frontend-index'),
          action: { allow: {} },
        },
        {
          name: 'allow-api-axios',
          priority: 19,
          statement: {
            andStatement: {
              statements: [
                byteMatch('/api/', { uriPath: {} }, 'STARTS_WITH'),
                byteMatch('axios', { singleHeader: { Name: 'user-agent' } }, 'CONTAINS', 'LOWERCASE'),
              ],
            },
          },
          visibilityConfig: vis('allow-api-axios'),
          action: { allow: {} },
        },
        {
          name: 'AWS-AWSManagedRulesBotControlRuleSet',
          priority: 20,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesBotControlRuleSet',
              managedRuleGroupConfigs: [
                { awsManagedRulesBotControlRuleSet: { inspectionLevel: 'COMMON' } },
              ],
              ruleActionOverrides: [
                { name: 'CategoryAdvertising', actionToUse: { count: {} } },
                { name: 'CategoryArchiver', actionToUse: { count: {} } },
                { name: 'CategoryContentFetcher', actionToUse: { count: {} } },
                { name: 'CategoryEmailClient', actionToUse: { count: {} } },
                { name: 'CategoryHttpLibrary', actionToUse: { block: {} } },
                { name: 'CategoryLinkChecker', actionToUse: { count: {} } },
                { name: 'CategoryMiscellaneous', actionToUse: { count: {} } },
                { name: 'CategoryMonitoring', actionToUse: { count: {} } },
                { name: 'CategoryScrapingFramework', actionToUse: { block: {} } },
                { name: 'CategorySearchEngine', actionToUse: { count: {} } },
                { name: 'CategorySecurity', actionToUse: { count: {} } },
                { name: 'CategorySeo', actionToUse: { count: {} } },
                { name: 'CategorySocialMedia', actionToUse: { count: {} } },
                { name: 'CategoryAI', actionToUse: { count: {} } },
                { name: 'SignalAutomatedBrowser', actionToUse: { count: {} } },
                { name: 'SignalKnownBotDataCenter', actionToUse: { block: {} } },
                { name: 'SignalNonBrowserUserAgent', actionToUse: { block: {} } },
                { name: 'TGT_VolumetricIpTokenAbsent', actionToUse: { count: {} } },
                { name: 'TGT_VolumetricSession', actionToUse: { count: {} } },
                { name: 'TGT_SignalAutomatedBrowser', actionToUse: { count: {} } },
                { name: 'TGT_SignalBrowserInconsistency', actionToUse: { count: {} } },
                { name: 'TGT_TokenReuseIp', actionToUse: { count: {} } },
                { name: 'TGT_ML_CoordinatedActivityMedium', actionToUse: { count: {} } },
                { name: 'TGT_ML_CoordinatedActivityHigh', actionToUse: { count: {} } },
              ],
            },
          },
          visibilityConfig: vis('AWS-AWSManagedRulesBotControlRuleSet'),
          overrideAction: { count: {} },
        },
        {
          name: 'Allow-valid-hosts',
          priority: 22,
          statement: hostMatchStatement(allowedHosts),
          visibilityConfig: vis('allow-valid-hosts'),
          action: { allow: {} },
        },
        {
          name: 'block-known-malicious-user-agents',
          priority: 23,
          statement: {
            orStatement: {
              statements: [
                byteMatch('feroxbuster', { singleHeader: { Name: 'user-agent' } }, 'CONTAINS', 'LOWERCASE'),
                byteMatch('postmanruntime', { singleHeader: { Name: 'user-agent' } }, 'CONTAINS', 'LOWERCASE'),
                byteMatch('python-requests', { singleHeader: { Name: 'user-agent' } }, 'CONTAINS', 'LOWERCASE'),
              ],
            },
          },
          visibilityConfig: vis('block-known-malicious-user-agents'),
          action: { block: {} },
        },
      ],
    });

    if (internalAlbArn) {
      new wafv2.CfnWebACLAssociation(this, 'InternalAlbWafAssociation', {
        resourceArn: internalAlbArn,
        webAclArn: internalAlbWaf.attrArn,
      });
    }

    new CfnOutput(this, 'InternalAlbWafArn', {
      exportName: `${prefix}-internal-alb-waf-arn`,
      value: internalAlbWaf.attrArn,
    });

    new CfnOutput(this, 'AllowedIpSetRegionalArn', {
      exportName: `${prefix}-allowed-ip-set-arn`,
      value: allowedIpSetRegional.attrArn,
      description: 'IP set de lista blanca REGIONAL (ALBs)',
    });

    new CfnOutput(this, 'AllowedIpSetCloudFrontArn', {
      exportName: `${prefix}-cf-allowed-ip-set-arn`,
      value: allowedIpSetCloudFront.attrArn,
      description: 'IP set de lista blanca CLOUDFRONT',
    });

    // ── S3 Bucket para logs de los 3 WAFs ──────────────────────
    // El nombre DEBE empezar con "aws-waf-logs-" para que WAFv2 pueda escribir.
    const wafLogBucket = new s3.Bucket(this, 'WafLogBucket', {
      bucketName: `aws-waf-logs-${prefix}`,
      removalPolicy: RemovalPolicy.RETAIN,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: false,
      lifecycleRules: [
        { expiration: Duration.days(90), description: 'Eliminar logs WAF después de 90 días' },
      ],
    });

    // Bucket policy requerida para que el servicio de entrega de logs de AWS escriba
    wafLogBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AWSLogDeliveryWrite',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('delivery.logs.amazonaws.com')],
      actions: ['s3:PutObject'],
      resources: [`${wafLogBucket.bucketArn}/*`],
      conditions: {
        StringEquals: {
          's3:x-amz-acl': 'bucket-owner-full-control',
          'aws:SourceAccount': this.account,
        },
      },
    }));

    wafLogBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AWSLogDeliveryAclCheck',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('delivery.logs.amazonaws.com')],
      actions: ['s3:GetBucketAcl'],
      resources: [wafLogBucket.bucketArn],
    }));

    // ── Logging Configuration para los 4 WAFs ──────────────────
    new wafv2.CfnLoggingConfiguration(this, 'CloudFrontWafLogging', {
      resourceArn: cloudFrontWaf.attrArn,
      logDestinationConfigs: [wafLogBucket.bucketArn],
    });

    new wafv2.CfnLoggingConfiguration(this, 'MiddlewareCloudFrontWafLogging', {
      resourceArn: middlewareCloudFrontWaf.attrArn,
      logDestinationConfigs: [wafLogBucket.bucketArn],
    });

    new wafv2.CfnLoggingConfiguration(this, 'PublicAlbWafLogging', {
      resourceArn: publicAlbWaf.attrArn,
      logDestinationConfigs: [wafLogBucket.bucketArn],
    });

    new wafv2.CfnLoggingConfiguration(this, 'InternalAlbWafLogging', {
      resourceArn: internalAlbWaf.attrArn,
      logDestinationConfigs: [wafLogBucket.bucketArn],
    });

    new CfnOutput(this, 'WafLogBucketName', {
      exportName: `${prefix}-waf-log-bucket`,
      value: wafLogBucket.bucketName,
      description: 'Bucket S3 con logs de los 3 WAFs',
    });
  }
}

module.exports = { WafStack };
