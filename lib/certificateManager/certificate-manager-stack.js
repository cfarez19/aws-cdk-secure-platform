const { Stack } = require('aws-cdk-lib');
const route53 = require('aws-cdk-lib/aws-route53');
const acm = require('aws-cdk-lib/aws-certificatemanager');

class CertificateManager extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    // Importar la Hosted Zone existente (dominio ya comprado en Route 53)
    this.hostedZone = route53.HostedZone.fromLookup(this, 'HostedZone', {
      domainName: props.domain,
    });

    // Certificado wildcard — cubre *.tudominio.com y tudominio.com
    this.certificate = new acm.Certificate(this, 'Certificate', {
      domainName: props.domain,
      subjectAlternativeNames: [`*.${props.domain}`],
      validation: acm.CertificateValidation.fromDns(this.hostedZone),
    });
  }
}

module.exports = { CertificateManager };
