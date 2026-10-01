const { Stack, Duration, RemovalPolicy, CfnOutput } = require('aws-cdk-lib');
const ecs = require('aws-cdk-lib/aws-ecs');
const ecr = require('aws-cdk-lib/aws-ecr');
const ec2 = require('aws-cdk-lib/aws-ec2');
const elbv2 = require('aws-cdk-lib/aws-elasticloadbalancingv2');
const acm = require('aws-cdk-lib/aws-certificatemanager');
const kms = require('aws-cdk-lib/aws-kms');
const iam = require('aws-cdk-lib/aws-iam');
const logs = require('aws-cdk-lib/aws-logs');
const appscaling = require('aws-cdk-lib/aws-applicationautoscaling');

/**
 * Props:
 *   environment       string  — prefijo del ambiente (ej: "prod-oneclick")
 *   empCodigo         string  — código del cliente (ej: "acme")
 *   envDescription    string  — descripción legible del ambiente
 *   vpcEnvironments   IVpc    — VPC donde corren los servicios
 *   certificateArn    string  — ARN del certificado ACM para los ALBs
 *   domain            string? — dominio base para reglas host-based del ALB (opcional)
 *   dbCluster         object  — cluster DocumentDB
 *   ecsUserSecret     ISecret — secret con credenciales ECS → DocumentDB
 *   dbKmsKey          IKey    — llave KMS del DocumentDB
 *   services          array   — definición de cada servicio (ver abajo)
 *
 * Cada servicio en services[]:
 *   name              string  — nombre del servicio
 *   albType           'public' | 'internal'
 *   subdomain         string? — si se especifica, la regla del ALB filtra por Host header
 *   pathPattern       string? — si no hay subdomain, ruta path-based (ej: "/api")
 *   port              number  — puerto del contenedor (default 80)
 *   cpu               number  — CPU units (default 256)
 *   memoryLimitMiB    number  — memoria en MiB (default 512)
 *   desiredCount      number  — tareas deseadas (default 0)
 *   priority          number  — prioridad de la listener rule (único por listener)
 *   healthCheckPath   string  — path del health check (default "/")
 *   imageTag          string  — tag de la imagen ECR (default "latest")
 *   containerEnv      object  — variables de entorno adicionales del contenedor
 */
class EcsFargateStack extends Stack {
  constructor(scope, id, props) {
    super(scope, id, props);

    const { environment, empCodigo, envDescription, vpcEnvironments, certificateArn, domain } = props;
    const prefix = `${environment}-${empCodigo}`;

    // Importa el certificado desde su ARN — no crea ni busca en hosted zones
    const certificate = acm.Certificate.fromCertificateArn(this, 'Certificate', certificateArn);

    // ── ECS Cluster ───────────────────────────────────────────
    this.cluster = new ecs.Cluster(this, `${prefix}-cluster`, {
      clusterName: `${prefix}-cluster`,
      vpc: vpcEnvironments,
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    });

    // ── Public ALB ────────────────────────────────────────────
    this.publicAlb = new elbv2.ApplicationLoadBalancer(this, `${prefix}-public-alb`, {
      loadBalancerName: `${prefix}-public-alb`,
      vpc: vpcEnvironments,
      internetFacing: true,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
    });

    const publicListener = this.publicAlb.addListener(`${prefix}-public-https-listener`, {
      port: 443,
      open: true,
      certificates: [certificate],
      defaultAction: elbv2.ListenerAction.fixedResponse(404, {
        contentType: 'text/plain',
        messageBody: 'Not found',
      }),
    });

    // ── Internal ALB ──────────────────────────────────────────
    this.internalAlb = new elbv2.ApplicationLoadBalancer(this, `${prefix}-internal-alb`, {
      loadBalancerName: `${prefix}-inter-alb`,
      vpc: vpcEnvironments,
      internetFacing: false,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    this.internalListener = this.internalAlb.addListener(`${prefix}-internal-https-listener`, {
      port: 443,
      open: true,
      certificates: [certificate],
      defaultAction: elbv2.ListenerAction.fixedResponse(404, {
        contentType: 'text/plain',
        messageBody: 'Not found',
      }),
    });

    new CfnOutput(this, 'PublicAlbDns', {
      exportName: `${prefix}-public-alb-dns`,
      value: this.publicAlb.loadBalancerDnsName,
      description: 'Public ALB DNS — apunta este CNAME en tu DNS externo',
    });

    new CfnOutput(this, 'InternalAlbDns', {
      exportName: `${prefix}-internal-alb-dns`,
      value: this.internalAlb.loadBalancerDnsName,
      description: 'Internal ALB DNS',
    });

    this.repositories  = {};
    this.services      = {};
    this.targetGroups  = {};
    this.taskRoles     = {};

    // ── Un ECR + Task Def + Fargate Service por entrada ───────
    for (const svc of props.services) {
      const svcPrefix  = `${environment}-${svc.name}`;
      const isInternal = svc.albType === 'internal';
      const listener   = isInternal ? this.internalListener : publicListener;
      const alb        = isInternal ? this.internalAlb : this.publicAlb;

      // KMS Key para el repositorio ECR
      const kmsKey = new kms.Key(this, `KmsKey-${svc.name}`, {
        alias: `alias/${svcPrefix}-ecr-key`,
        keySpec: kms.KeySpec.SYMMETRIC_DEFAULT,
        keyUsage: kms.KeyUsage.ENCRYPT_DECRYPT,
        enableKeyRotation: true,
        rotationPeriod: Duration.days(90),
        description: `KMS key for ${svc.name} ECR in ${envDescription}`,
      });

      // ECR Repository
      const repository = new ecr.Repository(this, `Ecr-${svc.name}`, {
        repositoryName: svcPrefix,
        encryption: ecr.RepositoryEncryption.KMS,
        encryptionKey: kmsKey,
        removalPolicy: RemovalPolicy.DESTROY,
        lifecycleRules: [
          { maxImageAge: Duration.days(30), description: 'Delete images older than 30 days' },
        ],
      });
      this.repositories[svc.name] = repository;

      // CloudWatch Log Group
      const logGroup = new logs.LogGroup(this, `LogGroup-${svc.name}`, {
        logGroupName: `/ecs/${svcPrefix}-td`,
        retention: logs.RetentionDays.TWO_YEARS,
        removalPolicy: RemovalPolicy.DESTROY,
      });

      // Task Definition
      const taskDef = new ecs.FargateTaskDefinition(this, `TaskDef-${svc.name}`, {
        family: `${svcPrefix}-td`,
        cpu: svc.cpu ?? 256,
        memoryLimitMiB: svc.memoryLimitMiB ?? 512,
        runtimePlatform: {
          cpuArchitecture: ecs.CpuArchitecture.X86_64,
          operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
        },
        ephemeralStorageGiB: 30,
      });

      taskDef.addContainer(`Container-${svc.name}`, {
        containerName: `${svcPrefix}-container`,
        image: ecs.ContainerImage.fromEcrRepository(repository, svc.imageTag ?? 'latest'),
        essential: true,
        portMappings: [
          {
            name: `${svc.name}-port`,
            containerPort: svc.port ?? 80,
            protocol: ecs.Protocol.TCP,
            appProtocol: ecs.AppProtocol.http,
          },
        ],
        environment: {
          DOCDB_SECRET_ARN: props.ecsUserSecret.secretArn,
          DOCDB_ENDPOINT:   props.dbCluster.clusterEndpoint.hostname,
          DOCDB_PORT:       props.dbCluster.clusterEndpoint.port.toString(),
          ...(svc.containerEnv ?? {}),
        },
        logging: ecs.LogDrivers.awsLogs({ logGroup, streamPrefix: 'ecs' }),
      });

      taskDef.addToTaskRolePolicy(new iam.PolicyStatement({
        actions: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
        resources: [props.ecsUserSecret.secretArn],
      }));
      taskDef.addToTaskRolePolicy(new iam.PolicyStatement({
        actions: ['kms:Decrypt'],
        resources: [props.dbKmsKey.keyArn],
      }));

      // Fargate Service
      const fargateService = new ecs.FargateService(this, `Service-${svc.name}`, {
        serviceName: `${svcPrefix}-service`,
        cluster: this.cluster,
        taskDefinition: taskDef,
        desiredCount: svc.desiredCount ?? 0,
        assignPublicIp: false,
        vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
        healthCheckGracePeriod: Duration.seconds(120),
      });

      fargateService.connections.allowFrom(alb, ec2.Port.tcp(svc.port ?? 80));

      const tgConfig = {
        vpc: vpcEnvironments,
        port: svc.port ?? 80,
        protocol: elbv2.ApplicationProtocol.HTTP,
        targetType: elbv2.TargetType.IP,
        healthCheck: {
          path: svc.healthCheckPath ?? '/',
          interval: Duration.seconds(30),
          healthyHttpCodes: '200-499',
        },
        ...(svc.stickySession ? { stickinessCookieDuration: Duration.days(1) } : {}),
      };

      const blueTG = new elbv2.ApplicationTargetGroup(this, `TG-blue-${svc.name}`, {
        ...tgConfig,
        targetGroupName: `${svcPrefix}-blue-tg`,
        targets: [fargateService],
      });

      const greenTG = new elbv2.ApplicationTargetGroup(this, `TG-green-${svc.name}`, {
        ...tgConfig,
        targetGroupName: `${svcPrefix}-green-tg`,
      });

      // Listener rule — host-based si tiene subdomain, path-based si no
      const conditions = svc.subdomain && domain
        ? [elbv2.ListenerCondition.hostHeaders([`${svc.subdomain}.${domain}`])]
        : [elbv2.ListenerCondition.pathPatterns([`${svc.pathPattern ?? `/${svc.name}`}*`])];

      // Regla de redirect raíz — debe ir ANTES (prioridad menor) que la regla forward
      if (svc.redirectRootTo) {
        const [redirectPath, redirectQuery] = svc.redirectRootTo.split('?');
        new elbv2.ApplicationListenerRule(this, `Rule-root-redirect-${svc.name}`, {
          listener,
          priority: svc.priority - 1,
          conditions: [
            ...conditions,
            elbv2.ListenerCondition.pathPatterns(['/']),
          ],
          action: elbv2.ListenerAction.redirect({
            protocol: 'HTTPS',
            port: '443',
            host: '#{host}',
            path: redirectPath,
            query: redirectQuery ?? '',
            permanent: true,
          }),
        });
      }

      new elbv2.ApplicationListenerRule(this, `Rule-${svc.name}`, {
        listener,
        priority: svc.priority,
        conditions,
        action: elbv2.ListenerAction.forward([blueTG]),
      });

      // Sin registros Route 53 — el DNS externo lo gestiona el cliente.
      // Los outputs exponen los DNS names de los ALBs para crear los CNAMEs.

      const scaling = fargateService.autoScaleTaskCount({
        minCapacity: svc.minCapacity ?? 1,
        maxCapacity: svc.maxCapacity ?? 6,
      });

      scaling.scaleOnCpuUtilization(`ScaleOnCpu-${svc.name}`, {
        targetUtilizationPercent: 60,
        scaleInCooldown: Duration.seconds(60),
        scaleOutCooldown: Duration.seconds(60),
      });

      scaling.scaleOnMemoryUtilization(`ScaleOnMemory-${svc.name}`, {
        targetUtilizationPercent: 60,
        scaleInCooldown: Duration.seconds(60),
        scaleOutCooldown: Duration.seconds(60),
      });

      // 6am Ecuador (11:00 UTC) → mínimo 2 tasks
      scaling.scaleOnSchedule(`DaytimeScale-${svc.name}`, {
        schedule: appscaling.Schedule.cron({ hour: '11', minute: '0' }),
        minCapacity: 2,
      });

      // 10pm Ecuador (03:00 UTC) → mínimo 1 task
      scaling.scaleOnSchedule(`NighttimeScale-${svc.name}`, {
        schedule: appscaling.Schedule.cron({ hour: '3', minute: '0' }),
        minCapacity: 1,
      });

      this.targetGroups[svc.name] = { blue: blueTG, green: greenTG };
      this.services[svc.name]     = fargateService;
      this.taskRoles[svc.name]    = taskDef.taskRole;

      new CfnOutput(this, `Output-blue-tg-${svc.name}`, {
        exportName: `${svcPrefix}-blue-tg-arn`,
        value: blueTG.targetGroupArn,
        description: `Blue TG ARN for ${svc.name}`,
      });

      new CfnOutput(this, `Output-green-tg-${svc.name}`, {
        exportName: `${svcPrefix}-green-tg-arn`,
        value: greenTG.targetGroupArn,
        description: `Green TG ARN for ${svc.name}`,
      });

      new CfnOutput(this, `Output-alb-${svc.name}`, {
        exportName: `${svcPrefix}-alb-arn`,
        value: alb.loadBalancerArn,
        description: `ALB ARN for ${svc.name} (${svc.albType ?? 'public'})`,
      });
    }
  }
}

module.exports = { EcsFargateStack };
