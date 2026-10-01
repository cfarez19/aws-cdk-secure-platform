#!/usr/bin/env node
/**
 * Secure multi-stack AWS platform — CDK entry point.
 *
 * Every environment is described by one JSON file in /config.
 * Pick it at deploy time:
 *
 *   npx cdk deploy --all -c config=prod -c apiHeaderSecret=<uuid>
 *
 * The AWS account comes from your CLI profile (CDK_DEFAULT_ACCOUNT).
 */
const cdk = require('aws-cdk-lib');
const { loadConfig } = require('../lib/config');
const { buildPlatform } = require('../lib/platform');

const app = new cdk.App();
const configName = app.node.tryGetContext('config') || 'dev';
const config = loadConfig(configName);

// Shared secret CloudFront sends to API Gateway. Never commit it.
const apiHeaderSecret = app.node.tryGetContext('apiHeaderSecret') || 'CHANGE-THIS-SECRET-BEFORE-DEPLOY';

buildPlatform(app, config, {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  apiHeaderSecret,
});
