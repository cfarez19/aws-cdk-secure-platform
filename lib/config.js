const fs = require('fs');
const path = require('path');

const REQUIRED = ['clientCode', 'environment', 'region', 'domain', 'certificateArn', 'cidrEnvironments', 'cidrDatabase', 'services'];

/** Load and validate config/<name>.json */
function loadConfig(name) {
  const file = path.join(__dirname, '..', 'config', `${name}.json`);
  if (!fs.existsSync(file)) {
    throw new Error(`Config "${name}" not found. Copy config/example.json to config/${name}.json and fill it in.`);
  }
  const config = JSON.parse(fs.readFileSync(file, 'utf8'));
  const missing = REQUIRED.filter((k) => config[k] === undefined);
  if (missing.length) throw new Error(`config/${name}.json is missing: ${missing.join(', ')}`);
  return config;
}

module.exports = { loadConfig };
