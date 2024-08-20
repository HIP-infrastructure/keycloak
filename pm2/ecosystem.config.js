const path = require("path");
const dotenv = require("dotenv");
const { execSync } = require("child_process");

const which = cmd => execSync(`which ${cmd}`).toString().trimEnd();
const relative = (...dir) => path.resolve(__dirname, ...dir);

const env = dotenv.config({ path: relative("../keycloak_backend/keycloak_backend.env") }).parsed;

const caddy = which("caddy");
const gunicorn = which("gunicorn");

module.exports = {
  apps : [{
    script: caddy,
    name: 'caddy_keycloak_backend',
    args: 'run',
    cwd: relative('../caddy'),
    watch: relative('../caddy'),
    env
  },
  {
    script: gunicorn,
    name: 'gunicorn_keycloak_backend',
    args: '--workers 3 --timeout 120 --bind 127.0.0.1:8081 --pythonpath keycloak_backend keycloak_backend:app',
    cwd: relative('..'),
    watch: relative('../keycloak_backend'),
    interpreter: 'python3'	  
  }]
};
