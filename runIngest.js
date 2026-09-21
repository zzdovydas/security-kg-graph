const { spawn } = require('node:child_process');
const path = require('node:path');

const ingestDir = path.join(__dirname, 'ingest');
const scriptPath = path.join(ingestDir, 'index.js');

const nodeArgs = ['--max-old-space-size=6144', scriptPath];

const child = spawn(process.execPath, nodeArgs, {
  cwd: ingestDir,
  stdio: 'inherit',
  env: process.env,
});

child.on('error', (err) => {
  console.error('failed to start ingest process:', err);
  process.exit(1);
});

child.on('exit', (code, signal) => {
  if (signal) {
    console.error(`ingest terminated by signal ${signal}`);
    process.exit(1);
  }
  process.exit(code ?? 0);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => child.kill(sig));
}
