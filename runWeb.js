const { spawn } = require('node:child_process');
const path = require('node:path');

const webDir = path.join(__dirname, 'web');
const scriptPath = path.join(webDir, 'server.js');

const child = spawn(process.execPath, [scriptPath], {
  cwd: webDir,
  stdio: 'inherit',
  env: process.env,
});

child.on('error', (err) => {
  console.error('failed to start web process:', err);
  process.exit(1);
});

child.on('exit', (code, signal) => {
  if (signal) {
    console.error(`web terminated by signal ${signal}`);
    process.exit(1);
  }
  process.exit(code ?? 0);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => child.kill(sig));
}
