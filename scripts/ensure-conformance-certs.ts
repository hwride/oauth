import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

main();

function main() {
  const certificateDirectory = resolve('conformance/nginx-auth-server/certs');
  const certificatePath = resolve(certificateDirectory, 'tls.crt');
  const keyPath = resolve(certificateDirectory, 'tls.key');
  const hostsPath = resolve(certificateDirectory, 'tls.hosts');
  const certificateHosts = [
    'localhost.emobix.co.uk',
    'host.docker.internal',
    'localhost',
    '127.0.0.1',
    '::1',
  ];

  runMkcert(['-install']);

  if (
    existsSync(certificatePath) &&
    existsSync(keyPath) &&
    existsSync(hostsPath) &&
    readFileSync(hostsPath, 'utf8').trim() === certificateHosts.join('\n')
  ) {
    return;
  }

  mkdirSync(certificateDirectory, { recursive: true });
  runMkcert([
    '-cert-file',
    certificatePath,
    '-key-file',
    keyPath,
    ...certificateHosts,
  ]);
  writeFileSync(hostsPath, `${certificateHosts.join('\n')}\n`);
}

function runMkcert(arguments_: string[]) {
  execFileSync('mkcert', arguments_, { stdio: 'inherit' });
}
