import { readFileSync } from 'fs';
import { join } from 'path';
import { commandSync } from 'execa';

(async () => {
  console.info('Publishing');
  try {
    const currentVersion = JSON.parse(readFileSync(join(__dirname, '..', 'package.json')).toString()).version;
    const latestPublished = JSON.parse(commandSync('npm view azure-ad-jwt-lite --json').stdout)['dist-tags'].latest;
    console.info('Current version', currentVersion);
    console.info('Last published', latestPublished);
    if (currentVersion === latestPublished) {
      console.info('NPM version is already up-to-date, skipping');
      process.exit(0);
    }
    commandSync('npm run build', { stdio: 'inherit' });
    commandSync('npm publish', { stdio: 'inherit' });
    process.exit(0);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();
