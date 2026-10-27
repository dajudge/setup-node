import {readdir, readFile, writeFile} from 'node:fs/promises';
import {join} from 'node:path';

const vulnerablePattern = `req.setTimeout(this._socketTimeout || 3 * 60000, () => {
            if (socket) {
                socket.end();
            }
            handleResult(new Error(\`Request timeout: \${info.options.path}\`));
        });`;
const safePattern = `req.setTimeout(this._socketTimeout || 3 * 60000, () => {
            const timeoutError = new Error(\`Request timeout: \${info.options.path}\`);
            req.destroy(timeoutError);
            handleResult(timeoutError);
        });`;

async function findHttpClientSources(directory) {
  const sources = [];
  for (const entry of await readdir(directory, {withFileTypes: true})) {
    if (!entry.isDirectory()) {
      continue;
    }
    const child = join(directory, entry.name);
    if (child.endsWith(join('@actions', 'http-client'))) {
      sources.push(join(child, 'lib', 'index.js'));
      continue;
    }
    sources.push(...(await findHttpClientSources(child)));
  }
  return sources;
}

const nodeModules = new URL('../node_modules', import.meta.url).pathname;
const sources = await findHttpClientSources(nodeModules);
if (sources.length === 0) {
  throw new Error(`No @actions/http-client installations found below ${nodeModules}`);
}

for (const sourcePath of sources) {
  const source = await readFile(sourcePath, 'utf8');
  if (source.includes(safePattern)) {
    continue;
  }
  const occurrences = source.split(vulnerablePattern).length - 1;
  if (occurrences !== 1) {
    throw new Error(
      `Expected one vulnerable timeout handler in ${sourcePath}, found ${occurrences}`
    );
  }
  await writeFile(sourcePath, source.replace(vulnerablePattern, safePattern));
}
