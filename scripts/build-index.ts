import fs from 'fs/promises';
import path from 'path';
import { CATEGORIES, TAGS, VERIFIED_PLUGINS } from './statics';
import { TPlugin, TPluginVersion, zPlugin, zPluginVersion } from './types';

const ROOT_DIR = process.cwd();
const PLUGINS_DIR = path.join(ROOT_DIR, 'plugins');
const INDEX_FILE = path.join(ROOT_DIR, 'plugins.json');

const pluginDirs = await fs.readdir(PLUGINS_DIR);

const results: {
  plugin: TPlugin & {
    verified: boolean;
  };
  versions: TPluginVersion[];
}[] = [];

for (const pluginId of pluginDirs) {
  const pluginPath = path.join(PLUGINS_DIR, pluginId);
  const pluginJsonPath = path.join(pluginPath, 'plugin.json');
  const versionsPath = path.join(pluginPath, 'versions');
  const stat = await fs.stat(pluginPath);

  if (!stat.isDirectory()) continue;

  if (!(await fs.exists(pluginJsonPath))) {
    throw new Error(`Missing plugin.json for plugin: ${pluginId}`);
  }

  if (!(await fs.exists(versionsPath))) {
    throw new Error(`Missing versions directory for plugin: ${pluginId}`);
  }

  const pluginJsonRaw = await Bun.file(pluginJsonPath).json();
  const plugin = zPlugin.parse(pluginJsonRaw);

  if (plugin.id !== pluginId) {
    throw new Error(
      `Plugin ID mismatch: expected ${pluginId}, got ${plugin.id}`
    );
  }

  if (plugin.tags && plugin.tags.some((tag) => !TAGS.includes(tag))) {
    throw new Error(`Invalid tag found in plugin: ${pluginId}`);
  }

  if (
    plugin.categories &&
    plugin.categories.some((category) => !CATEGORIES.includes(category))
  ) {
    throw new Error(`Invalid category found in plugin: ${pluginId}`);
  }

  const versionFiles = await fs.readdir(versionsPath);

  if (versionFiles.length === 0) {
    throw new Error(`No versions found for plugin: ${pluginId}`);
  }

  const versions: TPluginVersion[] = [];

  for (const versionFile of versionFiles) {
    const versionFromFile = path.parse(versionFile).name;
    const versionJsonPath = path.join(versionsPath, versionFile);

    if (!(await fs.exists(versionJsonPath))) {
      throw new Error(
        `Missing version file: ${versionFile} for plugin: ${pluginId}`
      );
    }

    const versionJsonRaw = await Bun.file(versionJsonPath).json();
    const versionData = zPluginVersion.parse(versionJsonRaw);

    if (versionData.version !== versionFromFile) {
      throw new Error(
        `Version mismatch in file name and content: ${versionFromFile} vs ${versionData.version} for plugin: ${pluginId}`
      );
    }

    versions.push(versionData);
  }

  const isVerified = VERIFIED_PLUGINS.includes(plugin.id);

  results.push({
    plugin: {
      ...plugin,
      verified: isVerified
    },
    versions: versions.sort((a, b) => {
      const [aMajor, aMinor, aPatch] = a.version.split('.').map(Number);
      const [bMajor, bMinor, bPatch] = b.version.split('.').map(Number);

      if (aMajor !== bMajor) return bMajor - aMajor;
      if (aMinor !== bMinor) return bMinor - aMinor;

      return bPatch - aPatch;
    })
  });

  console.log(
    `Processed plugin: ${pluginId} with ${versions.length} versions.`
  );
}

await fs.writeFile(INDEX_FILE, JSON.stringify(results));

const prettierBin = path.join(ROOT_DIR, 'node_modules', '.bin', 'prettier');

if (!(await fs.exists(prettierBin))) {
  throw new Error('Prettier is not installed.');
}

Bun.spawn(['bun', 'run', 'prettier', '--write', INDEX_FILE]);

console.log(`Index built successfully with ${results.length} plugins.`);
