import z from 'zod';

const zPluginId = z
  .string()
  .min(1, 'Plugin ID is required')
  .regex(
    /^[a-z0-9-]+$/,
    'Plugin ID must contain only lowercase letters, numbers, and dashes'
  );

const zPlugin = z.object({
  id: zPluginId,
  name: z.string(),
  description: z.string(),
  author: z.string(),
  logo: z.url(),
  homepage: z.string().optional(),
  tags: z.array(z.string()).optional(),
  categories: z.array(z.string()).optional(),
  verified: z.boolean().default(false),
  screenshots: z.array(z.url()).optional()
});

const zPluginVersion = z.object({
  version: z.string(),
  downloadUrl: z.url(),
  checksum: z.string(),
  sdkVersion: z.number().int().nonnegative(),
  size: z.number(),
  timestamp: z.number().int().nonnegative()
});

type TPlugin = z.infer<typeof zPlugin>;
type TPluginVersion = z.infer<typeof zPluginVersion>;
type TPluginsIndex = {
  plugin: TPlugin & {
    verified: boolean;
  };
  versions: TPluginVersion[];
};

export { zPlugin, zPluginVersion };
export type { TPlugin, TPluginVersion, TPluginsIndex };
