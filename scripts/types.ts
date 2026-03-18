import z from 'zod';

const zPlugin = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  author: z.string(),
  repo: z.string(),
  logo: z.url(),
  homepage: z.string().optional(),
  tags: z.array(z.string()).optional(),
  categories: z.array(z.string()).optional()
});

const zPluginVersion = z.object({
  version: z.string(),
  downloadUrl: z.url(),
  checksum: z.string(),
  sdkRange: z.string(),
  size: z.number()
});

type TPlugin = z.infer<typeof zPlugin>;
type TPluginVersion = z.infer<typeof zPluginVersion>;

export { zPlugin, zPluginVersion };
export type { TPlugin, TPluginVersion };
