import path from 'path';
import { zPluginVersion } from './types';

const VIRUSTOTAL_API_BASE = 'https://www.virustotal.com/api/v3';
const VIRUSTOTAL_DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024; // 32 MB
const POLL_INTERVAL_MS = 60_000; // 1 min
const MAX_POLL_ATTEMPTS = 5;
const VIRUSTOTAL_UI_BASE = 'https://www.virustotal.com/gui';

type TVirusTotalStats = {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
};

type TVirusTotalResult = {
  category?: string;
  engine_name?: string;
  result?: string | null;
};

type TVirusTotalAnalysis = {
  data?: {
    id?: string;
    attributes?: {
      status?: string;
      stats?: TVirusTotalStats;
      results?: Record<string, TVirusTotalResult>;
      sha256?: string;
    };
  };
};

type TAnalyzeResult = {
  analysisId: string;
  analysisUrl: string;
  fileName: string;
  sha256: string;
  stats: TVirusTotalStats;
};

const sha256ToHex = (buffer: ArrayBuffer) =>
  Array.from(new Uint8Array(buffer))
    .map((value) => value.toString(16).padStart(2, '0'))
    .join('');

const getSha256 = async (fileBuffer: ArrayBuffer) => {
  const digest = await crypto.subtle.digest('SHA-256', fileBuffer);

  return sha256ToHex(digest);
};

const getApiKey = () => {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    throw new Error('Missing VIRUSTOTAL_API_KEY environment variable.');
  }

  console.log('[analyze] VirusTotal API key found.');

  return apiKey;
};

const getFileNameFromUrl = (url: string) => {
  const parsedUrl = new URL(url);
  const pathname = parsedUrl.pathname;
  const fileName = pathname
    .split('/')
    .filter((str) => !!str)
    .pop();

  return fileName || 'downloaded-file';
};

const getAnalysisUrl = (analysisId: string, sha256?: string) => {
  if (sha256) {
    return `${VIRUSTOTAL_UI_BASE}/file/${sha256}`;
  }

  return `${VIRUSTOTAL_UI_BASE}/analysis/${analysisId}`;
};

const getVersionFilePathsFromArgs = (args: string[]) =>
  args.filter((arg) => arg !== '--');

const analyzeVersionFile = async (versionFilePath: string) => {
  const absolutePath = path.resolve(process.cwd(), versionFilePath);

  console.log(`[analyze] Reading version file: ${absolutePath}`);

  if (!(await Bun.file(absolutePath).exists())) {
    throw new Error(`Version file not found: ${absolutePath}`);
  }

  const versionJsonRaw = await Bun.file(absolutePath).json();
  const versionData = zPluginVersion.parse(versionJsonRaw);

  console.log(
    `[analyze] Analyzing artifact from ${absolutePath}: ${versionData.downloadUrl}`
  );

  return analyze(versionData.downloadUrl);
};

const analyzeVersionFiles = async (versionFilePaths: string[]) => {
  const results: TAnalyzeResult[] = [];

  for (const versionFilePath of versionFilePaths) {
    const result = await analyzeVersionFile(versionFilePath);
    results.push(result);
  }

  return results;
};

const virusTotalRequest = async <T>(
  input: string,
  init: RequestInit,
  apiKey: string
): Promise<T> => {
  const response = await fetch(input, {
    ...init,
    headers: {
      'x-apikey': apiKey,
      ...(init.headers || {})
    }
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `VirusTotal request failed (${response.status} ${response.statusText}): ${errorText}`
    );
  }

  return (await response.json()) as T;
};

const getUploadUrl = async (fileSize: number, apiKey: string) => {
  if (fileSize <= VIRUSTOTAL_DIRECT_UPLOAD_LIMIT) {
    console.log('[analyze] Using direct VirusTotal upload endpoint.');
    return `${VIRUSTOTAL_API_BASE}/files`;
  }

  console.log('[analyze] Requesting VirusTotal large-file upload URL.');

  const response = await virusTotalRequest<{ data?: string }>(
    `${VIRUSTOTAL_API_BASE}/files/upload_url`,
    {
      method: 'GET'
    },
    apiKey
  );

  if (!response.data) {
    throw new Error(
      'VirusTotal did not return an upload URL for a large file.'
    );
  }

  return response.data;
};

const submitFileForAnalysis = async (
  fileName: string,
  fileBuffer: ArrayBuffer,
  apiKey: string
) => {
  console.log(
    `[analyze] Preparing upload for ${fileName} (${fileBuffer.byteLength} bytes).`
  );
  const uploadUrl = await getUploadUrl(fileBuffer.byteLength, apiKey);
  const formData = new FormData();

  formData.append(
    'file',
    new File([fileBuffer], fileName, {
      type: 'application/octet-stream'
    })
  );

  const response = await virusTotalRequest<TVirusTotalAnalysis>(
    uploadUrl,
    {
      method: 'POST',
      body: formData
    },
    apiKey
  );

  const analysisId = response.data?.id;

  if (!analysisId) {
    throw new Error('VirusTotal did not return an analysis ID.');
  }

  console.log(`[analyze] File uploaded. Analysis ID: ${analysisId}`);

  return analysisId;
};

const pollAnalysis = async (analysisId: string, apiKey: string) => {
  for (let attempt = 1; attempt <= MAX_POLL_ATTEMPTS; attempt += 1) {
    console.log(
      `[analyze] Polling VirusTotal analysis ${analysisId} (attempt ${attempt}/${MAX_POLL_ATTEMPTS}).`
    );
    const analysis = await virusTotalRequest<TVirusTotalAnalysis>(
      `${VIRUSTOTAL_API_BASE}/analyses/${analysisId}`,
      {
        method: 'GET'
      },
      apiKey
    );

    const status = analysis.data?.attributes?.status;

    console.log(`[analyze] VirusTotal status: ${status || 'unknown'}.`);

    if (status === 'completed') {
      console.log('[analyze] VirusTotal analysis completed.');
      return analysis;
    }

    await Bun.sleep(POLL_INTERVAL_MS);
  }

  throw new Error('VirusTotal analysis did not complete before the timeout.');
};

const analyze = async (url: string): Promise<TAnalyzeResult> => {
  console.log(`[analyze] Starting analysis for URL: ${url}`);
  const apiKey = getApiKey();
  console.log('[analyze] Downloading file.');
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(
      `Failed to download file (${response.status} ${response.statusText}) from ${url}`
    );
  }

  const fileBuffer = await response.arrayBuffer();
  const fileName = getFileNameFromUrl(url);
  const localSha256 = await getSha256(fileBuffer);
  console.log(
    `[analyze] Download complete: ${fileName} (${fileBuffer.byteLength} bytes).`
  );
  console.log(`[analyze] Local SHA-256: ${localSha256}`);
  const analysisId = await submitFileForAnalysis(fileName, fileBuffer, apiKey);
  const analysis = await pollAnalysis(analysisId, apiKey);

  const stats = analysis.data?.attributes?.stats;
  const results = analysis.data?.attributes?.results || {};
  const maliciousCount = stats?.malicious ?? 0;
  const suspiciousCount = stats?.suspicious ?? 0;
  const detectionCount = maliciousCount + suspiciousCount;

  console.log(
    `[analyze] Analysis stats: malicious=${maliciousCount}, suspicious=${suspiciousCount}, harmless=${stats?.harmless ?? 0}, undetected=${stats?.undetected ?? 0}.`
  );

  const analysisUrl = getAnalysisUrl(
    analysisId,
    analysis.data?.attributes?.sha256 || localSha256
  );

  console.log(`[analyze] Full VirusTotal report: ${analysisUrl}`);

  if (detectionCount > 0) {
    const detectedBy = Object.values(results)
      .filter(
        (result) =>
          result.category === 'malicious' || result.category === 'suspicious'
      )
      .map(
        (result) => `${result.engine_name}: ${result.result || result.category}`
      )
      .join(', ');

    throw new Error(
      `VirusTotal detected ${detectionCount} issue(s) for ${fileName}. ${detectedBy}`.trim()
    );
  }

  console.log(`[analyze] No detections found for ${fileName}.`);

  return {
    analysisId,
    analysisUrl,
    fileName,
    sha256: analysis.data?.attributes?.sha256 || localSha256,
    stats: stats || {}
  };
};

if (import.meta.main) {
  const urlFlagIndex = Bun.argv.indexOf('--url');
  const url = urlFlagIndex >= 0 ? Bun.argv[urlFlagIndex + 1] : undefined;
  const versionFileArgs = getVersionFilePathsFromArgs(Bun.argv.slice(2));

  if (url) {
    const result = await analyze(url);

    console.log(`VirusTotal analysis passed for ${result.fileName}.`);
  } else if (versionFileArgs.length > 0) {
    const results = await analyzeVersionFiles(versionFileArgs);

    console.log(
      `[analyze] Completed VirusTotal analysis for ${results.length} version file(s).`
    );
  } else {
    throw new Error(
      'Usage: bun scripts/analyze.ts --url <file-url> | bun scripts/analyze.ts <version-file> [more-version-files...]'
    );
  }
}

export { analyze };
