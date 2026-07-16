import { AnalyzerFinding, IOCCollection, JobStatusResponse } from '../types';

export interface DisplayFinding extends AnalyzerFinding {
  analyzer: string;
}

export type IOCKey = 'urls' | 'ips' | 'domains';

export interface DisplayIOC {
  type: IOCKey;
  label: string;
  value: string;
}

export interface DisplayYaraHit {
  rule: string;
  severity: string;
  description?: string;
  namespace?: string;
  tags?: string[];
}

const IOC_LABELS: Record<IOCKey, string> = {
  urls: 'URL',
  ips: 'IP',
  domains: 'DOMAIN',
};

export const isTerminalStatus = (status?: string) =>
  status === 'completed' || status === 'failed';

export const formatJobStatus = (status: string) =>
  status
    .split('_')
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');

export const formatBytes = (value?: number | null) => {
  if (typeof value !== 'number') {
    return 'Pending';
  }

  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }

  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
};

export const collectFindings = (job?: JobStatusResponse | null): DisplayFinding[] => {
  const modules = job?.analysis_result?.results || [];

  return modules.flatMap(module =>
    (module.findings || []).map(finding => ({
      ...finding,
      analyzer: module.analyzer,
    }))
  );
};

export const collectIOCs = (job?: JobStatusResponse | null): DisplayIOC[] => {
  const topLevel = collectIOCCollection(job?.analysis_result?.iocs);
  if (topLevel.length > 0) {
    return topLevel;
  }

  const modules = job?.analysis_result?.results || [];
  const seen = new Set<string>();
  const values: DisplayIOC[] = [];

  modules.forEach(module => {
    collectIOCCollection(module.iocs).forEach(ioc => {
      const key = `${ioc.type}:${ioc.value}`;
      if (seen.has(key)) {
        return;
      }

      seen.add(key);
      values.push(ioc);
    });
  });

  return values;
};

export const collectYaraHits = (job?: JobStatusResponse | null): DisplayYaraHit[] => {
  const modules = job?.analysis_result?.results || [];
  const hits: DisplayYaraHit[] = [];

  modules.forEach(module => {
    if (module.analyzer !== 'yara') {
      return;
    }

    const rawMatches = module.metadata?.matches;
    if (!Array.isArray(rawMatches)) {
      return;
    }

    rawMatches.forEach(match => {
      if (!match || typeof match !== 'object') {
        return;
      }

      const record = match as Record<string, unknown>;
      if (typeof record.rule !== 'string' || record.rule.length === 0) {
        return;
      }

      hits.push({
        rule: record.rule,
        severity: typeof record.severity === 'string' ? record.severity : 'high',
        description: typeof record.description === 'string' ? record.description : undefined,
        namespace: typeof record.namespace === 'string' ? record.namespace : undefined,
        tags: Array.isArray(record.tags)
          ? record.tags.filter((tag): tag is string => typeof tag === 'string')
          : undefined,
      });
    });
  });

  return hits;
};

export const collectIOCCollection = (collection?: IOCCollection | null): DisplayIOC[] => {
  if (!collection) {
    return [];
  }

  return (Object.keys(IOC_LABELS) as IOCKey[]).flatMap(type => {
    const values = collection[type];
    if (!Array.isArray(values)) {
      return [];
    }

    return values
      .filter((value): value is string => typeof value === 'string' && value.length > 0)
      .map(value => ({
        type,
        label: IOC_LABELS[type],
        value,
      }));
  });
};
