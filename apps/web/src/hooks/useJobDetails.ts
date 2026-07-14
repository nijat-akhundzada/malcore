import { useEffect, useReducer, useState } from 'react';
import { getJobResult } from '../services/api';
import { JobStatusResponse } from '../types';
import { isTerminalStatus } from '../utils/analysis';

const DEFAULT_POLL_INTERVAL_MS = 1500;

interface UseJobDetailsOptions {
  pollUntilTerminal?: boolean;
  pollIntervalMs?: number;
}

export const useJobDetails = (
  jobId: string,
  options: UseJobDetailsOptions = {}
) => {
  const { pollUntilTerminal = false, pollIntervalMs = DEFAULT_POLL_INTERVAL_MS } = options;
  const [job, setJob] = useState<JobStatusResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshToken, refresh] = useReducer(value => value + 1, 0);

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    const load = async () => {
      try {
        const nextJob = await getJobResult(jobId);
        if (cancelled) {
          return;
        }

        setJob(nextJob);
        setError(null);
        setIsLoading(false);

        if (pollUntilTerminal && !isTerminalStatus(nextJob.status)) {
          timer = window.setTimeout(load, pollIntervalMs);
        }
      } catch (nextError) {
        if (cancelled) {
          return;
        }

        setError(nextError instanceof Error ? nextError.message : 'Failed to load job');
        setIsLoading(false);
      }
    };

    setIsLoading(true);
    void load();

    return () => {
      cancelled = true;
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    };
  }, [jobId, pollIntervalMs, pollUntilTerminal, refreshToken]);

  return {
    job,
    isLoading,
    error,
    refresh,
  };
};
