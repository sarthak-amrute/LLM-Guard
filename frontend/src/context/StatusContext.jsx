import { useState, useEffect, useCallback } from 'react';
import { getStatus } from '../services/api';
import { StatusContext } from './StatusContextInstance';

export function StatusProvider({ children }) {
  const [status, setStatus] = useState({
    llmguard: 'checking',
    target_online: false,
    target_mode: 'UNKNOWN',
    scan_status: 'idle',
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStatus = useCallback(async () => {
    try {
      const data = await getStatus();
      setStatus(data);
      setError(null);
    } catch (err) {
      setError(err.message);
      setStatus({
        llmguard: 'offline',
        target_online: false,
        target_mode: 'UNKNOWN',
        scan_status: 'idle',
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    getStatus().then(data => {
      if (active) {
        setStatus(data);
        setLoading(false);
      }
    }).catch(err => {
      if (active) {
        setError(err.message);
        setStatus({
          llmguard: 'offline',
          target_online: false,
          target_mode: 'UNKNOWN',
          scan_status: 'idle',
        });
        setLoading(false);
      }
    });

    const interval = setInterval(fetchStatus, 4000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [fetchStatus]);

  return (
    <StatusContext.Provider value={{ status, loading, error, refreshStatus: fetchStatus }}>
      {children}
    </StatusContext.Provider>
  );
}
