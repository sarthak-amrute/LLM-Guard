import { createContext } from 'react';

export const StatusContext = createContext({
  status: null,
  loading: true,
  error: null,
  refreshStatus: async () => {},
});
