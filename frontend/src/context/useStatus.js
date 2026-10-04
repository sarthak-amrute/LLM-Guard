import { useContext } from 'react';
import { StatusContext } from './StatusContextInstance';

export function useStatus() {
  return useContext(StatusContext);
}
