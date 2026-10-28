// Server features the console learns about by trying them (a 404/405 on the route): the buttons that need them stay
// visible until the server says it does not have them, then they explain and step aside. Per tab, never stored.
import { ApiError } from './api';

export const features = $state<{ withdraw: boolean; retire: boolean }>({ withdraw: true, retire: true });

/** The server has no such route (the REST adapter turns 404/405 of the route into `unsupported`). */
export const isUnsupported = (e: unknown): boolean => e instanceof ApiError && e.code === 'unsupported';
