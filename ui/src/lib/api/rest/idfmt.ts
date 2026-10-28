// REST implementation of the id formats (admin-api 1.18.0, /api/v1/id-formats) and of the mock identity settings
// (/api/v1/mocks/identity).

import type { IdFormat, IdFormatError, IdFormatPreview, IdFormatsApi, MockIdentity } from '../idfmt';
import type { Http } from './http';

export interface WireIdFormat {
  group: string;
  domain: string;
  format: string;
  capacity_label: string;
  preview?: string[];
  updated_by?: string;
  updated_at?: string;
}

export interface WireIdPreview {
  valid: boolean;
  preview?: string[];
  capacity_label?: string;
  error?: { code: string; at?: number };
}

export interface WireMockIdentity {
  group: string;
  enabled: boolean;
  header?: string;
  claim?: string;
  map?: { hash: string; customer: string }[];
  updated_by?: string;
  updated_at?: string;
}

const enc = encodeURIComponent;

export function mapIdFormat(w: WireIdFormat): IdFormat {
  return {
    group: w.group ?? '',
    domain: w.domain,
    format: w.format,
    capacityLabel: w.capacity_label ?? '',
    preview: w.preview ?? [],
    updatedBy: w.updated_by ?? '',
    updatedAt: w.updated_at ?? '',
  };
}

export function mapIdPreview(w: WireIdPreview): IdFormatPreview {
  if (w.valid) return { valid: true, preview: w.preview ?? [], capacityLabel: w.capacity_label ?? '' };
  return { valid: false, error: { code: (w.error?.code ?? 'bad_char') as IdFormatError['code'], at: w.error?.at ?? 0 } };
}

export function mapIdentity(w: WireMockIdentity): MockIdentity {
  return {
    group: w.group ?? '',
    enabled: !!w.enabled,
    header: w.header ?? '',
    claim: w.claim ?? '',
    map: w.map ?? [],
    updatedBy: w.updated_by || undefined,
    updatedAt: w.updated_at || undefined,
  };
}

export function createIdFormatsRest(http: Http): IdFormatsApi {
  return {
    async list(group) {
      const r = await http.get<{ formats: WireIdFormat[] }>('/api/v1/id-formats', { query: { group } });
      return (r?.formats ?? []).map(mapIdFormat);
    },
    async set(group, domain, format) {
      return mapIdFormat(await http.put<WireIdFormat>(`/api/v1/id-formats/${enc(domain)}`, { group, format }));
    },
    async remove(group, domain) {
      await http.del<void>(`/api/v1/id-formats/${enc(domain)}`, { query: { group } });
    },
    async preview(format, domain) {
      return mapIdPreview(await http.post<WireIdPreview>('/api/v1/id-formats/preview', domain ? { format, domain } : { format }));
    },
  };
}

export function createIdentityRest(http: Http) {
  return {
    async identity(group: string): Promise<MockIdentity> {
      return mapIdentity(await http.get<WireMockIdentity>('/api/v1/mocks/identity', { query: { group } }));
    },
    async setIdentity(group: string, header: string, claim: string): Promise<MockIdentity> {
      return mapIdentity(await http.put<WireMockIdentity>('/api/v1/mocks/identity', { group, header, claim }));
    },
    async addIdentityUser(group: string, user: string, customer: string): Promise<MockIdentity> {
      return mapIdentity(await http.post<WireMockIdentity>('/api/v1/mocks/identity/map', { group, user, customer }));
    },
    async removeIdentityUser(group: string, hash: string): Promise<MockIdentity> {
      return mapIdentity(await http.del<WireMockIdentity>(`/api/v1/mocks/identity/map/${enc(hash)}`, { query: { group } }));
    },
  };
}
