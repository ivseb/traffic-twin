// REST implementation of the relative dates (/api/v1/date-offsets) and of the third-party pages of the mocks
// (/api/v1/mocks/pages).

import type { DateOffset, DateOffsetsApi } from '../dates';
import type { MockPages, ThirdPartyPage } from '../pages';
import type { Http } from './http';

export interface WireDateOffset {
  group: string;
  field: string;
  min: string;
  max: string;
  updated_by?: string;
  updated_at?: string;
}

export interface WireMockPages {
  group: string;
  pages?: ThirdPartyPage[] | null;
  updated_by?: string;
  updated_at?: string;
}

const enc = encodeURIComponent;

export function mapDateOffset(w: WireDateOffset): DateOffset {
  return { group: w.group ?? '', field: w.field, min: w.min, max: w.max, updatedBy: w.updated_by ?? '', updatedAt: w.updated_at ?? '' };
}

export function mapPages(w: WireMockPages): MockPages {
  return {
    group: w.group ?? '',
    pages: (w.pages ?? []).map((p) => ({ ...p, buttons: p.buttons ?? [] })),
    updatedBy: w.updated_by || undefined,
    updatedAt: w.updated_at || undefined,
  };
}

export function createDateOffsetsRest(http: Http): DateOffsetsApi {
  return {
    async list(group) {
      const r = await http.get<{ offsets: WireDateOffset[] }>('/api/v1/date-offsets', { query: { group } });
      return (r?.offsets ?? []).map(mapDateOffset);
    },
    async set(group, field, min, max) {
      return mapDateOffset(await http.put<WireDateOffset>(`/api/v1/date-offsets/${enc(field)}`, { group, min, max }));
    },
    async remove(group, field) {
      await http.del<void>(`/api/v1/date-offsets/${enc(field)}`, { query: { group } });
    },
  };
}

export function createPagesRest(http: Http) {
  return {
    async pages(group: string): Promise<MockPages> {
      return mapPages(await http.get<WireMockPages>('/api/v1/mocks/pages', { query: { group } }));
    },
    async setPages(group: string, pages: ThirdPartyPage[]): Promise<MockPages> {
      return mapPages(await http.put<WireMockPages>('/api/v1/mocks/pages', { group, pages }));
    },
  };
}
