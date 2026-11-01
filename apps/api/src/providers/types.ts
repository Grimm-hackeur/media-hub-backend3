export class ProviderError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) { super(message); }
}

export interface MediaDownload { label: string; format: string; quality: string | null; url: string }
export interface MediaResult { platform: string; title: string; thumbnail: string | null; author: string | null; downloads: MediaDownload[] }
export type MediaToolId = 'tiktok' | 'instagram' | 'facebook';

export interface MediaProvider {
  readonly id: MediaToolId;
  readonly label: string;
  /** Hosts a link must belong to (exact or sub-domain). */
  readonly hosts: string[];
  /** False when the service cannot work (missing configuration or no documented integration yet). */
  readonly configured: boolean;
  /** Human reason shown to admins/users when `configured` is false. */
  readonly notConfiguredReason?: string;
  analyze(url: string): Promise<MediaResult>;
}

export type MusicType = 'song' | 'album' | 'artist';
export interface MusicItem {
  id: string; type: MusicType; title: string; artist: string | null; album: string | null;
  artwork: string | null; previewUrl: string | null; url: string | null; durationMs: number | null; releaseDate: string | null; genre: string | null;
}
export interface MusicSearchResult { items: MusicItem[]; page: number; pageSize: number; hasMore: boolean }
export interface MusicProvider {
  readonly id: string;
  readonly label: string;
  readonly configured: boolean;
  readonly notConfiguredReason?: string;
  search(q: { query: string; type: MusicType; page: number; pageSize: number }): Promise<MusicSearchResult>;
}
