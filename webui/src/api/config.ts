import { apiFetch } from "./client"

export interface ProxyConfig {
  proxy_api_key_set: boolean
  providers: Record<string, ProviderConfig>
  custom_providers: Record<string, string>
  concurrency: Record<string, ConcurrencyConfig>
  rotation_modes: Record<string, string>
  model_filters: Record<string, ModelFilterConfig>
  latest_aliases: Record<string, string>
  strip_suffixes: string[]
  proxy_urls?: {
    default?: string
    providers?: Record<string, string>
    credentials?: Record<string, string>
    credential_providers?: Record<string, string>
  }
}

export interface ProviderConfig {
  api_key_count: number
  oauth_count: number
  has_custom_base: boolean
}

export interface ConcurrencyConfig {
  max: number
  optimal: number
  mode_specific?: Record<string, { max: number; optimal: number }>
}

export interface ModelFilterConfig {
  ignore: string[]
  whitelist: string[]
}

export interface CredentialSummary {
  api_keys: Record<string, ApiKeyInfo[]>
  oauth: Record<string, OAuthInfo[]>
}

export interface ApiKeyInfo {
  key_name: string
  masked_value: string
  provider: string
}

export interface OAuthInfo {
  filename: string
  provider: string
  number?: number
  email?: string
  tier?: string
  status?: string
}

export async function getConfig(): Promise<ProxyConfig> {
  return apiFetch("/v1/admin/config")
}

export async function updateConfig(changes: Record<string, string | null>): Promise<{ updated: string[] }> {
  return apiFetch("/v1/admin/config", {
    method: "PATCH",
    body: JSON.stringify(changes),
  })
}

export interface CredentialBatchDeleteRequest {
  items: Array<
    | { type: "api_key"; provider: string; key_name: string }
    | { type: "oauth"; provider: string; filename: string }
  >
  dry_run: boolean
  confirm: boolean
}

export interface CredentialBatchDeleteResponse {
  dry_run: boolean
  candidates: Array<Record<string, unknown>>
  deleted: Array<Record<string, unknown>>
  errors: Array<Record<string, unknown>>
}

export async function getCredentials(filters?: { status?: string[] }): Promise<CredentialSummary> {
  const params = new URLSearchParams()
  if (filters?.status) {
    for (const s of filters.status) {
      params.append("status", s)
    }
  }
  const query = params.toString()
  return apiFetch(`/v1/admin/credentials${query ? `?${query}` : ""}`)
}

export async function batchDeleteCredentials(
  request: CredentialBatchDeleteRequest
): Promise<CredentialBatchDeleteResponse> {
  return apiFetch("/v1/admin/credentials/batch-delete", {
    method: "POST",
    body: JSON.stringify(request),
  })
}

export async function addApiKey(provider: string, key: string): Promise<{ key_name: string }> {
  return apiFetch("/v1/admin/credentials/api-key", {
    method: "POST",
    body: JSON.stringify({ provider, key }),
  })
}

export async function deleteApiKey(provider: string, keyName: string): Promise<void> {
  await apiFetch(`/v1/admin/credentials/api-key/${encodeURIComponent(provider)}/${encodeURIComponent(keyName)}`, {
    method: "DELETE",
  })
}

export async function deleteOAuthCredential(provider: string, filename: string): Promise<void> {
  await apiFetch(`/v1/admin/credentials/oauth/${encodeURIComponent(provider)}/${encodeURIComponent(filename)}`, {
    method: "DELETE",
  })
}

export async function addCustomProvider(name: string, baseUrl: string, apiKey: string): Promise<void> {
  await apiFetch("/v1/admin/credentials/custom-provider", {
    method: "POST",
    body: JSON.stringify({ name, base_url: baseUrl, api_key: apiKey }),
  })
}

export async function getModelFilters(provider: string): Promise<ModelFilterConfig> {
  return apiFetch(`/v1/admin/config/model-filters/${encodeURIComponent(provider)}`)
}

export async function updateModelFilters(
  provider: string,
  filters: ModelFilterConfig
): Promise<void> {
  await apiFetch(`/v1/admin/config/model-filters/${encodeURIComponent(provider)}`, {
    method: "PUT",
    body: JSON.stringify(filters),
  })
}

export async function reloadProxy(): Promise<{ status: string; message: string }> {
  return apiFetch("/v1/admin/reload", { method: "POST" })
}
