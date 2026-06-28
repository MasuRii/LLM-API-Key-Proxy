import { describe, it, expect, vi, beforeEach } from "vitest"
import { setApiKey, setBaseUrl } from "./client"
import * as configApi from "./config"

interface CredentialBatchDeleteRequest {
  items: Array<
    | { type: "api_key"; provider: string; key_name: string }
    | { type: "oauth"; provider: string; filename: string }
  >
  dry_run: boolean
  confirm: boolean
}

interface CredentialBatchDeleteResponse {
  dry_run: boolean
  candidates: Array<Record<string, unknown>>
  deleted: Array<Record<string, unknown>>
  errors: Array<Record<string, unknown>>
}

type BatchDeleteCredentials = (
  request: CredentialBatchDeleteRequest
) => Promise<CredentialBatchDeleteResponse>

const getCredentialsWithFilters = configApi.getCredentials as (
  filters?: { status?: string[] }
) => ReturnType<typeof configApi.getCredentials>

describe("credential admin API client", () => {
  beforeEach(() => {
    setBaseUrl("https://proxy.test")
    setApiKey("admin-token")
  })

  it("requests credentials with repeated status filters for user-selectable cleanup states", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ api_keys: {}, oauth: {} }), { status: 200 })
    )
    vi.stubGlobal("fetch", fetchMock)

    await getCredentialsWithFilters({ status: ["needs_reauth", "cooldown", "exhausted"] })

    expect(fetchMock).toHaveBeenCalledWith(
      "https://proxy.test/v1/admin/credentials?status=needs_reauth&status=cooldown&status=exhausted",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer admin-token" }),
      })
    )
  })

  it("posts the batch delete dry-run payload and returns per-item candidates, deleted rows, and errors", async () => {
    const responsePayload = {
      dry_run: true,
      candidates: [
        {
          type: "api_key",
          provider: "openai",
          identifier: "OPENAI_API_KEY",
          key_name: "OPENAI_API_KEY",
        },
        {
          type: "oauth",
          provider: "codex",
          identifier: "codex_oauth_1.json",
          filename: "codex_oauth_1.json",
        },
      ],
      deleted: [],
      errors: [
        {
          type: "oauth",
          provider: "gemini_cli",
          identifier: "gemini_cli_oauth_99.json",
          status_code: 404,
          detail: "OAuth credential not found",
        },
      ],
    }
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(responsePayload), { status: 200 })
    )
    vi.stubGlobal("fetch", fetchMock)
    const request: CredentialBatchDeleteRequest = {
      dry_run: true,
      confirm: false,
      items: [
        { type: "api_key", provider: "openai", key_name: "OPENAI_API_KEY" },
        { type: "oauth", provider: "codex", filename: "codex_oauth_1.json" },
        { type: "oauth", provider: "gemini_cli", filename: "gemini_cli_oauth_99.json" },
      ],
    }

    const batchDeleteCredentials = (
      configApi as typeof configApi & { batchDeleteCredentials?: BatchDeleteCredentials }
    ).batchDeleteCredentials

    expect(batchDeleteCredentials).toEqual(expect.any(Function))
    if (!batchDeleteCredentials) return

    const result = await batchDeleteCredentials(request)

    expect(fetchMock).toHaveBeenCalledWith(
      "https://proxy.test/v1/admin/credentials/batch-delete",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(request),
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          Authorization: "Bearer admin-token",
        }),
      })
    )
    expect(result).toEqual(responsePayload)
  })
})
