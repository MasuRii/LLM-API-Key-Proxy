import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { Credentials } from "./Credentials"
import type { CredentialSummary } from "@/api/config"
import * as configApi from "@/api/config"

interface CredentialBatchDeleteResponse {
  dry_run: boolean
  candidates: Array<Record<string, unknown>>
  deleted: Array<Record<string, unknown>>
  errors: Array<Record<string, unknown>>
}

type ConfigApiWithBatchDelete = typeof configApi & {
  batchDeleteCredentials?: ReturnType<typeof vi.fn<() => Promise<CredentialBatchDeleteResponse>>>
}

const configApiWithBatchDelete = configApi as ConfigApiWithBatchDelete

vi.mock("@/api/config", async () => {
  const actual = await vi.importActual<typeof import("@/api/config")>("@/api/config")
  return {
    ...actual,
    getCredentials: vi.fn(),
    deleteApiKey: vi.fn(),
    deleteOAuthCredential: vi.fn(),
    batchDeleteCredentials: vi.fn(),
  }
})

vi.mock("@/api/oauth", () => ({
  getOAuthProviders: vi.fn().mockResolvedValue({ providers: [] }),
  startOAuthFlow: vi.fn(),
  getOAuthStatus: vi.fn(),
  submitOAuthCode: vi.fn(),
}))

const credentialSummary: CredentialSummary = {
  api_keys: {
    openai: [
      { provider: "openai", key_name: "OPENAI_API_KEY", masked_value: "sk-o...1234" },
    ],
  },
  oauth: {
    codex: [
      {
        provider: "codex",
        filename: "codex_oauth_1.json",
        number: 1,
        email: "reauth@example.com",
        status: "needs_reauth",
      },
      {
        provider: "codex",
        filename: "codex_oauth_2.json",
        number: 2,
        email: "cooldown@example.com",
        status: "cooldown",
      },
      {
        provider: "codex",
        filename: "codex_oauth_3.json",
        number: 3,
        email: "exhausted@example.com",
        status: "exhausted",
      },
      {
        provider: "codex",
        filename: "codex_oauth_4.json",
        number: 4,
        email: "active@example.com",
        status: "active",
      },
    ],
  },
}

describe("Credentials deletion UX", () => {
  beforeEach(() => {
    vi.mocked(configApi.getCredentials).mockResolvedValue(credentialSummary)
    vi.mocked(configApi.deleteApiKey).mockResolvedValue(undefined)
    vi.mocked(configApi.deleteOAuthCredential).mockResolvedValue(undefined)
    configApiWithBatchDelete.batchDeleteCredentials?.mockResolvedValue({
      dry_run: true,
      candidates: [],
      deleted: [],
      errors: [],
    })
    vi.stubGlobal("confirm", vi.fn())
  })

  it("opens a safer single-delete dialog instead of the browser confirm prompt", async () => {
    const user = userEvent.setup()
    render(<Credentials />)
    await screen.findByText("OPENAI_API_KEY")

    const apiKeyRow = screen.getByText("OPENAI_API_KEY").closest("div")!.parentElement!
    await user.click(within(apiKeyRow).getByRole("button"))

    expect(window.confirm).not.toHaveBeenCalled()
    expect(screen.getByRole("dialog", { name: /delete api key/i })).toBeInTheDocument()
    expect(screen.getByText("OPENAI_API_KEY")).toBeInTheDocument()
    expect(screen.getByText("openai")).toBeInTheDocument()
    expect(screen.getByText("sk-o...1234")).toBeInTheDocument()
  })

  it("lets users select cleanup statuses and fetches only needs_reauth, cooldown, and exhausted credentials", async () => {
    const user = userEvent.setup()
    render(<Credentials />)
    await screen.findByText("reauth@example.com")

    const cleanupButton = screen.queryByRole("button", { name: /cleanup/i })
    expect(cleanupButton).toBeInTheDocument()
    if (!cleanupButton) return

    await user.click(cleanupButton)

    const cleanupDialog = screen.getByRole("dialog", { name: /cleanup credentials/i })
    for (const status of ["needs_reauth", "cooldown", "exhausted"]) {
      const checkbox = within(cleanupDialog).getByRole("checkbox", { name: new RegExp(status, "i") })
      expect(checkbox).toBeChecked()
    }

    await user.click(within(cleanupDialog).getByRole("button", { name: /preview/i }))

    expect(configApi.getCredentials).toHaveBeenLastCalledWith({
      status: ["needs_reauth", "cooldown", "exhausted"],
    })
  })

  it("multi-selects credentials, previews a batch dry-run, and renders per-item results before confirmed deletion", async () => {
    const user = userEvent.setup()
    const batchDeleteCredentials = configApiWithBatchDelete.batchDeleteCredentials
    expect(batchDeleteCredentials).toEqual(expect.any(Function))
    if (!batchDeleteCredentials) return

    batchDeleteCredentials
      .mockResolvedValueOnce({
        dry_run: true,
        candidates: [
          {
            type: "oauth",
            provider: "codex",
            identifier: "codex_oauth_1.json",
            filename: "codex_oauth_1.json",
          },
          {
            type: "oauth",
            provider: "codex",
            identifier: "codex_oauth_2.json",
            filename: "codex_oauth_2.json",
          },
        ],
        deleted: [],
        errors: [],
      })
      .mockResolvedValueOnce({
        dry_run: false,
        candidates: [],
        deleted: [
          {
            type: "oauth",
            provider: "codex",
            identifier: "codex_oauth_1.json",
            filename: "codex_oauth_1.json",
            removed_from_proxy: true,
          },
          {
            type: "oauth",
            provider: "codex",
            identifier: "codex_oauth_2.json",
            filename: "codex_oauth_2.json",
            removed_from_proxy: false,
          },
        ],
        errors: [
          {
            type: "oauth",
            provider: "codex",
            identifier: "codex_oauth_3.json",
            status_code: 404,
            detail: "OAuth credential not found",
          },
        ],
      })
    render(<Credentials />)
    await screen.findByText("reauth@example.com")

    const firstCredentialCheckbox = screen.queryByRole("checkbox", { name: /select codex_oauth_1\.json/i })
    const secondCredentialCheckbox = screen.queryByRole("checkbox", { name: /select codex_oauth_2\.json/i })
    expect(firstCredentialCheckbox).toBeInTheDocument()
    expect(secondCredentialCheckbox).toBeInTheDocument()
    if (!firstCredentialCheckbox || !secondCredentialCheckbox) return

    await user.click(firstCredentialCheckbox)
    await user.click(secondCredentialCheckbox)
    await user.click(screen.getByRole("button", { name: /delete selected/i }))

    expect(batchDeleteCredentials).toHaveBeenCalledWith({
      dry_run: true,
      confirm: false,
      items: [
        { type: "oauth", provider: "codex", filename: "codex_oauth_1.json" },
        { type: "oauth", provider: "codex", filename: "codex_oauth_2.json" },
      ],
    })
    expect(screen.getByText(/2 credentials ready to delete/i)).toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: /confirm delete/i }))

    await waitFor(() => {
      expect(batchDeleteCredentials).toHaveBeenLastCalledWith({
        dry_run: false,
        confirm: true,
        items: [
          { type: "oauth", provider: "codex", filename: "codex_oauth_1.json" },
          { type: "oauth", provider: "codex", filename: "codex_oauth_2.json" },
        ],
      })
    })
    expect(screen.getByText(/codex_oauth_1\.json.*removed from running proxy/i)).toBeInTheDocument()
    expect(screen.getByText(/codex_oauth_2\.json.*restart may be needed/i)).toBeInTheDocument()
    expect(screen.getByText(/codex_oauth_3\.json.*OAuth credential not found/i)).toBeInTheDocument()
  })
})
