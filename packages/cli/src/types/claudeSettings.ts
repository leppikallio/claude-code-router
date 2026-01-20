export interface ClaudeSettingsFlag {
  env: {
    ANTHROPIC_AUTH_TOKEN?: any;
    ANTHROPIC_API_KEY: string;
    ANTHROPIC_BASE_URL: string;
    NO_PROXY: string;
    DISABLE_TELEMETRY: string;
    DISABLE_COST_WARNINGS: string;
    API_TIMEOUT_MS: string;
    CLAUDE_CODE_USE_BEDROCK?: undefined;
    [key: string]: any;
  };
  statusLine?: {
    type: string;
    command: string;
    padding: number;
  };
}
