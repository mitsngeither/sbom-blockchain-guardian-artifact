
export interface SuspiciousCommandPattern {
    id: string;
    description: string;
    pattern: RegExp;
}


export const SUSPICIOUS_COMMAND_PATTERNS: SuspiciousCommandPattern[] = [
    {
        id: "remote-script-pipe-to-shell",
        description: "Downloads remote content and pipes it directly to a shell",
        pattern: /\b(curl|wget)\b[^|;&]*\|\s*(sh|bash|zsh)\b/i,
    },
    {
        id: "powershell-execution",
        description: "Executes a PowerShell command",
        pattern: /\b(powershell|pwsh)(?:\.exe)?\b/i,
    },
    {
        id: "encoded-powershell-command",
        description: "Executes an encoded PowerShell command",
        pattern:
            /\b(powershell|pwsh)(?:\.exe)?\b.*(?:-enc|-encodedcommand)\b/i,
    },
    {
        id: "base64-decoding",
        description: "Decodes Base64 content",
        pattern:
            /\bbase64\b.*(?:--decode|-d)\b|\b(?:atob|Buffer\.from)\s*\(/i,
    },
    {
        id: "dynamic-code-execution",
        description: "Uses eval or Function for dynamic code execution",
        pattern: /\b(?:eval|Function)\s*\(/i,
    },
    {
        id: "node-child-process",
        description: "Uses Node.js child_process APIs",
        pattern:
            /\bchild_process\b|\brequire\s*\(\s*["']child_process["']\s*\)/i,
    },
    {
        id: "shell-execution-api",
        description: "Uses a shell execution API",
        pattern:
            /\b(?:exec|execSync|spawn|spawnSync)\s*\(/i,
    },
    {
        id: "destructive-file-removal",
        description: "Recursively or forcibly removes files",
        pattern: /\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-rf|-fr)\b/i,
    },
    {
        id: "permission-change",
        description: "Changes a file to executable",
        pattern: /\bchmod\s+(?:\+x|[0-7]*7[0-7]{2})\b/i,
    },
    {
        id: "direct-ip-download",
        description: "Connects directly to an IP address",
        pattern:
            /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/i,
    },
    {
        id: "sensitive-file-access",
        description: "Accesses potentially sensitive system files",
        // (?<!process): `process.env` is not file access; ".env" files still match.
        pattern:
            /(?:\/etc\/passwd|\/etc\/shadow|\.ssh\/|id_rsa|\.npmrc|(?<!process)\.env)\b/i,
    },
    {
        id: "environment-variable-exfiltration",
        description: "May send environment variables to a remote endpoint",
        // Network and env access in either order, via shell (curl/wget) or Node APIs.
        pattern:
            /(?=[\s\S]*(?:\b(?:curl|wget|fetch|XMLHttpRequest|WebSocket)\b|\.(?:get|request)\s*\())(?=[\s\S]*(?:process\.env|\benv\b|\bprintenv\b))/i,
    },
    {
        id: "network-tool-usage",
        description: "Uses a low-level networking tool",
        pattern: /\b(?:nc|netcat|ncat|socat)\b/i,
    },
];