
// Static replacement for AI Service to allow easy Vercel deployment without API Keys

export const generateRemediationAdvice = async (vulnerabilityTitle: string, userContext: string): Promise<string> => {
  // Simulate network delay for realism
  await new Promise(resolve => setTimeout(resolve, 1500));

  return `### AI Security Analysis (Offline Mode)

**Vulnerability:** ${vulnerabilityTitle}

**Remediation Strategy:**
1. **Input Validation:** Ensure all user inputs are validated against a strict allowlist.
2. **Parameterized Queries:** Never concatenate strings for database queries; use prepared statements.
3. **Least Privilege:** Ensure the database user has only the permissions necessary for the task.

*Note: Live AI analysis is currently disabled for this static deployment. Please configure the API Key in a local environment for custom advice.*`;
};
