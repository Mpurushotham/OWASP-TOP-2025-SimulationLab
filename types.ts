export enum VulnerabilityID {
  A01 = 'A01',
  A02 = 'A02',
  A03 = 'A03',
  A04 = 'A04',
  A05 = 'A05',
  A06 = 'A06',
  A07 = 'A07',
  A08 = 'A08',
  A09 = 'A09',
  A10 = 'A10',
  // Bonus/Legacy
  A11 = 'A11', // CSRF
  A12 = 'A12', // Clickjacking
}

export interface SimulationStep {
  id: number;
  instruction: string;
  actionLabel: string;
  expectedResult: string;
  isMalicious: boolean;
}

export interface AuditChallenge {
  question: string;
  snippet?: string;
  options: string[];
  correctAnswer: number; // index of the correct option
  explanation: string;
}

export interface CicdSimulation {
  toolName: string;
  stage: 'Build' | 'SAST' | 'SCA' | 'DAST' | 'Deploy';
  failMessage: string;
  passMessage: string;
  description: string;
}

export interface CodeSnippet {
  language: string;
  vulnerable: string;
  secure: string;
  description: string;
}

export interface OwaspItem {
  id: VulnerabilityID;
  title: string;
  shortDescription: string;
  fullDescription: string;
  architecture: string; // Description for the architecture view
  prevention: string[];
  simulationType: 'SQLI' | 'ACCESS_CONTROL' | 'CRYPTO' | 'GENERIC';
  simulationConfig?: {
    scenario: string;
    steps: SimulationStep[];
  };
  audit: AuditChallenge;
  cicd: CicdSimulation;
  codeSnippet?: CodeSnippet; // New field for interactive code
}