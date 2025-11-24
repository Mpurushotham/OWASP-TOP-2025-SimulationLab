import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });

export const generateRemediationAdvice = async (vulnerabilityTitle: string, userContext: string): Promise<string> => {
  if (!process.env.API_KEY) {
    return "API Key not configured. Please set process.env.API_KEY to use the AI Assistant.";
  }

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: `Provide a concise, technical code remediation strategy for the OWASP vulnerability: "${vulnerabilityTitle}". 
      Context: The user asks "${userContext}". 
      Focus on a React/Node.js stack. Keep it under 150 words. Use Markdown.`
    });
    
    return response.text || "No advice generated.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return "Unable to connect to AI security consultant at this time.";
  }
};