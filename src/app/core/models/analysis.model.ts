export interface AnalysisRequest {
  input_value: string;
  engine_choice: 'vt' | 'otx';
  file?: File;
}

export interface Analyst {
  id: number;
  username: string;
  role: string;
}

export interface AnalysisResponse {
  id: number;
  analyst: Analyst;
  input_type: string;
  input_value: string;
  engine_used: string;
  vt_data?: any;
  ipinfo_data?: any;
  otx_data?: any;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  threat_score: number;
  status: 'Pending' | 'Completed' | 'Failed';
  created_at: string;
}
