import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../../environments/environment';
import { AnalysisRequest, AnalysisResponse } from '../models/analysis.model';

@Injectable({
  providedIn: 'root'
})
export class ThreatAnalysisService {
  private http = inject(HttpClient);

  analyzeInput(request: AnalysisRequest): Observable<AnalysisResponse> {
    if (request.file) {
      return this.analyzeFile(request.file, request.engine_choice);
    } else {
      return this.analyzeText(request.input_value, request.engine_choice);
    }
  }

  private analyzeText(inputValue: string, engineChoice: 'vt' | 'otx'): Observable<AnalysisResponse> {
    return this.http.post<AnalysisResponse>(`${environment.apiUrl}/analyze/`, {
      input_value: inputValue,
      engine_choice: engineChoice
    });
  }

  private analyzeFile(file: File, engineChoice: 'vt' | 'otx'): Observable<AnalysisResponse> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('engine_choice', engineChoice);

    return this.http.post<AnalysisResponse>(`${environment.apiUrl}/analyze/`, formData);
  }
}