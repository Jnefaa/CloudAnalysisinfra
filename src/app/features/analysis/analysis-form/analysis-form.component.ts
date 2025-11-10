import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { ThreatAnalysisService } from '../../../core/services/threat-analysis.service';
import { AnalysisResponse } from '../../../core/models/analysis.model';

@Component({
  selector: 'app-analysis-form',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  template: `
    <div class="analysis-container">
      <div class="analysis-card">
        <div class="card-header">
          <h2>🔍 Threat Analysis</h2>
          <p>Analyze IPs, URLs, Domains, File Hashes, or Upload Files</p>
        </div>

        <form [formGroup]="analysisForm" (ngSubmit)="onSubmit()" class="analysis-form">
          <!-- Analysis Type Selection -->
          <div class="form-group">
            <label>Analysis Type</label>
            <div class="radio-group">
              <label class="radio-label">
                <input 
                  type="radio" 
                  name="analysisType" 
                  value="text"
                  (change)="onAnalysisTypeChange('text')"
                  [checked]="analysisType() === 'text'"
                />
                <span>Text Input (IP/URL/Domain/Hash)</span>
              </label>
              <label class="radio-label">
                <input 
                  type="radio" 
                  name="analysisType" 
                  value="file"
                  (change)="onAnalysisTypeChange('file')"
                  [checked]="analysisType() === 'file'"
                />
                <span>File Upload</span>
              </label>
            </div>
          </div>

          <!-- Text Input Section -->
          <div *ngIf="analysisType() === 'text'" class="form-group">
            <label for="inputValue">Input Value</label>
            <textarea
              id="inputValue"
              formControlName="input_value"
              class="form-control textarea"
              placeholder="Enter IP address, URL, domain, or file hash&#10;Examples:&#10;  • 8.8.8.8&#10;  • https://example.com&#10;  • malicious-domain.com&#10;  • 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
              rows="4"
            ></textarea>
            <div class="error-message" *ngIf="analysisForm.get('input_value')?.invalid && analysisForm.get('input_value')?.touched">
              Input value is required
            </div>
          </div>

          <!-- File Upload Section -->
          <div *ngIf="analysisType() === 'file'" class="form-group">
            <label for="fileInput">Upload File</label>
            <div class="file-upload-area" 
                 [class.has-file]="selectedFile()"
                 (click)="fileInput.click()">
              <input 
                #fileInput
                type="file" 
                id="fileInput"
                (change)="onFileSelected($event)"
                style="display: none"
              />
              <div class="file-upload-content">
                <span class="upload-icon" *ngIf="!selectedFile()">📁</span>
                <span class="upload-icon" *ngIf="selectedFile()">✅</span>
                <p *ngIf="!selectedFile()">Click to select a file</p>
                <p *ngIf="selectedFile()" class="file-name">{{ selectedFile()?.name }}</p>
              </div>
            </div>
          </div>

          <!-- Engine Selection -->
          <div class="form-group">
            <label>Analysis Engine</label>
            <div class="radio-group">
              <label class="radio-label">
                <input 
                  type="radio" 
                  formControlName="engine_choice" 
                  value="vt"
                />
                <span>VirusTotal</span>
              </label>
              <label class="radio-label">
                <input 
                  type="radio" 
                  formControlName="engine_choice" 
                  value="otx"
                />
                <span>AlienVault OTX</span>
              </label>
            </div>
          </div>

          <!-- Error Message -->
          <div class="alert alert-error" *ngIf="errorMessage()">
            <strong>Error:</strong> {{ errorMessage() }}
          </div>

          <!-- Submit Button -->
          <button 
            type="submit" 
            class="btn-primary btn-large"
            [disabled]="!isFormValid() || loading()"
          >
            <span *ngIf="!loading()">🚀 Analyze Threat</span>
            <span *ngIf="loading()">⏳ Analyzing...</span>
          </button>
        </form>
      </div>

      <!-- Results Section -->
      <div class="results-section" *ngIf="analysisResult()">
        <div class="results-card">
          <div class="results-header">
            <h3>Analysis Results</h3>
            <span class="severity-badge" [class]="'severity-' + analysisResult()!.severity.toLowerCase()">
              {{ analysisResult()!.severity }}
            </span>
          </div>

          <div class="results-grid">
            <div class="result-item">
              <span class="label">Input Type:</span>
              <span class="value">{{ analysisResult()!.input_type }}</span>
            </div>
            <div class="result-item">
              <span class="label">Input Value:</span>
              <span class="value">{{ analysisResult()!.input_value }}</span>
            </div>
            <div class="result-item">
              <span class="label">Engine Used:</span>
              <span class="value">{{ analysisResult()!.engine_used.toUpperCase() }}</span>
            </div>
            <div class="result-item">
              <span class="label">Threat Score:</span>
              <span class="value threat-score">{{ analysisResult()!.threat_score }}</span>
            </div>
            <div class="result-item">
              <span class="label">Status:</span>
              <span class="value">{{ analysisResult()!.status }}</span>
            </div>
            <div class="result-item">
              <span class="label">Analyzed At:</span>
              <span class="value">{{ analysisResult()!.created_at | date:'medium' }}</span>
            </div>
            <div class="result-item">
              <span class="label">Analyst:</span>
              <span class="value">{{ analysisResult()!.analyst.username }} ({{ analysisResult()!.analyst.role }})</span>
            </div>
          </div>

          <!-- Raw Data Section -->
          <div class="raw-data-section">
            <button 
              type="button"
              class="btn-secondary"
              (click)="showRawData.set(!showRawData())"
            >
              {{ showRawData() ? '▼' : '▶' }} View Raw Data
            </button>
            
            <div class="raw-data" *ngIf="showRawData()">
              <pre>{{ analysisResult() | json }}</pre>
            </div>
          </div>

          <button type="button" class="btn-secondary" (click)="resetForm()">
            🔄 New Analysis
          </button>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .analysis-container {
      max-width: 900px;
      margin: 0 auto;
      padding: 20px;
    }

    .analysis-card, .results-card {
      background: white;
      border-radius: 12px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
      padding: 32px;
      margin-bottom: 24px;
    }

    .card-header {
      margin-bottom: 32px;
    }

    .card-header h2 {
      font-size: 24px;
      font-weight: 700;
      color: #1a202c;
      margin-bottom: 8px;
    }

    .card-header p {
      color: #718096;
      font-size: 14px;
    }

    .analysis-form {
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    .form-group {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    label {
      font-weight: 600;
      color: #2d3748;
      font-size: 14px;
    }

    .form-control {
      padding: 12px 16px;
      border: 2px solid #e2e8f0;
      border-radius: 8px;
      font-size: 14px;
      transition: all 0.2s;
      font-family: inherit;
    }

    .textarea {
      resize: vertical;
      min-height: 100px;
    }

    .form-control:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }

    .radio-group {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }

    .radio-label {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 12px 16px;
      border: 2px solid #e2e8f0;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .radio-label:hover {
      border-color: #cbd5e0;
    }

    .radio-label input[type="radio"] {
      cursor: pointer;
    }

    .radio-label input[type="radio"]:checked + span {
      font-weight: 600;
      color: #667eea;
    }

    .file-upload-area {
      border: 2px dashed #e2e8f0;
      border-radius: 8px;
      padding: 40px;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s;
    }

    .file-upload-area:hover {
      border-color: #667eea;
      background-color: #f7fafc;
    }

    .file-upload-area.has-file {
      border-color: #48bb78;
      background-color: #f0fff4;
    }

    .file-upload-content {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
    }

    .upload-icon {
      font-size: 48px;
    }

    .file-name {
      font-weight: 600;
      color: #2d3748;
    }

    .error-message {
      color: #f56565;
      font-size: 12px;
    }

    .alert {
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
    }

    .alert-error {
      background-color: #fed7d7;
      color: #c53030;
      border: 1px solid #fc8181;
    }

    .btn-primary, .btn-secondary {
      padding: 12px 24px;
      border: none;
      border-radius: 8px;
      font-weight: 600;
      font-size: 16px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .btn-primary {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
    }

    .btn-primary:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
    }

    .btn-primary:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    .btn-large {
      padding: 16px 32px;
      font-size: 18px;
    }

    .btn-secondary {
      background: white;
      color: #667eea;
      border: 2px solid #667eea;
    }

    .btn-secondary:hover {
      background: #f7fafc;
    }

    .results-section {
      animation: slideIn 0.3s ease-out;
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateY(20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .results-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 2px solid #e2e8f0;
    }

    .results-header h3 {
      font-size: 20px;
      font-weight: 700;
      color: #1a202c;
    }

    .severity-badge {
      padding: 6px 16px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .severity-low {
      background-color: #c6f6d5;
      color: #22543d;
    }

    .severity-medium {
      background-color: #feebc8;
      color: #7c2d12;
    }

    .severity-high {
      background-color: #fed7d7;
      color: #742a2a;
    }

    .severity-critical {
      background-color: #fed7e2;
      color: #702459;
    }

    .results-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .result-item {
      display: flex;
      flex-direction: column;
      gap: 4px;
      padding: 12px;
      background-color: #f7fafc;
      border-radius: 8px;
    }

    .result-item .label {
      font-size: 12px;
      color: #718096;
      font-weight: 600;
      text-transform: uppercase;
    }

    .result-item .value {
      font-size: 14px;
      color: #2d3748;
      font-weight: 500;
      word-break: break-all;
    }

    .threat-score {
      font-size: 18px;
      font-weight: 700;
      color: #667eea;
    }

    .raw-data-section {
      margin-top: 24px;
      padding-top: 24px;
      border-top: 2px solid #e2e8f0;
    }

    .raw-data {
      margin-top: 16px;
      background-color: #1a202c;
      padding: 16px;
      border-radius: 8px;
      overflow-x: auto;
    }

    .raw-data pre {
      color: #68d391;
      font-size: 12px;
      margin: 0;
      font-family: 'Courier New', monospace;
    }
  `]
})
export class AnalysisFormComponent {
  private fb = inject(FormBuilder);
  private threatAnalysisService = inject(ThreatAnalysisService);

  analysisForm: FormGroup;
  analysisType = signal<'text' | 'file'>('text');
  selectedFile = signal<File | null>(null);
  loading = signal(false);
  errorMessage = signal('');
  analysisResult = signal<AnalysisResponse | null>(null);
  showRawData = signal(false);

  constructor() {
    this.analysisForm = this.fb.group({
      input_value: ['', Validators.required],
      engine_choice: ['vt', Validators.required]
    });
  }

  onAnalysisTypeChange(type: 'text' | 'file'): void {
    this.analysisType.set(type);
    this.selectedFile.set(null);
    this.analysisForm.patchValue({ input_value: '' });
    this.errorMessage.set('');
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.selectedFile.set(input.files[0]);
      this.errorMessage.set('');
    }
  }

  isFormValid(): boolean {
    if (this.analysisType() === 'file') {
      return !!this.selectedFile() && !!this.analysisForm.get('engine_choice')?.value;
    }
    return this.analysisForm.valid;
  }

  onSubmit(): void {
    if (!this.isFormValid()) {
      return;
    }

    this.loading.set(true);
    this.errorMessage.set('');
    this.analysisResult.set(null);

    const request = {
      input_value: this.analysisForm.get('input_value')?.value || '',
      engine_choice: this.analysisForm.get('engine_choice')?.value as 'vt' | 'otx',
      file: this.selectedFile() || undefined
    };

    this.threatAnalysisService.analyzeInput(request).subscribe({
      next: (result) => {
        this.analysisResult.set(result);
        this.loading.set(false);
      },
      error: (error) => {
        this.errorMessage.set(error.error?.detail || 'Analysis failed. Please try again.');
        this.loading.set(false);
      }
    });
  }

  resetForm(): void {
    this.analysisForm.reset({ engine_choice: 'vt' });
    this.selectedFile.set(null);
    this.analysisResult.set(null);
    this.errorMessage.set('');
    this.showRawData.set(false);
    this.analysisType.set('text');
  }
}