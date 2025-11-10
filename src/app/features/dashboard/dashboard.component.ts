import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AnalysisFormComponent } from '../analysis/analysis-form/analysis-form.component';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, AnalysisFormComponent],
  template: `
    <div class="dashboard">
      <div class="dashboard-header">
        <h1>Welcome to Threat Analysis Dashboard</h1>
        <p>Analyze potential security threats using VirusTotal or AlienVault OTX</p>
      </div>

      <div class="features-grid">
        <div class="feature-card">
          <div class="feature-icon">🌐</div>
          <h3>IP Address Analysis</h3>
          <p>Check IP addresses for malicious activity and reputation</p>
        </div>

        <div class="feature-card">
          <div class="feature-icon">🔗</div>
          <h3>URL Scanning</h3>
          <p>Scan URLs for phishing, malware, and security threats</p>
        </div>

        <div class="feature-card">
          <div class="feature-icon">🏢</div>
          <h3>Domain Lookup</h3>
          <p>Investigate domain reputation and historical data</p>
        </div>

        <div class="feature-card">
          <div class="feature-icon">🔐</div>
          <h3>File Hash Check</h3>
          <p>Verify file integrity using MD5, SHA-1, or SHA-256 hashes</p>
        </div>

        <div class="feature-card">
          <div class="feature-icon">📁</div>
          <h3>File Upload</h3>
          <p>Upload files directly for comprehensive malware analysis</p>
        </div>

        <div class="feature-card">
          <div class="feature-icon">⚡</div>
          <h3>Real-time Results</h3>
          <p>Get instant threat intelligence from multiple sources</p>
        </div>
      </div>

      <app-analysis-form></app-analysis-form>
    </div>
  `,
  styles: [`
    .dashboard {
      max-width: 1400px;
      margin: 0 auto;
      padding: 40px 20px;
    }

    .dashboard-header {
      text-align: center;
      margin-bottom: 48px;
    }

    .dashboard-header h1 {
      font-size: 36px;
      font-weight: 800;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      margin-bottom: 12px;
    }

    .dashboard-header p {
      font-size: 18px;
      color: #718096;
    }

    .features-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 24px;
      margin-bottom: 48px;
    }

    .feature-card {
      background: white;
      padding: 24px;
      border-radius: 12px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
      transition: all 0.3s;
      border: 2px solid transparent;
    }

    .feature-card:hover {
      transform: translateY(-4px);
      box-shadow: 0 8px 15px rgba(102, 126, 234, 0.2);
      border-color: #667eea;
    }

    .feature-icon {
      font-size: 48px;
      margin-bottom: 16px;
    }

    .feature-card h3 {
      font-size: 18px;
      font-weight: 700;
      color: #2d3748;
      margin-bottom: 8px;
    }

    .feature-card p {
      font-size: 14px;
      color: #718096;
      line-height: 1.6;
    }

    @media (max-width: 768px) {
      .dashboard-header h1 {
        font-size: 28px;
      }

      .dashboard-header p {
        font-size: 16px;
      }

      .features-grid {
        grid-template-columns: 1fr;
      }
    }
  `]
})
export class DashboardComponent {}