import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AuthService } from '../../../core/services/auth.service';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <nav class="navbar">
      <div class="navbar-container">
        <div class="navbar-brand">
          <a routerLink="/dashboard" class="brand-link">
            <span class="brand-icon">🛡️</span>
            <span class="brand-text">Threat Analyzer</span>
          </a>
        </div>

        <div class="navbar-menu">
          <a routerLink="/dashboard" routerLinkActive="active" class="nav-link">
            <span class="nav-icon">📊</span>
            Dashboard
          </a>
        </div>

        <div class="navbar-user" *ngIf="currentUser$ | async as user">
          <div class="user-info">
            <div class="user-avatar">{{ user.username.charAt(0).toUpperCase() }}</div>
            <div class="user-details">
              <div class="user-name">{{ user.username }}</div>
              <div class="user-role">{{ user.role }}</div>
            </div>
          </div>
          <button class="btn-logout" (click)="logout()">
            <span>🚪</span> Logout
          </button>
        </div>
      </div>
    </nav>
  `,
  styles: [`
    .navbar {
      background: white;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.08);
      position: sticky;
      top: 0;
      z-index: 1000;
    }

    .navbar-container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 0 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      height: 64px;
    }

    .navbar-brand {
      display: flex;
      align-items: center;
    }

    .brand-link {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
      color: #1a202c;
      font-weight: 700;
      font-size: 20px;
      transition: all 0.2s;
    }

    .brand-link:hover {
      color: #667eea;
    }

    .brand-icon {
      font-size: 28px;
    }

    .navbar-menu {
      display: flex;
      gap: 8px;
      flex: 1;
      justify-content: center;
    }

    .nav-link {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      text-decoration: none;
      color: #4a5568;
      font-weight: 500;
      border-radius: 8px;
      transition: all 0.2s;
    }

    .nav-link:hover {
      background-color: #f7fafc;
      color: #667eea;
    }

    .nav-link.active {
      background-color: #edf2f7;
      color: #667eea;
    }

    .nav-icon {
      font-size: 18px;
    }

    .navbar-user {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .user-info {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .user-avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 16px;
    }

    .user-details {
      display: flex;
      flex-direction: column;
    }

    .user-name {
      font-weight: 600;
      color: #2d3748;
      font-size: 14px;
    }

    .user-role {
      font-size: 12px;
      color: #718096;
      text-transform: capitalize;
    }

    .btn-logout {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 16px;
      background: white;
      border: 2px solid #e2e8f0;
      border-radius: 8px;
      color: #4a5568;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
    }

    .btn-logout:hover {
      border-color: #f56565;
      color: #f56565;
      background-color: #fff5f5;
    }

    @media (max-width: 768px) {
      .navbar-container {
        flex-wrap: wrap;
        height: auto;
        padding: 12px 20px;
      }

      .navbar-menu {
        order: 3;
        width: 100%;
        margin-top: 12px;
        justify-content: flex-start;
      }

      .user-details {
        display: none;
      }
    }
  `]
})
export class NavbarComponent {
  private authService = inject(AuthService);
  
  currentUser$ = this.authService.currentUser$;

  logout(): void {
    this.authService.logout().subscribe();
  }
}