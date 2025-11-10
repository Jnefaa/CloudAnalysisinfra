import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterOutlet, Router, NavigationEnd } from '@angular/router';
import { NavbarComponent } from './shared/layout/navbar/navbar.component';
import { AuthService } from './core/services/auth.service';
import { filter } from 'rxjs';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterOutlet, NavbarComponent],
  template: `
    <div class="app-container">
      <app-navbar *ngIf="showNavbar"></app-navbar>
      <main class="main-content" [class.with-navbar]="showNavbar">
        <router-outlet></router-outlet>
      </main>
    </div>
  `,
  styles: [`
    .app-container {
      min-height: 100vh;
      background-color: #f7fafc;
    }

    .main-content {
      min-height: calc(100vh - 64px);
    }

    .main-content.with-navbar {
      padding-top: 0;
    }

    .main-content:not(.with-navbar) {
      padding-top: 0;
      min-height: 100vh;
    }
  `]
})
export class AppComponent {
  private router = inject(Router);
  private authService = inject(AuthService);
  
  showNavbar = false;

  constructor() {
    // Show navbar on all routes except login
    this.router.events.pipe(
      filter(event => event instanceof NavigationEnd)
    ).subscribe((event: any) => {
      this.showNavbar = !event.url.includes('/login');
    });

    // Check initial route
    this.showNavbar = !this.router.url.includes('/login');
  }
}