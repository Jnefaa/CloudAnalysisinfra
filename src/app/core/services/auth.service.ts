import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { Router } from '@angular/router';
import { environment } from '../../../environments/environment';
import { LoginRequest, LoginResponse, User, TokenRefreshResponse } from '../models/user.model';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private http = inject(HttpClient);
  private router = inject(Router);
  
  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  private readonly ACCESS_TOKEN_KEY = 'access_token';
  private readonly REFRESH_TOKEN_KEY = 'refresh_token';
  private readonly USER_KEY = 'user';

  constructor() {
    this.loadUserFromStorage();
  }

  login(credentials: LoginRequest): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${environment.apiUrl}/auth/login/`, credentials)
      .pipe(
        tap(response => {
          this.storeTokens(response.access, response.refresh);
          this.storeUser(response.user);
          this.currentUserSubject.next(response.user);
        })
      );
  }

  logout(): Observable<any> {
    return this.http.post(`${environment.apiUrl}/auth/logout/`, {})
      .pipe(
        tap(() => {
          this.clearStorage();
          this.currentUserSubject.next(null);
          this.router.navigate(['/login']);
        })
      );
  }

  refreshToken(): Observable<TokenRefreshResponse> {
    const refreshToken = this.getRefreshToken();
    return this.http.post<TokenRefreshResponse>(
      `${environment.apiUrl}/auth/token/refresh/`,
      { refresh: refreshToken }
    ).pipe(
      tap(response => {
        this.storeAccessToken(response.access);
      })
    );
  }

  getCurrentUser(): Observable<User> {
    return this.http.get<User>(`${environment.apiUrl}/auth/user/`)
      .pipe(
        tap(user => {
          this.storeUser(user);
          this.currentUserSubject.next(user);
        })
      );
  }

  getAccessToken(): string | null {
    return localStorage.getItem(this.ACCESS_TOKEN_KEY);
  }

  getRefreshToken(): string | null {
    return localStorage.getItem(this.REFRESH_TOKEN_KEY);
  }

  isAuthenticated(): boolean {
    return !!this.getAccessToken();
  }

  private storeTokens(access: string, refresh: string): void {
    localStorage.setItem(this.ACCESS_TOKEN_KEY, access);
    localStorage.setItem(this.REFRESH_TOKEN_KEY, refresh);
  }

  private storeAccessToken(access: string): void {
    localStorage.setItem(this.ACCESS_TOKEN_KEY, access);
  }

  private storeUser(user: User): void {
    localStorage.setItem(this.USER_KEY, JSON.stringify(user));
  }

  private loadUserFromStorage(): void {
    const userStr = localStorage.getItem(this.USER_KEY);
    if (userStr) {
      const user = JSON.parse(userStr);
      this.currentUserSubject.next(user);
    }
  }

  private clearStorage(): void {
    localStorage.removeItem(this.ACCESS_TOKEN_KEY);
    localStorage.removeItem(this.REFRESH_TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
  }
}