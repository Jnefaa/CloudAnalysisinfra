import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { AuthService } from '../services/auth.service';
import { catchError, switchMap, throwError } from 'rxjs';
import { Router } from '@angular/router';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Skip adding token for login and refresh endpoints
  if (req.url.includes('/auth/login/') || req.url.includes('/auth/token/refresh/')) {
    return next(req);
  }

  const token = authService.getAccessToken();

  if (token) {
    req = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  return next(req).pipe(
    catchError(error => {
      // If 401 error, try to refresh token
      if (error.status === 401 && !req.url.includes('/auth/token/refresh/')) {
        return authService.refreshToken().pipe(
          switchMap(() => {
            // Retry the request with new token
            const newToken = authService.getAccessToken();
            const clonedReq = req.clone({
              setHeaders: {
                Authorization: `Bearer ${newToken}`
              }
            });
            return next(clonedReq);
          }),
          catchError(refreshError => {
            // If refresh fails, logout and redirect to login
            authService.logout().subscribe();
            router.navigate(['/login']);
            return throwError(() => refreshError);
          })
        );
      }
      return throwError(() => error);
    })
  );
};