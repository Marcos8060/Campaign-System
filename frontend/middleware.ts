// middleware.ts (at root, next to app/ folder)
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Public routes that don't require authentication
const PUBLIC_ROUTES = ['/', '/login', '/signup', '/forgot-password', '/verify-email', '/reset-password'];

// Onboarding routes
const ONBOARDING_ROUTES = ['/create-organization', '/choose-plan', '/invite-team'];

// Routes that require active subscription
const SUBSCRIPTION_REQUIRED_ROUTES = ['/campaigns/new', '/campaigns/[id]/edit'];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Get access token from cookies
  const accessToken = request.cookies.get('access_token')?.value;
  const refreshToken = request.cookies.get('refresh_token')?.value;

  // Check if route is public
  const isPublicRoute = PUBLIC_ROUTES.includes(pathname) || pathname.startsWith('/api/auth');
  const isOnboardingRoute = ONBOARDING_ROUTES.some(route => pathname.startsWith(route));

  // Allow public routes
  if (isPublicRoute) {
    // If authenticated and on login/signup, redirect to dashboard
    if (accessToken && (pathname === '/login' || pathname === '/signup')) {
      return NextResponse.redirect(new URL('/dashboard', request.url));
    }
    return NextResponse.next();
  }

  // Require authentication for all other routes
  if (!accessToken) {
    // Try to refresh token if refresh token exists
    if (refreshToken && !pathname.startsWith('/api/')) {
      try {
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/refresh`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });

        if (response.ok) {
          const data = await response.json();
          
          // Create response with new tokens
          const nextResponse = NextResponse.next();
          
          nextResponse.cookies.set('access_token', data.access_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 60 * 15, // 15 minutes
          });
          
          if (data.refresh_token) {
            nextResponse.cookies.set('refresh_token', data.refresh_token, {
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
              sameSite: 'lax',
              maxAge: 60 * 60 * 24 * 7, // 7 days
            });
          }
          
          return nextResponse;
        }
      } catch (error) {
        console.error('Token refresh failed:', error);
      }
    }
    
    // No valid token, redirect to login
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('redirect', pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Verify token and get user info
  try {
    const verifyResponse = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/verify`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    if (!verifyResponse.ok) {
      // Token invalid, redirect to login
      const loginUrl = new URL('/login', request.url);
      loginUrl.searchParams.set('redirect', pathname);
      
      const response = NextResponse.redirect(loginUrl);
      response.cookies.delete('access_token');
      response.cookies.delete('refresh_token');
      return response;
    }

    const userData = await verifyResponse.json();

    // Check if user has completed onboarding (has organization)
    if (!isOnboardingRoute) {
      // Check if user has organization
      const orgResponse = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/users/me/organizations`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      if (orgResponse.ok) {
        const organizations = await orgResponse.json();
        
        // No organization membership = redirect to onboarding
        if (!organizations || organizations.length === 0) {
          // Allow API routes to handle their own errors
          if (pathname.startsWith('/api/')) {
            return NextResponse.next();
          }
          return NextResponse.redirect(new URL('/create-organization', request.url));
        }

        // Store current organization ID in cookie for easy access
        const response = NextResponse.next();
        const currentOrgId = request.cookies.get('current_org_id')?.value || organizations[0].id;
        
        response.cookies.set('current_org_id', currentOrgId, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          maxAge: 60 * 60 * 24 * 7, // 7 days
        });
        
        return response;
      }
    }

    // If on onboarding route but already has organization, redirect to dashboard
    if (isOnboardingRoute) {
      const orgResponse = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/users/me/organizations`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      if (orgResponse.ok) {
        const organizations = await orgResponse.json();
        if (organizations && organizations.length > 0) {
          return NextResponse.redirect(new URL('/dashboard', request.url));
        }
      }
    }

  } catch (error) {
    console.error('Middleware error:', error);
    // On error, allow request to proceed but log it
    // The page/API route will handle authentication
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder files (images, etc)
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
  ],
};